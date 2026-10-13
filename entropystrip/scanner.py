"""
PE structural analysis, import inspection, disassembly, and indicator harvesting.
"""

import os
import re
import hashlib
from typing import Dict, List, Tuple, Optional, Any
import pefile

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

from .radar.staging import STRING_STAGING_APIS

SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", 
    "CreateRemoteThread", "LoadLibraryA", "LoadLibraryW", 
    "GetProcAddress", "IsDebuggerPresent", "CreateProcessW",
    "NtUnmapViewOfSection", "QueueUserAPC", "SetWindowsHookExA",
    "CheckRemoteDebuggerPresent", "OutputDebugStringA", "FindWindowA",
    *STRING_STAGING_APIS
}

ANTI_DEBUG_APIS = {
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", 
    "OutputDebugStringA", "NtQueryInformationProcess", "FindWindowA"
}

KNOWN_PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".mpress", "pecrypt", ".themida", ".vmp"}

URL_REGEX = re.compile(rb"https?://[a-zA-Z0-9_\-\./:]+")
IP_REGEX = re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def compute_hashes(data: bytes) -> Dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }


def inspect_imports(pe: pefile.PE) -> Tuple[int, List[str]]:
    total_imports = 0
    flagged_apis = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if not getattr(entry, "imports", None):
                continue
            for imp in entry.imports:
                total_imports += 1
                if imp.name:
                    name = imp.name.decode("utf-8", errors="ignore")
                    if name in SUSPICIOUS_APIS:
                        flagged_apis.append(name)
    return total_imports, list(set(flagged_apis))


def is_dotnet_assembly(pe: pefile.PE) -> bool:
    try:
        com_desc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        return com_desc.VirtualAddress != 0 and com_desc.Size != 0
    except Exception:
        return False


def check_rich_header(pe: pefile.PE) -> Tuple[bool, Optional[str], str]:
    """
    Validates MSVC Rich Header (@comp.id compiler/linker records).
    Crypters, packers, and custom linkers frequently strip or invalidate this header.
    """
    try:
        if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
            if hasattr(pe.RICH_HEADER, "checksum"):
                return True, hex(pe.RICH_HEADER.checksum), "Valid Rich Header present"

        # Check if the binary imports MSVC runtime libraries
        is_msvc = False
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll:
                    dll_name = entry.dll.decode(errors="ignore").lower()
                    if any(lib in dll_name for lib in ("vcruntime", "msvcr", "msvcp")):
                        is_msvc = True
                        break
        if is_msvc:
            return False, None, "Stripped or missing in MSVC-linked binary (crypter / custom linker anomaly)"
    except Exception:
        pass
    return False, None, "Not present"


def detect_overlay(pe: pefile.PE, file_size: int, file_data: bytes) -> Tuple[int, bytes]:
    max_offset = 0
    for section in pe.sections:
        end = section.PointerToRawData + section.SizeOfRawData
        if end > max_offset:
            max_offset = end

    if file_size > max_offset:
        return max_offset, file_data[max_offset:]
    return 0, b""


def harvest_indicators(data: bytes, max_scan_len: int = 65536) -> List[str]:
    """Scans for plain and all 256 single-byte XORed URLs and IP indicators."""
    indicators = []
    chunk = data[:max_scan_len]

    urls = URL_REGEX.findall(chunk)
    for u in urls[:5]:
        indicators.append(f"URL: {u.decode('utf-8', errors='ignore')}")

    ips = IP_REGEX.findall(chunk)
    for ip in ips[:5]:
        indicators.append(f"IP: {ip.decode('utf-8', errors='ignore')}")

    # Exhaustive 256 single-byte XOR key hunt
    if not indicators:
        scan_buf = chunk[:4096]
        for key in range(1, 256):
            xored = bytes([b ^ key for b in scan_buf])
            found = URL_REGEX.findall(xored)
            for u in found[:2]:
                indicators.append(f"XOR [0x{key:02X}] URL: {u.decode('utf-8', errors='ignore')}")
            if len(indicators) >= 5:
                break

    return list(set(indicators))


def disassemble_entry_point(pe: pefile.PE, file_data: bytes) -> str:
    """Disassembles initial instructions at the entry point using Capstone."""
    try:
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if ep_rva == 0:
            return "No execution entry point (DLL resource/pure data)"

        ep_offset = pe.get_offset_from_rva(ep_rva)
        if ep_offset is None or ep_offset >= len(file_data):
            return f"Entry point points outside file (RVA: {hex(ep_rva)} - Header anomaly)"

        code_bytes = file_data[ep_offset : ep_offset + 32]
        if not code_bytes:
            return "Empty bytes at entry point"

        if HAS_CAPSTONE:
            is_64 = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
            mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
            cs = capstone.Cs(capstone.CS_ARCH_X86, mode)

            lines = []
            for ins in cs.disasm(code_bytes, ep_rva):
                lines.append(f"{hex(ins.address):<10} {ins.mnemonic:<7} {ins.op_str}")
                if len(lines) >= 8:
                    break
            return "\n".join(lines) if lines else code_bytes.hex(" ")
        else:
            hex_str = " ".join([f"{b:02x}" for b in code_bytes[:24]])
            return f"{hex(ep_rva)}: {hex_str} (install 'capstone' for full disassembly)"
    except Exception as e:
        return f"Disassembly unavailable: {e}"


def map_mitre_techniques(
    anomalies: List[str],
    flagged_apis: List[str],
    has_wx: bool,
    high_entropy: bool,
    has_overlay: bool,
    is_diluted: bool,
    has_staging: bool = False,
    has_concealed: bool = False,
) -> List[Tuple[str, str, str]]:
    """Maps structural and behavioral findings to MITRE ATT&CK technique IDs."""
    mitre_hits = []
    if high_entropy or is_diluted or has_concealed:
        mitre_hits.append(
            (
                "T1027",
                "Obfuscated Files or Information",
                "Cryptographic entropy, sliding-window spike, or null-byte dilution in payload",
            )
        )
    if has_overlay:
        mitre_hits.append(
            ("T1027.001", "Binary Padding / Steganography", "Unmapped trailing overlay appended to file")
        )
    if has_staging:
        mitre_hits.append(
            (
                "T1027.002",
                "Software Packing (String Staging)",
                "UUID / IP string-to-binary dynamic staging primitives detected",
            )
        )
    if has_wx:
        mitre_hits.append(("T1055", "Process Injection (Memory)", "Self-modifying W+X memory permissions"))

    inject_apis = {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC"}
    intersect = inject_apis.intersection(set(flagged_apis))
    if intersect:
        mitre_hits.append(
            ("T1055.002", "Portable Executable Injection", f"Injection primitives: {', '.join(intersect)}")
        )

    anti_debug = ANTI_DEBUG_APIS.intersection(set(flagged_apis))
    if anti_debug:
        mitre_hits.append(
            ("T1497", "Virtualization/Sandbox Evasion", f"Anti-analysis APIs: {', '.join(anti_debug)}")
        )

    for a in anomalies:
        if "small import table" in a.lower():
            mitre_hits.append(
                (
                    "T1129",
                    "Shared Modules (Dynamic Resolution)",
                    "Sparse IAT indicative of runtime dynamic API resolution",
                )
            )
            break

    return mitre_hits
