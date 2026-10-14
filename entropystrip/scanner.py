"""
PE structural analysis, import inspection, disassembly, and indicator harvesting.
"""

import os
import re
import struct
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


def compute_file_hashes(file_path: str, max_hash_bytes: Optional[int] = None) -> Dict[str, str]:
    """Streams file in 1MB chunks to calculate MD5 and SHA256 hashes without RAM exhaustion."""
    md5_h = hashlib.md5()
    sha256_h = hashlib.sha256()
    total_read = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            md5_h.update(chunk)
            sha256_h.update(chunk)
            total_read += len(chunk)
            if max_hash_bytes and total_read >= max_hash_bytes:
                break
    return {
        "md5": md5_h.hexdigest(),
        "sha256": sha256_h.hexdigest()
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


def sanitize_section_name(raw_name: Any) -> str:
    """
    Sanitizes PE section names.
    - Strips trailing null bytes
    - Strips ANSI escape sequences
    - Cleanly formats non-printable / non-ASCII bytes as hex strings without raw b'...' repr
    - Returns '[unnamed]' if empty
    """
    if isinstance(raw_name, str):
        cleaned_bytes = raw_name.encode("latin-1", errors="replace")
    elif isinstance(raw_name, (bytes, bytearray)):
        cleaned_bytes = bytes(raw_name)
    else:
        cleaned_bytes = str(raw_name).encode("latin-1", errors="replace")

    cleaned_bytes = cleaned_bytes.rstrip(b"\x00")
    if not cleaned_bytes:
        return "[unnamed]"

    try:
        text = cleaned_bytes.decode("utf-8")
    except UnicodeDecodeError:
        chars = []
        for b in cleaned_bytes:
            if 32 <= b <= 126 and chr(b) not in "\\\"'":
                chars.append(chr(b))
            else:
                chars.append(f"\\x{b:02x}")
        text = "".join(chars)

    # Strip ANSI escape sequences (\x1b[...m or similar)
    ansi_regex = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
    text = ansi_regex.sub("", text)

    # Strip any residual control characters (< 32)
    cleaned = "".join(c if (ord(c) >= 32 and ord(c) != 127) else f"\\x{ord(c):02x}" for c in text).strip()
    return cleaned if cleaned else "[unnamed]"


def detect_overlapping_sections(pe: pefile.PE, file_size: int) -> Tuple[List[str], int]:
    """
    Identifies physically overlapping sections, zero-length sections, and physical raw size anomalies.
    
    Returns:
        (anomalies: List[str], score_penalty: int)
    """
    anomalies: List[str] = []
    penalty = 0

    physical_spans: List[Tuple[int, int, str]] = []
    for section in pe.sections:
        name = sanitize_section_name(section.Name)
        ptr = getattr(section, "PointerToRawData", 0)
        raw_sz = getattr(section, "SizeOfRawData", 0)
        v_sz = getattr(section, "Misc_VirtualSize", 0)

        # Zero-length section check (both virtual and raw size are zero)
        if raw_sz == 0 and v_sz == 0:
            anomalies.append(f"Structural Anomaly: Section '{name}' is zero-length (0 raw bytes, 0 virtual bytes).")
            penalty += 10

        # Check raw size extending past physical file boundary
        if ptr + raw_sz > file_size and raw_sz > 0:
            anomalies.append(
                f"Header Anomaly: Section '{name}' raw data ({ptr + raw_sz} bytes) extends beyond physical file size ({file_size} bytes)."
            )
            penalty += 20

        # Physical section extent [ptr, ptr + raw_sz)
        if ptr > 0 and raw_sz > 0:
            physical_spans.append((ptr, ptr + raw_sz, name))

    # Sort physical spans by start offset
    physical_spans.sort(key=lambda s: s[0])

    for i in range(len(physical_spans)):
        start_a, end_a, name_a = physical_spans[i]
        for j in range(i + 1, len(physical_spans)):
            start_b, end_b, name_b = physical_spans[j]
            if start_b < end_a:
                overlap_bytes = min(end_a, end_b) - start_b
                anomalies.append(
                    f"Structural Anomaly: Physical section overlap detected! '{name_a}' [{hex(start_a)}-{hex(end_a)}] "
                    f"overlaps with '{name_b}' [{hex(start_b)}-{hex(end_b)}] by {overlap_bytes} bytes (T1027 evasion risk)."
                )
                penalty += 35
            else:
                break

    return anomalies, min(penalty, 60)


def detect_overlay(
    pe: pefile.PE,
    file_size: int,
    file_data: Optional[bytes] = None,
    file_path: Optional[str] = None,
    max_overlay_bytes: int = 10 * 1024 * 1024,
) -> Tuple[int, bytes]:
    max_offset = 0
    for section in pe.sections:
        end = min(section.PointerToRawData + section.SizeOfRawData, file_size)
        if end > max_offset:
            max_offset = end

    if file_size > max_offset:
        overlay_len = file_size - max_offset
        if file_data is not None and len(file_data) >= file_size:
            return max_offset, file_data[max_offset:]
        elif file_path and os.path.exists(file_path):
            with open(file_path, "rb") as f:
                f.seek(max_offset)
                if overlay_len <= max_overlay_bytes:
                    return max_offset, f.read(overlay_len)
                else:
                    # Sample head and tail for entropy analysis without loading multi-GBs into RAM
                    half = max_overlay_bytes // 2
                    head = f.read(half)
                    f.seek(max(max_offset, file_size - half))
                    tail = f.read(half)
                    return max_offset, head + tail
        elif file_data is not None and len(file_data) > max_offset:
            return max_offset, file_data[max_offset:]
    return 0, b""


def inspect_tls_callbacks(pe: pefile.PE, file_data: bytes) -> List[Dict[str, Any]]:
    """
    Parses IMAGE_DIRECTORY_ENTRY_TLS (DataDirectory[9]) to locate TLS callbacks.
    TLS callbacks execute before the main AddressOfEntryPoint, commonly used by
    malware/packers for anti-debugging and payload staging.
    """
    callbacks = []
    try:
        if not hasattr(pe, "OPTIONAL_HEADER") or not hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            return []
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 9:
            return []

        tls_dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
        if not tls_dir_entry or tls_dir_entry.VirtualAddress == 0 or tls_dir_entry.Size == 0:
            return []

        tls_rva = tls_dir_entry.VirtualAddress
        is_64 = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
        image_base = pe.OPTIONAL_HEADER.ImageBase

        callbacks_va = None
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS and hasattr(pe.DIRECTORY_ENTRY_TLS, "struct"):
            callbacks_va = getattr(pe.DIRECTORY_ENTRY_TLS.struct, "AddressOfCallBacks", None)

        if not callbacks_va:
            try:
                tls_offset = pe.get_offset_from_rva(tls_rva)
            except Exception:
                tls_offset = None
            if tls_offset is not None and 0 <= tls_offset < len(file_data):
                # 32-bit: AddressOfCallBacks is at offset 12 (0x0C)
                # 64-bit: AddressOfCallBacks is at offset 24 (0x18)
                cb_ptr_offset = tls_offset + (24 if is_64 else 12)
                ptr_size = 8 if is_64 else 4
                if cb_ptr_offset + ptr_size <= len(file_data):
                    fmt = "<Q" if is_64 else "<I"
                    callbacks_va = struct.unpack(fmt, file_data[cb_ptr_offset : cb_ptr_offset + ptr_size])[0]

        if not callbacks_va or callbacks_va < image_base:
            return []

        cb_array_rva = callbacks_va - image_base
        try:
            cb_array_offset = pe.get_offset_from_rva(cb_array_rva)
        except Exception:
            cb_array_offset = None

        if cb_array_offset is None or cb_array_offset < 0 or cb_array_offset >= len(file_data):
            return []

        ptr_size = 8 if is_64 else 4
        fmt = "<Q" if is_64 else "<I"
        curr_offset = cb_array_offset

        for _ in range(16):
            if curr_offset + ptr_size > len(file_data):
                break
            target_va = struct.unpack(fmt, file_data[curr_offset : curr_offset + ptr_size])[0]
            if target_va == 0:
                break
            curr_offset += ptr_size

            target_rva = target_va - image_base
            try:
                target_file_offset = pe.get_offset_from_rva(target_rva)
            except Exception:
                target_file_offset = None

            cb_info = {
                "va": hex(target_va),
                "rva": hex(target_rva),
                "file_offset": target_file_offset,
                "disasm": "",
            }

            if target_file_offset is not None and 0 <= target_file_offset < len(file_data):
                code_bytes = file_data[target_file_offset : target_file_offset + 32]
                if HAS_CAPSTONE and code_bytes:
                    mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
                    cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
                    lines = []
                    for ins in cs.disasm(code_bytes, target_va):
                        lines.append(f"{hex(ins.address):<10} {ins.mnemonic:<7} {ins.op_str}")
                        if len(lines) >= 6:
                            break
                    cb_info["disasm"] = "\n".join(lines) if lines else code_bytes.hex(" ")
                elif code_bytes:
                    cb_info["disasm"] = " ".join([f"{b:02x}" for b in code_bytes[:16]])
            else:
                cb_info["disasm"] = "[Target VA outside mapped section]"

            callbacks.append(cb_info)

    except Exception:
        pass

    return callbacks


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
    """Disassembles initial instructions at the entry point and TLS callbacks using Capstone."""
    output_blocks = []

    # 1. Enumerate & Disassemble TLS callbacks (pre-entrypoint execution stagers)
    tls_callbacks = inspect_tls_callbacks(pe, file_data)
    if tls_callbacks:
        for idx, cb in enumerate(tls_callbacks):
            cb_disasm = cb["disasm"] if cb["disasm"] else "[unmapped code]"
            output_blocks.append(f"[TLS Callback #{idx+1} at {cb['va']} (Pre-EP Execution)]:\n{cb_disasm}")

    # 2. Main AddressOfEntryPoint disassembly
    try:
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if ep_rva == 0:
            output_blocks.append("No execution entry point (DLL resource/pure data)")
        else:
            ep_offset = pe.get_offset_from_rva(ep_rva)
            if ep_offset is None or ep_offset < 0 or ep_offset >= len(file_data):
                output_blocks.append(f"Entry point points outside file (RVA: {hex(ep_rva)} - Header anomaly)")
            else:
                code_bytes = file_data[ep_offset : ep_offset + 32]
                if not code_bytes:
                    output_blocks.append("Empty bytes at entry point")
                elif HAS_CAPSTONE:
                    is_64 = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
                    mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
                    cs = capstone.Cs(capstone.CS_ARCH_X86, mode)

                    lines = []
                    for ins in cs.disasm(code_bytes, ep_rva):
                        lines.append(f"{hex(ins.address):<10} {ins.mnemonic:<7} {ins.op_str}")
                        if len(lines) >= 8:
                            break
                    ep_text = "\n".join(lines) if lines else code_bytes.hex(" ")
                    output_blocks.append(f"[Main Entry Point (RVA: {hex(ep_rva)})]:\n{ep_text}")
                else:
                    hex_str = " ".join([f"{b:02x}" for b in code_bytes[:24]])
                    output_blocks.append(f"[Main Entry Point (RVA: {hex(ep_rva)})]: {hex_str} (install 'capstone' for full disassembly)")
    except Exception as e:
        output_blocks.append(f"Disassembly unavailable: {e}")

    return "\n\n".join(output_blocks)


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

    for a in anomalies:
        if "overlap" in a.lower():
            mitre_hits.append(
                (
                    "T1027",
                    "Obfuscated Files or Information",
                    "Overlapping physical section headers concealing alternate payloads",
                )
            )
            break

    for a in anomalies:
        if "tls callback" in a.lower():
            mitre_hits.append(
                (
                    "T1055",
                    "Process Injection / Execution Guardrails",
                    "Pre-entrypoint TLS callback routines registered",
                )
            )
            break

    return mitre_hits
