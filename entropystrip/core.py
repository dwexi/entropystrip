import sys
import math
import os
import argparse
import json
import re
import hashlib
import pefile
import html

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

BANNER = r"""
___________       __                               _________ __         .__        
\_   _____/ _____/  |________  ____ ______ ___.__./   _____//  |________|__|_____  
 |    __)_ /    \   __\_  __ \/  _ \\____ <   |  |\_____  \\   __\_  __ \  \____ \ 
 |        \   |  \  |  |  | \(  <_> )  |_> >___  |/        \|  |  |  | \/  |  |_> >
/_______  /___|  /__|  |__|   \____/|   __// ____/_______  /|__|  |__|  |__|   __/ 
        \/     \/                   |__|   \/            \/                |__|    
"""

STRING_STAGING_APIS = {
    "UuidFromStringA", "UuidFromStringW", 
    "RtlIpv4StringToAddressA", "RtlIpv4StringToAddressW", 
    "RtlIpv6StringToAddressA", "RtlIpv6StringToAddressW", 
    "RtlEthernetStringToAddressA", "CLSIDFromString"
}

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

URL_REGEX = re.compile(rb'https?://[a-zA-Z0-9_\-\./:]+')
IP_REGEX = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
UUID_REGEX = re.compile(rb'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')

def calculate_entropy(data):
    if not data:
        return 0.0
    if len(data) > 1_000_000:
        # Statistical sampling on massive buffers (> 1MB) for high-performance triage
        data = data[:500_000] + data[-500_000:]
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    for count in byte_counts:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy

BASE64_CHARSET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n")

def detect_encoded_payload(data):
    """Detects dense Base64 encoded payload buffers."""
    if not data or len(data) < 512:
        return False, 0.0, ""
    
    sample = data[:4096]
    b64_matches = sum(1 for b in sample if b in BASE64_CHARSET)
    ratio = b64_matches / len(sample)
    if ratio >= 0.96:
        ent = calculate_entropy(sample)
        if 5.6 <= ent <= 6.05:
            return True, ent, f"Base64-encoded payload detected (H={ent:.2f}, {ratio*100:.0f}% charset uniformity)"
    return False, 0.0, ""

def calculate_dilution_metrics(data):
    """
    Detects entropy dilution attacks where high-entropy payloads are padded
    with null bytes or repetitive delimiter bytes (e.g. NOPs 0x90, spaces 0x20).
    """
    if not data or len(data) < 1024:
        return 0.0, 0.0, False, "none"
    
    if len(data) > 1_000_000:
        data = data[:500_000] + data[-500_000:]
    
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    
    max_count = max(counts)
    mode_byte = counts.index(max_count)
    pad_ratio = max_count / len(data)
    
    # If the dominant padding byte makes up at least 30% of the buffer
    if pad_ratio >= 0.30:
        non_pad_bytes = bytes([b for b in data if b != mode_byte])
        if len(non_pad_bytes) >= 256:
            non_pad_ent = calculate_entropy(non_pad_bytes)
            # If the non-padded bytes alone have cryptographic entropy (H > 7.38)
            if non_pad_ent > 7.38:
                pad_name = "null-byte" if mode_byte == 0 else f"repeated-byte (0x{mode_byte:02X})"
                return non_pad_ent, pad_ratio, True, pad_name
    
    return 0.0, pad_ratio, False, "none"

def scan_sliding_window_entropy(data, window_size=1024, step_size=None, threshold=7.4):
    """
    Scans data with a sliding window to catch small, concentrated high-entropy
    payloads embedded inside large, low-entropy sections (sub-section granularity).
    Features adaptive step-sizing to prevent DoS on large files, and dual-scale
    sampling to catch compact sub-window payloads (e.g. 256B-512B stagers).
    """
    if not data or len(data) < 256:
        return 0.0, []
    
    # Adaptive step size: prevent CPU lockup on multi-megabyte buffers
    if step_size is None:
        if len(data) > 500_000:
            step_size = max(512, len(data) // 150)
        else:
            step_size = 512
            
    effective_window = min(window_size, len(data))
    max_ent = 0.0
    anomalous_spans = []
    current_span = None

    for offset in range(0, len(data) - effective_window + 1, step_size):
        chunk = data[offset:offset + effective_window]
        ent = calculate_entropy(chunk)
        if ent > max_ent:
            max_ent = ent
            
        if ent >= threshold:
            if current_span is None:
                current_span = {"start": offset, "end": offset + effective_window, "max_ent": ent, "scale": effective_window}
            else:
                current_span["end"] = offset + effective_window
                if ent > current_span["max_ent"]:
                    current_span["max_ent"] = ent
        else:
            if current_span is not None:
                anomalous_spans.append(current_span)
                current_span = None

    if current_span is not None:
        anomalous_spans.append(current_span)

    # Sub-window pass for compact dense blocks (256B) if no span found yet and buffer is moderate
    if not anomalous_spans and len(data) >= 256 and len(data) <= 500_000:
        sub_win = 256
        sub_step = 64
        for offset in range(0, len(data) - sub_win + 1, sub_step):
            chunk = data[offset:offset + sub_win]
            sub_ent = calculate_entropy(chunk)
            if sub_ent > max_ent:
                max_ent = sub_ent
            if sub_ent >= 7.15: # Dense cryptographic block in 256 bytes
                anomalous_spans.append({"start": offset, "end": offset + sub_win, "max_ent": sub_ent, "scale": 256})
                break

    return max_ent, anomalous_spans

def calculate_chi_square(data):
    """
    Computes Chi-Square goodness-of-fit against a uniform distribution.
    Detects artificially diluted ciphertext (interleaved nulls/delimiters)
    where non-outlier byte frequencies display statistical uniformity.
    """
    if not data or len(data) < 256:
        return 0.0, 0.0, False

    if len(data) > 1_000_000:
        data = data[:500_000] + data[-500_000:]

    n = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    expected = n / 256.0
    chi2 = sum(((c - expected) ** 2) / expected for c in counts)

    max_count = max(counts)
    mode_byte = counts.index(max_count)
    pad_ratio = max_count / n
    non_mode_counts = [counts[b] for b in range(256) if b != mode_byte]
    nz_total = sum(non_mode_counts)
    is_diluted_uniform = False
    nz_chi2 = 0.0

    if pad_ratio >= 0.15 and nz_total >= 512:
        nz_expected = nz_total / 255.0
        nz_chi2 = sum(((c - nz_expected) ** 2) / nz_expected for c in non_mode_counts)
        # 254 degrees of freedom: chi2 between 160 and 420 indicates uniform randomness
        if 160.0 <= nz_chi2 <= 420.0:
            is_diluted_uniform = True

    return chi2, nz_chi2, is_diluted_uniform

def detect_string_staging(data, flagged_apis):
    """Detects UUID / IPv4 / MAC string-to-memory staging and array cluster patterns."""
    staging_hits = [api for api in flagged_apis if api in STRING_STAGING_APIS]
    # Bound regex scan on large files to prevent DoS
    scan_buf = (data[:1_000_000] + data[-500_000:]) if data and len(data) > 1_500_000 else data
    uuid_matches = UUID_REGEX.findall(scan_buf) if scan_buf else []
    ip_matches = IP_REGEX.findall(scan_buf) if scan_buf else []
    
    # Require tighter cluster or correlation with staging API to prevent FP on standard COM GUIDs
    has_uuid_cluster = len(uuid_matches) >= (4 if staging_hits else 12)
    has_ip_cluster = len(ip_matches) >= (6 if staging_hits else 16)
    
    return staging_hits, len(uuid_matches), has_uuid_cluster, len(ip_matches), has_ip_cluster

def detect_installer(data, overlay_data=None, pe=None):
    """
    Identifies common legitimate installer frameworks: NSIS, Inno Setup, WiX/Burn.
    Performs structural validation so injected substrings do not bypass triage.
    """
    if not data:
        return None
    sample = data[:0x40000]
    ov_sample = overlay_data[:0x4000] if overlay_data else b""
    combined_check = sample + ov_sample

    if b"NullsoftInst" in combined_check or b"Nullsoft.NSIS" in data:
        # Require genuine NSIS characteristics: overlay starts with NullsoftInst, or section names match
        has_nsis_sec = False
        if pe:
            for s in pe.sections:
                try:
                    s_name = s.Name.decode(errors='ignore').rstrip('\x00').lower()
                    if ".ndata" in s_name or s_name == ".data":
                        has_nsis_sec = True
                except Exception:
                    pass
        if overlay_data and overlay_data.startswith(b"NullsoftInst") and len(overlay_data) >= 28:
            # Validate genuine NSIS block header signature (0xdeadbeef)
            if overlay_data[16:20] == b"\xef\xbe\xad\xde" or overlay_data[12:16] == b"\xef\xbe\xad\xde":
                return "Nullsoft NSIS Setup"
            return "Unverified NSIS Marker"
        elif has_nsis_sec and b"NullsoftInst" in data[:0x40000]:
            return "Nullsoft NSIS Setup"
        return "Unverified NSIS Marker"
    if b"Inno Setup Setup Data" in combined_check or b"Inno Setup" in combined_check:
        return "Inno Setup"
    if b"WixBurnBundle" in data or b"WixBurn" in data:
        return "WiX / Burn Bootstrapper"
    if b"InstallShield" in combined_check:
        return "InstallShield Setup"
    return None

def get_entropy_heatmap_string(data, width=30):
    if not data or len(data) == 0:
        return "[dim]No Data (Unmapped)[/dim]"
    
    chunk_size = max(1, len(data) // width)
    heatmap = ""
    for i in range(width):
        start = i * chunk_size
        end = len(data) if i == width - 1 else start + chunk_size
        chunk = data[start:start + 50_000] if (end - start) > 50_000 else data[start:end]
        if not chunk:
            continue
        ent = calculate_entropy(chunk)
        if ent > 7.4:
            color = "red"
        elif ent > 6.6:
            color = "yellow"
        elif ent > 5.0:
            color = "green"
        elif ent > 1.0:
            color = "blue"
        else:
            color = "bright_black"
        heatmap += f"[{color}]█[/{color}]"
    return heatmap

def compute_hashes(data):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }

def inspect_imports(pe):
    total_imports = 0
    flagged_apis = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            # Guard against malformed thunks where entry.imports is None
            if not getattr(entry, 'imports', None):
                continue
            for imp in entry.imports:
                total_imports += 1
                if imp.name:
                    name = imp.name.decode('utf-8', errors='ignore')
                    if name in SUSPICIOUS_APIS:
                        flagged_apis.append(name)
    return total_imports, list(set(flagged_apis))

def is_dotnet_assembly(pe):
    try:
        com_desc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        return com_desc.VirtualAddress != 0 and com_desc.Size != 0
    except Exception:
        return False

def check_authenticode_signature(pe, file_size=0, file_data=b""):
    """
    Cryptographically / structurally validates the PE Security Directory.
    Verifies WIN_CERTIFICATE header: dwLength, wRevision, wCertificateType.
    """
    try:
        if not hasattr(pe, 'OPTIONAL_HEADER') or not hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
            return False, "No data directories"
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 4:
            return False, "Missing security directory entry"
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if sec_dir.VirtualAddress == 0 or sec_dir.Size == 0:
            return False, "Unsigned"
        
        offset = sec_dir.VirtualAddress
        size = sec_dir.Size
        if file_size > 0 and file_data:
            if offset + size > file_size or offset < 0x200 or size < 8:
                return False, "Security directory offset/size points out of bounds"
            
            cert_header = file_data[offset:offset + 8]
            if len(cert_header) < 8:
                return False, "Truncated certificate header"
            
            dw_length = int.from_bytes(cert_header[0:4], "little")
            w_revision = int.from_bytes(cert_header[4:6], "little")
            w_cert_type = int.from_bytes(cert_header[6:8], "little")
            
            if dw_length > size or w_revision not in (0x0100, 0x0200) or w_cert_type != 0x0002:
                return False, "Malformed or forged WIN_CERTIFICATE header"
        
        return True, "Valid Authenticode PKCS#7 signed structure"
    except Exception as e:
        return False, str(e)

def check_rich_header(pe):
    """Detects compiler toolchain anomalies in the MSVC Rich Header."""
    try:
        if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER:
            # Validate checksum if raw cleartext is present
            if hasattr(pe.RICH_HEADER, 'checksum'):
                return True, hex(pe.RICH_HEADER.checksum)
    except Exception:
        pass
    return False, None

def detect_overlay(pe, file_size, file_data):
    max_offset = 0
    for section in pe.sections:
        end = section.PointerToRawData + section.SizeOfRawData
        if end > max_offset:
            max_offset = end
    
    if file_size > max_offset:
        overlay_bytes = file_data[max_offset:]
        return max_offset, overlay_bytes
    return 0, b""

def harvest_indicators(data, max_scan_len=65536):
    """Exhaustively scans for plain and all 256 single-byte XORed URLs and IP indicators."""
    indicators = []
    chunk = data[:max_scan_len]
    
    # 1. Plain text search
    urls = URL_REGEX.findall(chunk)
    for u in urls[:5]:
        indicators.append(f"URL: {u.decode('utf-8', errors='ignore')}")
    
    ips = IP_REGEX.findall(chunk)
    for ip in ips[:5]:
        indicators.append(f"IP: {ip.decode('utf-8', errors='ignore')}")

    # 2. Exhaustive 256 single-byte XOR key hunt on high entropy blocks
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

def disassemble_entry_point(pe, file_data):
    """Disassembles initial instructions at the Entry Point or dumps raw hex if capstone is absent."""
    try:
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if ep_rva == 0:
            return "[dim]No execution entry point (DLL resource/pure data)[/dim]"

        ep_offset = pe.get_offset_from_rva(ep_rva)
        if ep_offset is None or ep_offset >= len(file_data):
            return f"[red]Entry point points outside file (RVA: {hex(ep_rva)} - Header anomaly)[/red]"

        code_bytes = file_data[ep_offset:ep_offset + 32]
        if not code_bytes:
            return "[dim]Empty bytes at entry point[/dim]"

        if HAS_CAPSTONE:
            is_64 = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']
            mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
            cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
            
            lines = []
            for ins in cs.disasm(code_bytes, ep_rva):
                lines.append(f"{hex(ins.address):<10} {ins.mnemonic:<7} {ins.op_str}")
                if len(lines) >= 8:
                    break
            return "\n".join(lines) if lines else code_bytes.hex(' ')
        else:
            hex_str = " ".join([f"{b:02x}" for b in code_bytes[:24]])
            return f"{hex(ep_rva)}: {hex_str} [dim](install 'capstone' for asm disassembly)[/dim]"
    except Exception as e:
        return f"[dim]Disassembly unavailable: {e}[/dim]"

def map_mitre_techniques(anomalies, flagged_apis, has_wx, high_entropy, has_overlay, is_diluted, has_staging=False, has_concealed=False):
    """Maps structural and behavioral findings to MITRE ATT&CK technique IDs."""
    mitre_hits = []
    if high_entropy or is_diluted or has_concealed:
        mitre_hits.append(("T1027", "Obfuscated Files or Information", "Cryptographic entropy, sliding-window spike, or null-byte dilution in payload"))
    if has_overlay:
        mitre_hits.append(("T1027.001", "Binary Padding / Steganography", "Unmapped trailing overlay appended to file"))
    if has_staging:
        mitre_hits.append(("T1027.002", "Software Packing (String Staging)", "UUID / IP string-to-binary dynamic staging primitives detected"))
    if has_wx:
        mitre_hits.append(("T1055", "Process Injection (Memory)", "Self-modifying W+X memory permissions"))
    
    inject_apis = {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC"}
    if inject_apis.intersection(set(flagged_apis)):
        mitre_hits.append(("T1055.002", "Portable Executable Injection", f"Injection primitives: {', '.join(inject_apis.intersection(set(flagged_apis)))}"))
        
    anti_debug = ANTI_DEBUG_APIS.intersection(set(flagged_apis))
    if anti_debug:
        mitre_hits.append(("T1497", "Virtualization/Sandbox Evasion", f"Anti-analysis APIs: {', '.join(anti_debug)}"))
        
    for a in anomalies:
        if "small import table" in a.lower():
            mitre_hits.append(("T1129", "Shared Modules (Dynamic Resolution)", "Sparse IAT indicative of runtime dynamic API resolution"))
            break

    return mitre_hits

def generate_minimal_html_report(telemetry, output_path):
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    status_color = "#e06c75" if telemetry["threat_score"] >= 70 else ("#e5c07b" if telemetry["threat_score"] >= 35 else "#98c379")
    
    sha256_val = telemetry.get("hashes", {}).get("sha256", "-")
    imphash_val = telemetry.get("imphash") or "-"
    
    sections_html = ""
    for s in telemetry["sections"]:
        heatmap_blocks = ""
        for char in s["raw_heatmap"]:
            c = "#e06c75" if char == "R" else ("#e5c07b" if char == "Y" else ("#98c379" if char == "G" else ("#61afef" if char == "B" else "#3e4451")))
            heatmap_blocks += f'<span style="color:{c};">■</span>'
            
        sections_html += f"""
        <tr>
            <td style="font-family:ui-monospace,monospace; font-weight:600;">{html.escape(s['name'])}</td>
            <td style="font-family:ui-monospace,monospace; text-align:right;">{s['virt_size']}</td>
            <td style="font-family:ui-monospace,monospace; text-align:right;">{s['raw_size']}</td>
            <td style="font-family:ui-monospace,monospace; text-align:right; font-weight:600;">{s['entropy']:.2f}</td>
            <td style="text-align:center;"><span class="badge">{html.escape(str(s['perms']))}</span></td>
            <td style="letter-spacing:1px;">{heatmap_blocks}</td>
            <td style="text-align:center; font-family:ui-monospace,monospace; font-size:11px;">{html.escape(str(s['status']))}</td>
        </tr>
        """

    anomalies_html = "".join([f"<li>{html.escape(a)}</li>" for a in telemetry["anomalies"]]) if telemetry["anomalies"] else "<li>No anomalies detected.</li>"
    indicators_html = "".join([f"<li>{html.escape(i)}</li>" for i in telemetry["indicators"]]) if telemetry["indicators"] else "<li>No network indicators extracted.</li>"
    
    mitre_html = ""
    if telemetry.get("mitre"):
        for tid, tname, tdesc in telemetry["mitre"]:
            mitre_html += f"<tr><td style='font-family:monospace; font-weight:600;'>{html.escape(str(tid))}</td><td style='font-weight:600;'>{html.escape(str(tname))}</td><td>{html.escape(str(tdesc))}</td></tr>"

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>entropystrip - {html.escape(telemetry['filename'])}</title>
<style>
    body {{
        background: #0f141c;
        color: #abb2bf;
        font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
        margin: 0;
        padding: 32px 20px;
        line-height: 1.45;
        font-size: 13px;
    }}
    .container {{
        max-width: 900px;
        margin: 0 auto;
    }}
    .header {{
        border-bottom: 1px solid #282c34;
        padding-bottom: 16px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: baseline;
    }}
    h1 {{
        font-size: 16px;
        margin: 0;
        color: #e6edf3;
        font-weight: 600;
        letter-spacing: 0.5px;
    }}
    .target-path {{
        color: #5c6370;
        font-size: 12px;
        margin-top: 4px;
        word-break: break-all;
    }}
    .card {{
        border: 1px solid #282c34;
        background: #161b22;
        padding: 16px;
        margin-bottom: 16px;
    }}
    .score-card {{
        border-left: 3px solid {status_color};
    }}
    .score-val {{
        font-size: 20px;
        font-weight: 700;
        color: {status_color};
    }}
    .verdict {{
        color: #e6edf3;
        font-weight: 600;
        margin: 4px 0 12px 0;
    }}
    .grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
        margin-bottom: 16px;
    }}
    .cell {{
        background: #161b22;
        border: 1px solid #282c34;
        padding: 10px 14px;
    }}
    .label {{
        font-size: 11px;
        color: #5c6370;
        text-transform: uppercase;
    }}
    .val {{
        color: #e6edf3;
        font-weight: 600;
        margin-top: 2px;
        font-size: 12px;
        word-break: break-all;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        background: #161b22;
        border: 1px solid #282c34;
        margin-bottom: 16px;
    }}
    th, td {{
        padding: 8px 12px;
        text-align: left;
        border-bottom: 1px solid #282c34;
        font-size: 12px;
    }}
    th {{
        background: #1b2028;
        color: #5c6370;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 11px;
    }}
    .badge {{
        font-size: 11px;
        padding: 1px 5px;
        background: #21262d;
        border: 1px solid #30363d;
        color: #c9d1d9;
    }}
    ul {{
        margin: 0;
        padding-left: 18px;
    }}
    li {{
        margin-bottom: 4px;
    }}
    pre {{
        background: #10141b;
        padding: 12px;
        border: 1px solid #282c34;
        overflow-x: auto;
        font-size: 12px;
        color: #98c379;
        margin: 0;
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>entropystrip report</h1>
            <div class="target-path">{html.escape(telemetry['path'])}</div>
        </div>
        <div style="font-size:11px; color:#5c6370;">PE triage</div>
    </div>

    <div class="card score-card">
        <div class="score-val">{telemetry['threat_score']} / 100</div>
        <div class="verdict">{html.escape(telemetry['verdict'])}</div>
        <ul>{anomalies_html}</ul>
    </div>

    <div class="grid">
        <div class="cell">
            <div class="label">SHA256</div>
            <div class="val" style="font-size:11px;">{sha256_val}</div>
        </div>
        <div class="cell">
            <div class="label">Imphash</div>
            <div class="val" style="font-size:11px;">{imphash_val}</div>
        </div>
        <div class="cell">
            <div class="label">Format</div>
            <div class="val">{'Managed (.NET)' if telemetry['is_dotnet'] else 'Native PE'}</div>
        </div>
        <div class="cell">
            <div class="label">Overlay</div>
            <div class="val">{str(telemetry['overlay_size']) + ' bytes' if telemetry['has_overlay'] else 'None'}</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Section</th>
                <th style="text-align:right;">Virt Size</th>
                <th style="text-align:right;">Raw Size</th>
                <th style="text-align:right;">Entropy</th>
                <th style="text-align:center;">Perms</th>
                <th>Entropy Strip</th>
                <th style="text-align:center;">Status</th>
            </tr>
        </thead>
        <tbody>
            {sections_html}
        </tbody>
    </table>

    {f'''
    <div class="card">
        <div class="label" style="margin-bottom:8px;">MITRE ATT&CK Classification</div>
        <table>
            <thead><tr><th>Technique</th><th>Name</th><th>Context</th></tr></thead>
            <tbody>{mitre_html}</tbody>
        </table>
    </div>
    ''' if mitre_html else ''}

    {f'''
    <div class="card">
        <div class="label" style="margin-bottom:8px;">Entry Point Disassembly Stub</div>
        <pre>{html.escape(telemetry.get("ep_disasm", ""))}</pre>
    </div>
    ''' if telemetry.get("ep_disasm") else ''}

    <div class="card">
        <div class="label" style="margin-bottom:8px;">Extracted Indicators</div>
        <ul>{indicators_html}</ul>
    </div>
</div>
</body>
</html>"""
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_html)

def analyze_single_file(file_path, dump_payloads=False, quiet=False, html_out=None, json_out=None, deep=False):
    file_path = os.path.abspath(os.path.normpath(file_path.strip().strip('"\'')))
    
    if not os.path.exists(file_path):
        if not quiet:
            console.print(f"[red]Error: File not found -> {file_path}[/red]")
        return None

    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
        file_size = len(file_data)
        
        # Check ELF magic bytes (\x7fELF)
        if file_data[:4] == b"\x7fELF":
            return analyze_elf(file_path, file_data, quiet=quiet)
            
        pe = pefile.PE(data=file_data)
    except Exception as e:
        if not quiet:
            console.print(f"[dim]Skipping (Invalid PE or locked): {os.path.basename(file_path)}[/dim]")
        return None

    hashes = compute_hashes(file_data)
    try:
        imphash_val = pe.get_imphash()
    except Exception:
        imphash_val = None

    anomalies = []
    threat_score = 0
    high_entropy_sections = []
    has_wx = False
    is_diluted = False
    has_concealed = False
    has_staging = False
    sections_telemetry = []

    if not quiet:
        console.print(f"\n[bold]Target:[/bold] {file_path}")
        if deep:
            console.print(f"[dim]SHA256: {hashes['sha256']}[/dim]")
            if imphash_val:
                console.print(f"[dim]Imphash: {imphash_val}[/dim]")

    table = Table(title="Section Architecture & Entropy", show_header=True, header_style="bold")
    table.add_column("Section", style="cyan", justify="center")
    table.add_column("Virt Size", style="dim", justify="right")
    table.add_column("Raw Size", style="dim", justify="right")
    table.add_column("Entropy", justify="right")
    table.add_column("Perms", justify="center")
    table.add_column("Entropy Strip", justify="left")
    table.add_column("Status", justify="center")

    for section in pe.sections:
        try:
            name = section.Name.decode('utf-8').rstrip('\x00').lower()
        except UnicodeDecodeError:
            name = str(section.Name)

        raw_data = section.get_data()
        entropy = calculate_entropy(raw_data)
        
        # Check for null-byte / repeated-byte dilution evasion in section
        non_pad_ent, pad_ratio, is_dilution_hit, pad_name = calculate_dilution_metrics(raw_data)
        if is_dilution_hit:
            is_diluted = True
            anomalies.append(f"Section '{name}': Evasion detected! {pad_name} dilution masking high-entropy payload (Real Entropy: {non_pad_ent:.2f}, Pad Ratio: {pad_ratio*100:.0f}%).")
            threat_score += 40
            high_entropy_sections.append((name, raw_data, non_pad_ent))

        # Chi-Square goodness-of-fit test for uniform ciphertext
        chi2, nz_chi2, is_diluted_uniform = calculate_chi_square(raw_data)
        if is_diluted_uniform and not is_dilution_hit:
            is_diluted = True
            anomalies.append(f"Section '{name}': Chi-Square (χ²={nz_chi2:.1f}) confirms uniform ciphertext distribution despite low global entropy.")
            threat_score += 35
            high_entropy_sections.append((name, raw_data, 7.5))

        # Check for Base64 payload in section
        has_b64, b64_ent, b64_desc = detect_encoded_payload(raw_data)
        if has_b64 and entropy <= 6.6:
            anomalies.append(f"Section '{name}': {b64_desc}. Obfuscated payload risk.")
            threat_score += 30
            high_entropy_sections.append((f"{name}_base64", raw_data, b64_ent))

        is_exec = bool(section.Characteristics & 0x20000000)
        is_write = bool(section.Characteristics & 0x80000000)

        # Sliding-Window / Sub-section granularity
        has_local_spike = False
        local_max_ent = 0.0
        if entropy <= 7.2 and len(raw_data) >= 512:
            local_max_ent, anomalous_spans = scan_sliding_window_entropy(raw_data)
            if anomalous_spans:
                span = anomalous_spans[0]
                span_len = span['end'] - span['start']
                span_data = raw_data[span['start']:span['end']]

                is_benign_asset = False
                if name in (".rsrc", ".data", ".rdata") and not is_exec and not is_write:
                    if span_data.startswith(b"\x89PNG") or span_data.startswith(b"\x00\x00\x01\x00") or span_data.startswith(b"PK\x03\x04") or span_data.startswith(b"BM"):
                        is_benign_asset = True
                    elif name == ".rsrc":
                        is_benign_asset = True

                if is_benign_asset:
                    anomalies.append(f"Section '{name}': Compressed resource asset detected (Local H={local_max_ent:.2f} at offset {hex(span['start'])}, ~{span_len} bytes).")
                    threat_score += 5
                elif not is_exec and not is_write:
                    has_local_spike = True
                    has_concealed = True
                    anomalies.append(f"Section '{name}': High-density data cluster detected via sliding window (Local H={local_max_ent:.2f} at offset {hex(span['start'])}, ~{span_len} bytes) in read-only section.")
                    threat_score += 15
                    high_entropy_sections.append((f"{name}_concealed", span_data, local_max_ent))
                else:
                    has_local_spike = True
                    has_concealed = True
                    anomalies.append(f"Section '{name}': Concealed payload detected via sliding window! (Local H={local_max_ent:.2f} at offset {hex(span['start'])}, ~{span_len} bytes) in executable/writable code space!")
                    threat_score += 35
                    high_entropy_sections.append((f"{name}_concealed", span_data, local_max_ent))
        perms = ""
        perms_raw = "R"
        if is_write and is_exec:
            perms = "[bold red]W+X[/bold red]"
            perms_raw = "W+X"
            has_wx = True
            anomalies.append(f"Section '{name}' is Writable + Executable (W+X self-modifying code risk).")
            threat_score += 25
        elif is_exec:
            perms = "[green]R+X[/green]"
            perms_raw = "R+X"
        elif is_write:
            perms = "[blue]R+W[/blue]"
            perms_raw = "R+W"
        else:
            perms = "[dim]R[/dim]"

        if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
            anomalies.append(f"Section '{name}' has 0 raw data on disk but reserves {hex(section.Misc_VirtualSize)} in RAM.")
            threat_score += 25

        if name in KNOWN_PACKER_SECTIONS:
            anomalies.append(f"Known packer section name: '{name}'.")
            threat_score += 30

        raw_heatmap_chars = []
        chunk_sz = max(1, len(raw_data) // 30) if raw_data else 1
        for i in range(30):
            st = i * chunk_sz
            en = len(raw_data) if i == 29 else st + chunk_sz
            chk = raw_data[st:en]
            if chk:
                c_ent = calculate_entropy(chk)
                raw_heatmap_chars.append("R" if c_ent > 7.4 else ("Y" if c_ent > 6.6 else ("G" if c_ent > 5.0 else ("B" if c_ent > 1.0 else "D"))))

        if entropy > 7.4:
            entropy_str = f"[bold red]{entropy:.2f}[/bold red]"
            status = "[red]HIGH[/red]"
            high_entropy_sections.append((name, raw_data, entropy))
            threat_score += 35
            anomalies.append(f"Section '{name}' has high entropy ({entropy:.2f} / 8.00).")
        elif is_dilution_hit or is_diluted_uniform:
            entropy_str = f"[bold red]{entropy:.2f}*[/bold red]"
            status = "[red]DILUTED[/red]"
        elif has_local_spike:
            entropy_str = f"[bold red]{entropy:.2f}![/bold red]"
            status = "[bold red]CONCEALED[/bold red]"
        elif entropy > 6.6:
            if name == ".rsrc":
                entropy_str = f"[bold green]{entropy:.2f}[/bold green]"
                status = "[green]OK[/green]"
            else:
                entropy_str = f"[bold yellow]{entropy:.2f}[/bold yellow]"
                status = "[yellow]SUSP[/yellow]"
                threat_score += 10
        else:
            entropy_str = f"[bold green]{entropy:.2f}[/bold green]"
            status = "[green]OK[/green]"

        heatmap_visual = get_entropy_heatmap_string(raw_data)

        table.add_row(
            name,
            hex(section.Misc_VirtualSize),
            hex(section.SizeOfRawData),
            entropy_str,
            perms,
            heatmap_visual,
            status
        )

        sections_telemetry.append({
            "name": name,
            "virt_size": hex(section.Misc_VirtualSize),
            "raw_size": hex(section.SizeOfRawData),
            "entropy": entropy,
            "perms": perms_raw,
            "status": "HIGH" if entropy > 7.4 else ("DILUTED" if (is_dilution_hit or is_diluted_uniform) else ("CONCEALED" if has_local_spike else ("SUSP" if entropy > 6.6 else "OK"))),
            "raw_heatmap": "".join(raw_heatmap_chars)
        })

    is_dotnet = is_dotnet_assembly(pe)
    is_signed, cert_msg = check_authenticode_signature(pe, file_size, file_data)
    if "Malformed or forged" in cert_msg or "out of bounds" in cert_msg:
        anomalies.append(f"Security Directory Anomaly: {cert_msg}.")
        threat_score += 30

    max_offset, overlay_data = detect_overlay(pe, file_size, file_data)
    has_overlay = len(overlay_data) > 0
    overlay_entropy = 0.0
    is_cert_overlay = False

    if has_overlay:
        overlay_entropy = calculate_entropy(overlay_data)
        
        # Check if overlay is legitimately the Authenticode digital signature table
        if is_signed and hasattr(pe, 'OPTIONAL_HEADER') and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
            sec_va = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress
            sec_sz = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
            if sec_va == max_offset and sec_sz <= len(overlay_data):
                is_cert_overlay = True
                trailing_extra = len(overlay_data) - sec_sz
                if trailing_extra == 0:
                    status = "[dim]SIGNED[/dim]"
                    anomalies.append(f"Overlay is valid Authenticode digital signature table ({len(overlay_data)} bytes).")
                else:
                    status = "[yellow]SUSP[/yellow]"
                    anomalies.append(f"Overlay contains Authenticode signature ({sec_sz} bytes) plus {trailing_extra} unmapped trailing bytes past certificate!")
                    threat_score += 25

        if not is_cert_overlay:
            # Check for Base64 payload in overlay
            has_b64, b64_ent, b64_desc = detect_encoded_payload(overlay_data)
            if has_b64:
                anomalies.append(f"Overlay: {b64_desc}. Obfuscated payload risk.")
                threat_score += 35
                high_entropy_sections.append(("overlay_base64", overlay_data, b64_ent))
                status = "[red]OBFUSCATED[/red]"

            # Check for dilution evasion in overlay
            ov_non_pad, ov_pad_ratio, ov_diluted, ov_pad_name = calculate_dilution_metrics(overlay_data)
            ov_chi2, ov_nz_chi2, ov_diluted_uniform = calculate_chi_square(overlay_data)

            if ov_diluted or ov_diluted_uniform:
                is_diluted = True
                disp_ent = ov_non_pad if ov_diluted else 7.5
                anomalies.append(f"Overlay evasion detected! {ov_pad_name} dilution/Chi-Square masking high-entropy payload (Real Payload Entropy: {disp_ent:.2f}).")
                threat_score += 45
                high_entropy_sections.append(("overlay", overlay_data, disp_ent))
                status = "[red]DILUTED[/red]"
            elif overlay_entropy > 7.2:
                anomalies.append(f"Overlay detected ({len(overlay_data)} bytes) with high entropy ({overlay_entropy:.2f}). Steganography/Dropper risk.")
                threat_score += 35
                high_entropy_sections.append(("overlay", overlay_data, overlay_entropy))
                status = "[red]HIGH[/red]"
            else:
                ov_has_local_spike = False
                if len(overlay_data) >= 512:
                    ov_max_win, ov_anomalous_spans = scan_sliding_window_entropy(overlay_data)
                    if ov_anomalous_spans:
                        ov_has_local_spike = True
                        has_concealed = True
                        ov_span = ov_anomalous_spans[0]
                        ov_len = ov_span['end'] - ov_span['start']
                        anomalies.append(f"Overlay: Concealed payload detected via sliding window! (Local H={ov_max_win:.2f} at offset {hex(ov_span['start'])}, ~{ov_len} bytes) despite overall overlay H={overlay_entropy:.2f}.")
                        threat_score += 35
                        high_entropy_sections.append(("overlay_concealed", overlay_data[ov_span['start']:ov_span['end']], ov_max_win))
                        status = "[bold red]CONCEALED[/bold red]"

                if not ov_has_local_spike:
                    anomalies.append(f"Overlay detected ({len(overlay_data)} bytes, entropy {overlay_entropy:.2f}).")
                    threat_score += 10
                    status = "[yellow]SUSP[/yellow]"

        raw_heatmap_chars = []
        chunk_sz = max(1, len(overlay_data) // 30)
        for i in range(30):
            st = i * chunk_sz
            en = len(overlay_data) if i == 29 else st + chunk_sz
            chk = overlay_data[st:en]
            if chk:
                c_ent = calculate_entropy(chk)
                raw_heatmap_chars.append("R" if c_ent > 7.4 else ("Y" if c_ent > 6.6 else ("G" if c_ent > 5.0 else ("B" if c_ent > 1.0 else "D"))))

        table.add_row(
            "[dim][OVERLAY][/dim]",
            "-",
            hex(len(overlay_data)),
            f"{overlay_entropy:.2f}",
            "[dim]DATA[/dim]",
            get_entropy_heatmap_string(overlay_data),
            status
        )

        sections_telemetry.append({
            "name": "[OVERLAY]",
            "virt_size": "-",
            "raw_size": hex(len(overlay_data)),
            "entropy": overlay_entropy,
            "perms": "DATA",
            "status": status.strip("[]").replace("red", "").replace("/", ""),
            "raw_heatmap": "".join(raw_heatmap_chars)
        })

    installer_type = detect_installer(file_data, overlay_data, pe=pe)
    has_rich, rich_ck = check_rich_header(pe)

    total_imports, flagged_apis = inspect_imports(pe)
    if not is_dotnet:
        if total_imports < 15 and file_size > 30000:
            anomalies.append(f"Unusually small import table ({total_imports} functions).")
            threat_score += 20

    if flagged_apis:
        anomalies.append(f"Sensitive APIs: {', '.join(flagged_apis)}")
        threat_score += 15

    # String-based obfuscation and memory staging detection (UUID / IPv4 / MAC)
    staging_apis, uuid_count, has_uuid_cluster, ip_count, has_ip_cluster = detect_string_staging(file_data, flagged_apis)
    if staging_apis or has_uuid_cluster or has_ip_cluster:
        has_staging = True
        parts = []
        if staging_apis:
            parts.append(f"Staging APIs: {', '.join(staging_apis)}")
        if has_uuid_cluster:
            parts.append(f"UUID array cluster: {uuid_count} formatted strings")
        if has_ip_cluster:
            parts.append(f"IP address array cluster: {ip_count} formatted strings")
        anomalies.append(f"String-based shellcode staging primitive detected ({'; '.join(parts)}).")
        threat_score += 35

    # Installer and Authenticode whitelisting (FP reduction)
    exec_high_entropy = any(
        s.get('perms') in ('R+X', 'W+X') and s.get('entropy', 0) > 7.0 
        for s in sections_telemetry
    )
    is_trusted_installer = installer_type in ("Nullsoft NSIS Setup", "Inno Setup", "WiX / Burn Bootstrapper", "InstallShield Setup")
    if (is_trusted_installer or is_signed) and not has_wx and not has_staging and not exec_high_entropy:
        discount = 35 if is_trusted_installer else 20
        old_score = threat_score
        threat_score = max(0, threat_score - discount)
        src = installer_type if is_trusted_installer else "Valid Authenticode Digital Signature"
        anomalies.append(f"Whitelisting discount: Verified {src}. Resource/overlay compressed assets discounted (-{discount} pts: {old_score} -> {threat_score}).")
    elif installer_type == "Unverified NSIS Marker":
        anomalies.append("Suspicious: Unverified NSIS marker in overlay without valid installer structure (potential evasion spoof).")
        threat_score += 25

    indicators = []
    for s_name, s_bytes, s_ent in high_entropy_sections:
        indicators.extend(harvest_indicators(s_bytes))
    indicators = list(set(indicators))

    threat_score = min(100, threat_score)

    if threat_score >= 70:
        verdict_color = "red"
        verdict_text = "[CRITICAL] High Risk (Packed / Obfuscated)"
    elif threat_score >= 35:
        verdict_color = "yellow"
        verdict_text = "[WARNING] Suspicious (Anomalies Present)"
    else:
        verdict_color = "green"
        verdict_text = "[OK] Clean / Low Risk"

    mitre_techniques = map_mitre_techniques(anomalies, flagged_apis, has_wx, len(high_entropy_sections) > 0, has_overlay, is_diluted, has_staging=has_staging, has_concealed=has_concealed)
    ep_disasm = disassemble_entry_point(pe, file_data) if deep else None

    if not quiet:
        console.print(table)
        score_panel_text = (
            f"[bold {verdict_color}]Score: {threat_score}/100[/bold {verdict_color}]\n"
            f"[bold]Verdict:[/bold] [{verdict_color}]{verdict_text}[/{verdict_color}]\n"
            f"[bold]Format:[/bold] {'Managed (.NET)' if is_dotnet else 'Native PE'} | "
            f"[bold]Signature:[/bold] {'Signed' if is_signed else 'Unsigned'}\n\n"
            f"[underline]Findings:[/underline]\n"
            + ("\n".join([f"• [{verdict_color}]{a}[/{verdict_color}]" for a in anomalies]) if anomalies else "• Clean structure.")
        )
        if indicators:
            score_panel_text += "\n\n[underline]Extracted Indicators:[/underline]\n" + "\n".join([f"• [cyan]{ind}[/cyan]" for ind in indicators])

        console.print("\n", Panel(score_panel_text, title="Triage Diagnostic", border_style=verdict_color))

        if deep:
            if mitre_techniques:
                mitre_table = Table(title="MITRE ATT&CK Adversary Techniques", show_header=True, header_style="bold magenta")
                mitre_table.add_column("Technique ID", style="bold cyan", justify="center")
                mitre_table.add_column("Technique Name", style="bold")
                mitre_table.add_column("Triggered By", style="dim")
                for tid, tname, tdesc in mitre_techniques:
                    mitre_table.add_row(tid, tname, tdesc)
                console.print(mitre_table)

            if ep_disasm:
                console.print("\n", Panel(ep_disasm, title="Entry Point Disassembly Stub", border_style="dim"))

    if dump_payloads:
        if high_entropy_sections:
            out_dir = "extracted_payloads"
            os.makedirs(out_dir, exist_ok=True)
            for s_name, data, ent in high_entropy_sections:
                clean_name = "".join([c if c.isalnum() else "_" for c in s_name])
                out_path = os.path.join(out_dir, f"{os.path.basename(file_path)}_{clean_name}.bin")
                with open(out_path, "wb") as f:
                    f.write(data)
                if not quiet:
                    console.print(f"[green][+] Carved payload ({len(data)} bytes) -> {out_path}[/green]")

    telemetry_data = {
        "filename": os.path.basename(file_path),
        "path": file_path,
        "hashes": hashes,
        "imphash": imphash_val,
        "threat_score": threat_score,
        "verdict": verdict_text,
        "color": verdict_color,
        "is_dotnet": is_dotnet,
        "is_signed": is_signed,
        "has_overlay": has_overlay,
        "overlay_size": len(overlay_data),
        "total_imports": total_imports,
        "anomalies": anomalies,
        "mitre": mitre_techniques,
        "ep_disasm": ep_disasm,
        "indicators": indicators,
        "sections": sections_telemetry,
        "wx": has_wx
    }

    if json_out:
        out_dir = os.path.dirname(os.path.abspath(json_out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(telemetry_data, f, indent=2)
        console.print(f"[green][+] JSON telemetry written:[/green] {os.path.abspath(json_out)}")

    if html_out:
        generate_minimal_html_report(telemetry_data, html_out)
        console.print(f"[green][+] HTML report generated:[/green] {os.path.abspath(html_out)}")

    return telemetry_data

def analyze_elf(file_path, file_data, quiet=False):
    """Basic cross-platform fallback for Linux ELF binaries."""
    if not quiet:
        console.print(f"\n[bold]Target:[/bold] {file_path}")
        console.print("[dim]Format: Linux ELF Binary[/dim]")

    entropy = calculate_entropy(file_data)
    status = "[red]HIGH[/red]" if entropy > 7.4 else ("[yellow]SUSP[/yellow]" if entropy > 6.6 else "[green]OK[/green]")
    
    table = Table(title="ELF Binary Entropy Summary", show_header=True, header_style="bold")
    table.add_column("Type", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Entropy", justify="right")
    table.add_column("Entropy Strip", justify="left")
    table.add_column("Status", justify="center")
    
    table.add_row(
        "ELF Full Image",
        hex(len(file_data)),
        f"{entropy:.2f}",
        get_entropy_heatmap_string(file_data),
        status
    )
    if not quiet:
        console.print(table)
    return {
        "filename": os.path.basename(file_path),
        "path": file_path,
        "threat_score": 50 if entropy > 7.4 else 0,
        "verdict": "[WARNING] High Entropy ELF" if entropy > 7.4 else "[OK] Clean ELF",
        "color": "yellow" if entropy > 7.4 else "green",
        "is_dotnet": False,
        "is_signed": False,
        "has_overlay": False,
        "overlay_size": 0,
        "total_imports": 0,
        "anomalies": ["High entropy full image"] if entropy > 7.4 else [],
        "indicators": [],
        "sections": [],
        "wx": False
    }

def scan_directory(dir_path, recursive=False, dump_payloads=False):
    dir_path = os.path.abspath(os.path.normpath(dir_path.strip().strip('"\'')))
    if not os.path.isdir(dir_path):
        console.print(f"[red]Error: Directory not found -> {dir_path}[/red]")
        return

    console.print(f"\n[bold]Scanning Directory:[/bold] {dir_path} (Recursive={recursive})")
    
    executable_files = []
    valid_exts = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi"}

    if recursive:
        for root, _, files in os.walk(dir_path):
            for f in files:
                if os.path.splitext(f)[1].lower() in valid_exts:
                    executable_files.append(os.path.join(root, f))
    else:
        for f in os.listdir(dir_path):
            p = os.path.join(dir_path, f)
            if os.path.isfile(p) and os.path.splitext(f)[1].lower() in valid_exts:
                executable_files.append(p)

    if not executable_files:
        console.print("[dim]No executable files found in directory.[/dim]")
        return

    console.print(f"[dim]Triaging {len(executable_files)} binaries...[/dim]\n")

    results = []
    for fp in executable_files:
        res = analyze_single_file(fp, dump_payloads=dump_payloads, quiet=True)
        if res:
            results.append(res)

    if not results:
        console.print("[dim]No valid Windows PE binaries found.[/dim]")
        return

    results.sort(key=lambda x: x["threat_score"], reverse=True)

    triage_table = Table(title="Incident Triage Leaderboard", show_header=True, header_style="bold")
    triage_table.add_column("Rank", justify="center", style="dim")
    triage_table.add_column("Filename", style="cyan")
    triage_table.add_column("Score", justify="right")
    triage_table.add_column("W+X", justify="center")
    triage_table.add_column(".NET", justify="center")
    triage_table.add_column("Overlay", justify="center")
    triage_table.add_column("Verdict", justify="center")
    triage_table.add_column("Primary Flag", style="dim")

    for idx, r in enumerate(results, 1):
        score_str = f"[{r['color']}]{r['threat_score']}[/{r['color']}]"
        verdict_str = f"[{r['color']}]{r['verdict']}[/{r['color']}]"
        wx_str = "[bold red]YES[/bold red]" if r["wx"] else "[dim]NO[/dim]"
        dotnet_str = "[cyan]YES[/cyan]" if r["is_dotnet"] else "[dim]NO[/dim]"
        overlay_str = "[bold red]YES[/bold red]" if r["has_overlay"] else "[dim]NO[/dim]"
        top_anomaly = r["anomalies"][0] if r["anomalies"] else "None"

        triage_table.add_row(
            str(idx),
            r["filename"],
            score_str,
            wx_str,
            dotnet_str,
            overlay_str,
            verdict_str,
            top_anomaly
        )

    console.print(triage_table)
    console.print(f"\n[green][+] Completed:[/green] Triaged {len(results)} binaries.")

def main():
    console.print(BANNER, style="cyan")
    parser = argparse.ArgumentParser(description="entropystrip: PE De-obfuscator & Triage Engine")
    parser.add_argument("target", help="Path to Windows executable (.exe / .dll) or directory")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan subdirectories")
    parser.add_argument("--dump", action="store_true", help="Carve high-entropy payloads to extracted_payloads/")
    parser.add_argument("--deep", action="store_true", help="Deep forensic triage: MITRE ATT&CK mapping, entry point disassembly, and hashes")
    parser.add_argument("--html", help="Path to write HTML report")
    parser.add_argument("--json", help="Path to write JSON telemetry")
    args = parser.parse_args()

    clean_target = os.path.abspath(os.path.normpath(args.target.strip().strip('"\'')))

    if os.path.isdir(clean_target):
        scan_directory(clean_target, recursive=args.recursive, dump_payloads=args.dump)
    else:
        analyze_single_file(clean_target, dump_payloads=args.dump, quiet=False, html_out=args.html, json_out=args.json, deep=args.deep)

if __name__ == "__main__":
    main()
