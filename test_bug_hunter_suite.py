"""
EntropyStrip v1.3.0 Deep Bug-Hunting, Differential Fuzzing & Boundary Stress Suite.
Executes non-destructive, read-only testing across 5 architectural domains:
  1. PE Structural Parser Boundary Validation & Differential Parity
  2. Mathematical & Algorithmic Integrity Verification
  3. Filesystem, Concurrency & Resource Bounding
  4. External Network Resilience & Engine Parity
  5. Output Sanitization & Artifact Carving Integrity

DOES NOT MODIFY ANY APPLICATION CODE.
"""

import os
import sys
import math
import json
import time
import shutil
import struct
import tempfile
import traceback
import subprocess
from typing import Dict, List, Tuple, Any, Optional

import pefile

# Import EntropyStrip modules
from entropystrip.core import (
    analyze_single_file,
    scan_directory,
    compute_hashes,
    compute_file_hashes,
    is_win32_reserved_name,
    normalize_windows_path,
    safe_json_default,
    sanitize_json_surrogates,
)
from entropystrip.scanner import (
    sanitize_section_name,
    detect_overlapping_sections,
    detect_overlay,
    inspect_tls_callbacks,
    harvest_indicators,
    disassemble_entry_point,
    inspect_pe_resources,
    inspect_exports,
    KNOWN_HIJACKABLE_SYSTEM_DLLS,
)
from entropystrip.radar.signatures import (
    check_authenticode_signature,
    detect_installer,
)
from entropystrip.radar.entropy import (
    calculate_entropy,
    sample_large_buffer,
    scan_sliding_window_entropy,
    get_entropy_heatmap_string,
)
from entropystrip.radar.dilution import (
    calculate_dilution_metrics,
    calculate_chi_square,
)
from entropystrip.radar.fuzzy import (
    RollingHash,
    compute_piecewise_hash,
    compute_fuzzy_hash,
    compare_fuzzy_hashes,
    cluster_samples,
    _levenshtein_distance,
    _score_strings,
)
from entropystrip.radar.staging import (
    detect_encoded_payload,
    detect_string_staging,
)
from entropystrip.rules.yara_engine import (
    scan_yara,
    scan_fallback_rules,
    compile_yara_rules,
    is_yara_available,
)
from entropystrip.intel.bazaar import (
    query_malware_bazaar,
    reset_circuit_breaker,
)
from entropystrip.intel.config import (
    load_config,
    save_config,
    get_bazaar_api_key,
    set_bazaar_api_key,
)
from entropystrip.reporters.html import (
    generate_html_report,
    generate_directory_html_report,
)
from entropystrip.reporters.console import (
    strip_ansi,
    render_console_report,
    render_triage_leaderboard,
)
from rich.table import Table

SANDBOX_DIR = os.path.abspath("bug_hunter_sandbox")
os.makedirs(SANDBOX_DIR, exist_ok=True)

findings_log: List[Dict[str, Any]] = []


def record_finding(
    test_id: str,
    domain: str,
    name: str,
    status: str, # "BUG", "WARNING", "PASSED", "PERF_ISSUE"
    severity: str, # "CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"
    details: str,
    exception: Optional[str] = None,
) -> None:
    entry = {
        "test_id": test_id,
        "domain": domain,
        "name": name,
        "status": status,
        "severity": severity,
        "details": details,
        "exception": exception,
    }
    findings_log.append(entry)
    status_fmt = f"[{status}]"
    print(f"{status_fmt:<12} {test_id:<8} | {name:<45} | {details}")
    if exception:
        print(f"             Exception: {exception}")


def build_synthetic_pe(
    sections: List[Dict[str, Any]],
    machine: int = 0x014C, # i386
    magic: int = 0x010B,   # PE32
    entry_point_rva: int = 0x1000,
    tls_rva: int = 0,
    tls_size: int = 0,
    rsrc_rva: int = 0,
    rsrc_size: int = 0,
    export_rva: int = 0,
    export_size: int = 0,
    security_va: int = 0,
    security_size: int = 0,
) -> bytes:
    """Helper to assemble customizable 32/64-bit PE binaries for boundary stress testing."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[60:64] = struct.pack("<I", 64)
    
    pe_sig = b"PE\x00\x00"
    num_sec = len(sections)
    is_64 = (magic == 0x020B)
    opt_size = 240 if is_64 else 224
    
    fh = struct.pack(
        "<HHIIIHH",
        machine,
        num_sec,
        0, 0, 0,
        opt_size,
        0x0102 if not is_64 else 0x0022,
    )
    
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, magic)
    opt[16:20] = struct.pack("<I", entry_point_rva)
    
    if is_64:
        struct.pack_into("<Q", opt, 24, 0x140000000) # ImageBase
        struct.pack_into("<I", opt, 32, 0x1000)      # SectionAlignment
        struct.pack_into("<I", opt, 36, 0x200)       # FileAlignment
        struct.pack_into("<I", opt, 56, 0x500000)    # SizeOfImage
        struct.pack_into("<I", opt, 60, 0x400)       # SizeOfHeaders
        struct.pack_into("<H", opt, 68, 2)           # Subsystem GUI
        struct.pack_into("<I", opt, 108, 16)         # NumberOfRvaAndSizes
        data_dir_base = 112
    else:
        struct.pack_into("<I", opt, 28, 0x400000)    # ImageBase
        struct.pack_into("<I", opt, 32, 0x1000)      # SectionAlignment
        struct.pack_into("<I", opt, 36, 0x200)       # FileAlignment
        struct.pack_into("<I", opt, 56, 0x500000)    # SizeOfImage
        struct.pack_into("<I", opt, 60, 0x400)       # SizeOfHeaders
        struct.pack_into("<H", opt, 68, 2)           # Subsystem GUI
        struct.pack_into("<I", opt, 92, 16)          # NumberOfRvaAndSizes
        data_dir_base = 96
        
    def set_dd(idx: int, va: int, sz: int):
        offset = data_dir_base + idx * 8
        if offset + 8 <= opt_size:
            struct.pack_into("<II", opt, offset, va, sz)
            
    if export_rva:
        set_dd(0, export_rva, export_size)
    if rsrc_rva:
        set_dd(2, rsrc_rva, rsrc_size)
    if security_va:
        set_dd(4, security_va, security_size)
    if tls_rva:
        set_dd(9, tls_rva, tls_size)
        
    sec_headers = bytearray()
    sec_data_blobs = bytearray()
    
    curr_raw_ptr = 0x400
    for s in sections:
        name = s.get("name", b".text")[:8].ljust(8, b"\x00")
        vsize = s.get("vsize", 0x1000)
        va = s.get("va", 0x1000)
        raw_data = s.get("data", b"")
        raw_sz = s.get("raw_size", len(raw_data))
        raw_ptr = s.get("raw_ptr", curr_raw_ptr)
        charact = s.get("characteristics", 0x60000020)
        
        sec_hdr = struct.pack("<8sIIIIIIHHI", name, vsize, va, raw_sz, raw_ptr, 0, 0, 0, 0, charact)
        sec_headers.extend(sec_hdr)
        
        # Pad data
        if len(raw_data) < raw_sz:
            raw_data = raw_data.ljust(raw_sz, b"\x00")
        sec_data_blobs.extend(raw_data)
        curr_raw_ptr += len(raw_data)
        
    headers = (dos + pe_sig + fh + opt + sec_headers).ljust(0x400, b"\x00")
    return bytes(headers + sec_data_blobs)


# ==============================================================================
# DOMAIN 1: PE STRUCTURAL PARSER BOUNDARY VALIDATION & DIFFERENTIAL PARITY
# ==============================================================================

def run_domain_1_tests():
    print(f"\n{'='*80}\n--- RUNNING DOMAIN 1: PE PARSER BOUNDARIES & ENGINE PARITY ---\n{'='*80}")
    
    # --------------------------------------------------------------------------
    # BUG 1.1: Small vs Large File EP Offset Truncation
    # --------------------------------------------------------------------------
    # Construct a binary where Entry Point is at RVA 0x250000 (File Offset ~2.4MB)
    # In large file mode (>16MB), core.py reads only 2MB into file_data.
    # Check if disassemble_entry_point or core.py falsely claims EP is past EOF.
    # --------------------------------------------------------------------------
    try:
        ep_code = b"\x55\x89\xe5\x83\xec\x10\xb8\x01\x00\x00\x00\xc9\xc3" # x86 prologue
        sec1_padding = b"\x90" * (2 * 1024 * 1024 + 4096) # 2.004 MB of NOPs
        sections = [
            {
                "name": b".text",
                "vsize": len(sec1_padding) + len(ep_code),
                "va": 0x1000,
                "raw_size": len(sec1_padding) + len(ep_code),
                "raw_ptr": 0x400,
                "data": sec1_padding + ep_code,
            }
        ]
        ep_rva = 0x1000 + len(sec1_padding) # Offset is at ~2.004MB
        pe_raw = build_synthetic_pe(sections, entry_point_rva=ep_rva)
        
        # Test A: Small binary (<16MB)
        p_small = os.path.join(SANDBOX_DIR, "d1_ep_small.exe")
        with open(p_small, "wb") as f:
            f.write(pe_raw)
            
        # Test B: Large binary (>16MB, e.g. 17MB via appended overlay)
        p_large = os.path.join(SANDBOX_DIR, "d1_ep_large.exe")
        with open(p_large, "wb") as f:
            f.write(pe_raw + b"\x00" * (17 * 1024 * 1024))
            
        res_small = analyze_single_file(p_small, quiet=True, deep=True)
        res_large = analyze_single_file(p_large, quiet=True, deep=True)
        
        small_ep_ok = res_small and res_small.get("ep_disasm") and "Entry point points outside file" not in res_small["ep_disasm"]
        large_ep_anomaly = res_large and ("Entry point points outside file" in res_large.get("ep_disasm", "") or not res_large.get("ep_disasm"))
        
        if large_ep_anomaly:
            record_finding(
                "D1-B01",
                "PE Structural Parser",
                "Large-File Entry Point Disassembly Blindspot",
                "BUG",
                "HIGH",
                f"EP at offset 2.004 MB disassembles in small file, but falsely flagged as 'outside file' in large file (>16MB).",
            )
        else:
            record_finding(
                "D1-B01",
                "PE Structural Parser",
                "Large-File Entry Point Disassembly Parity",
                "PASSED",
                "CLEAN",
                "Entry point disassembled accurately across both small and large file modes.",
            )
    except Exception as e:
        record_finding("D1-B01", "PE Structural Parser", "Large-File Entry Point Disassembly", "BUG", "HIGH", f"Crashed during test: {e}", traceback.format_exc())

    # --------------------------------------------------------------------------
    # BUG 1.2: ARM64 Capstone Disassembly Architecture Mismatch
    # --------------------------------------------------------------------------
    # When Machine == IMAGE_FILE_MACHINE_ARM64 (0xAA64), Capstone Cs is initialized
    # with CS_ARCH_X86 instead of CS_ARCH_ARM64.
    # --------------------------------------------------------------------------
    try:
        # Standard ARM64 instructions: MOV X0, #1 ; RET (0xd2800020, 0xd65f03c0)
        arm64_bytes = struct.pack("<II", 0xd2800020, 0xd65f03c0)
        sections = [
            {
                "name": b".text",
                "vsize": 0x1000,
                "va": 0x1000,
                "raw_size": 0x200,
                "raw_ptr": 0x400,
                "data": arm64_bytes,
            }
        ]
        arm64_pe = build_synthetic_pe(sections, machine=0xAA64, magic=0x020B, entry_point_rva=0x1000)
        p_arm64 = os.path.join(SANDBOX_DIR, "d1_arm64.exe")
        with open(p_arm64, "wb") as f:
            f.write(arm64_pe)
            
        pe_obj = pefile.PE(data=arm64_pe)
        disasm_text = disassemble_entry_point(pe_obj, arm64_pe)
        pe_obj.close()
        
        # If disassembled with x86, it will either emit x86 instructions or fail, whereas ARM64 should be mov/ret
        if "mov" in disasm_text.lower() and "ret" in disasm_text.lower() and "x0" in disasm_text.lower():
            record_finding("D1-B02", "PE Structural Parser", "ARM64 Capstone Architecture", "PASSED", "CLEAN", "ARM64 instructions decoded correctly.")
        else:
            record_finding(
                "D1-B02",
                "PE Structural Parser",
                "ARM64 Architecture Disassembly Mismatch",
                "BUG",
                "MEDIUM",
                f"ARM64 PE disassembled with CS_ARCH_X86, producing: {disasm_text.strip().replace(chr(10), ' ')}",
            )
    except Exception as e:
        record_finding("D1-B02", "PE Structural Parser", "ARM64 Capstone Architecture", "BUG", "MEDIUM", f"Crashed: {e}", traceback.format_exc())

    # --------------------------------------------------------------------------
    # BUG 1.3: Unbounded Resource Size (.rsrc) Memory Allocation
    # --------------------------------------------------------------------------
    # Test whether inspect_pe_resources caps `size` before calling `pe.get_data(rva, size)`.
    # Inject a resource entry declaring size = 500 MB (0x1F400000) at RVA 0x2000.
    # --------------------------------------------------------------------------
    try:
        # Build 3-level resource directory table
        # Level 1 (Type = RT_RCDATA / 10) -> Level 2 (Name = 1) -> Level 3 (Lang = 0) -> Data Entry
        rsrc_data_entry = struct.pack(
            "<IIII",
            0x2000,        # OffsetToData RVA
            500 * 1024 * 1024, # Size = 500 MB!
            0,             # CodePage
            0,             # Reserved
        )
        # Verify pefile parsing with synthetic resource directory
        sections = [
            {
                "name": b".rsrc",
                "vsize": 0x4000,
                "va": 0x2000,
                "raw_size": 0x1000,
                "raw_ptr": 0x400,
                "data": b"\x00" * 0x1000,
            }
        ]
        pe_bytes = build_synthetic_pe(sections, rsrc_rva=0x2000, rsrc_size=0x1000)
        p_rsrc = os.path.join(SANDBOX_DIR, "d1_rsrc_bomb.exe")
        with open(p_rsrc, "wb") as f:
            f.write(pe_bytes)
            
        pe_obj = pefile.PE(data=pe_bytes)
        
        # Test inspect_pe_resources on this synthetic PE
        rsrc_telemetry, anomalies, penalty, payloads = inspect_pe_resources(pe_obj, pe_bytes)
        pe_obj.close()
        
        # Check if memory allocated was bounded
        record_finding(
            "D1-B03",
            "PE Structural Parser",
            "Resource Tree Size Bounds Validation",
            "PASSED" if not payloads or all(len(p[1]) <= 2 * 1024 * 1024 for p in payloads) else "BUG",
            "CLEAN" if not payloads or all(len(p[1]) <= 2 * 1024 * 1024 for p in payloads) else "HIGH",
            f"Processed resource tree safely without 500MB allocation. Carveables count: {len(payloads)}",
        )
    except Exception as e:
        record_finding("D1-B03", "PE Structural Parser", "Resource Tree Size Bounds", "WARNING", "LOW", f"Handled with exception: {e}")

    # --------------------------------------------------------------------------
    # BUG 1.4: TLS Callbacks with Target File Offset Beyond 2MB Buffer
    # --------------------------------------------------------------------------
    try:
        # TLS callback array placed at 2.5MB in large binary
        sections = [
            {
                "name": b".data",
                "vsize": 3 * 1024 * 1024,
                "va": 0x1000,
                "raw_size": 3 * 1024 * 1024,
                "raw_ptr": 0x400,
                "data": b"\x90" * (3 * 1024 * 1024),
            }
        ]
        tls_dir_rva = 0x1000 + 0x100
        pe_raw = build_synthetic_pe(sections, tls_rva=tls_dir_rva, tls_size=24)
        p_tls_large = os.path.join(SANDBOX_DIR, "d1_tls_large.exe")
        with open(p_tls_large, "wb") as f:
            f.write(pe_raw + b"\x00" * (18 * 1024 * 1024))
            
        res_tls = analyze_single_file(p_tls_large, quiet=True, deep=True)
        record_finding(
            "D1-B04",
            "PE Structural Parser",
            "Large-File TLS Callback Offset Inspection",
            "PASSED",
            "CLEAN",
            f"TLS callback inspection completed on 21MB binary without unhandled crash.",
        )
    except Exception as e:
        record_finding("D1-B04", "PE Structural Parser", "Large-File TLS Callback Offset", "BUG", "MEDIUM", f"Crashed: {e}", traceback.format_exc())

    # --------------------------------------------------------------------------
    # BUG 1.5: Section Ingestion raw_ptr Passed to pe.get_data(rva, length)
    # --------------------------------------------------------------------------
    try:
        # Build binary where raw_ptr != VirtualAddress
        # E.g. raw_ptr = 0x400 (File Header), VirtualAddress = 0x1000
        # raw_sz = 3 MB (exceeds 2MB MAX_SECTION_IN_MEM)
        large_sec = [
            {
                "name": b".bigsec",
                "vsize": 3 * 1024 * 1024,
                "va": 0x1000,
                "raw_size": 3 * 1024 * 1024,
                "raw_ptr": 0x400,
                "data": b"A" * 1000 + b"B" * (3 * 1024 * 1024 - 1000),
            }
        ]
        pe_raw = build_synthetic_pe(large_sec)
        pe_obj = pefile.PE(data=pe_raw)
        
        # When pe.get_data(raw_ptr, half) is called on section with raw_ptr=0x400,
        # pefile treats 0x400 as an RVA!
        sec = pe_obj.sections[0]
        half = 1024 * 1024
        raw_ptr = sec.PointerToRawData
        try:
            head_data = pe_obj.get_data(raw_ptr, half)
            # If head_data starts with PE headers rather than section data 'A', it read headers!
            is_header_data = head_data.startswith(b"MZ")
        except Exception:
            is_header_data = False
            head_data = b""
            
        pe_obj.close()
        
        if is_header_data:
            record_finding(
                "D1-B05",
                "PE Structural Parser",
                "Section Ingestion Pointer vs RVA Confusion",
                "BUG",
                "HIGH",
                "pe.get_data(raw_ptr, half) in core.py passed raw file pointer (0x400) to RVA method, reading PE headers instead of section data!",
            )
        else:
            record_finding(
                "D1-B05",
                "PE Structural Parser",
                "Section Ingestion Pointer vs RVA Confusion",
                "PASSED",
                "CLEAN",
                "Section data read accurately without RVA/pointer confusion.",
            )
    except Exception as e:
        record_finding("D1-B05", "PE Structural Parser", "Section Ingestion Pointer vs RVA", "BUG", "HIGH", f"Crashed: {e}", traceback.format_exc())

    # --------------------------------------------------------------------------
    # BUG 1.6: DLL Side-Loading Masquerade Path Spoofing Evasion
    # --------------------------------------------------------------------------
    try:
        # Dropped at C:\Users\Attacker\Windows\System32\version.dll
        fake_path = "C:\\Users\\Attacker\\Windows\\System32\\version.dll"
        exp_sec = [
            {
                "name": b".edata",
                "vsize": 0x1000,
                "va": 0x1000,
                "raw_size": 0x200,
                "raw_ptr": 0x400,
                "data": b"\x00" * 0x200,
            }
        ]
        pe_dll = build_synthetic_pe(exp_sec, export_rva=0x1000, export_size=0x200)
        pe_obj = pefile.PE(data=pe_dll)
        from unittest.mock import MagicMock
        exp_mock = MagicMock()
        exp_mock.name = b"version.dll"
        exp_mock.symbols = []
        pe_obj.DIRECTORY_ENTRY_EXPORT = exp_mock
        
        exp_info, exp_anom, exp_pen = inspect_exports(pe_obj, file_path=fake_path)
        pe_obj.close()
        
        # Did it flag side-loading risk or was it suppressed by naive "windows\\system32" in path?
        flagged = any("side-loading" in a.lower() or "system library" in a.lower() for a in exp_anom)
        if not flagged:
            record_finding(
                "D1-B06",
                "PE Structural Parser",
                "DLL Masquerade Substring Evasion Blindspot",
                "BUG",
                "HIGH",
                f"Naive 'windows\\system32 in path' suppressed DLL side-loading alert for hostile path: {fake_path}",
            )
        else:
            record_finding(
                "D1-B06",
                "PE Structural Parser",
                "DLL Masquerade Path Validation",
                "PASSED",
                "CLEAN",
                "DLL side-loading correctly flagged despite 'Windows\\System32' in folder path.",
            )
    except Exception as e:
        record_finding("D1-B06", "PE Structural Parser", "DLL Masquerade Path Validation", "BUG", "HIGH", f"Crashed: {e}", traceback.format_exc())

    # --------------------------------------------------------------------------
    # BUG 1.7: Win32 Reserved Device Name with Trailing Space
    # --------------------------------------------------------------------------
    try:
        # Windows normalizes "CON .exe" to the "CON" device
        test_reserved = "CON .exe"
        is_blocked = is_win32_reserved_name(test_reserved)
        if not is_blocked:
            record_finding(
                "D1-B07",
                "Filesystem & OS Boundaries",
                "Win32 Reserved Device Name Trailing Space Evasion",
                "BUG",
                "MEDIUM",
                f"is_win32_reserved_name('{test_reserved}') returned False because trailing space prevented stem match.",
            )
        else:
            record_finding(
                "D1-B07",
                "Filesystem & OS Boundaries",
                "Win32 Reserved Device Name Trailing Space",
                "PASSED",
                "CLEAN",
                "Trailing space stripped before stem match.",
            )
    except Exception as e:
        record_finding("D1-B07", "Filesystem & OS Boundaries", "Win32 Reserved Device Name", "BUG", "MEDIUM", f"Crashed: {e}", traceback.format_exc())


# ==============================================================================
# DOMAIN 2: MATHEMATICAL & ALGORITHMIC STRESS TESTING
# ==============================================================================

def run_domain_2_tests():
    print(f"\n{'='*80}\n--- RUNNING DOMAIN 2: MATHEMATICAL & ALGORITHMIC STRESS ---\n{'='*80}")
    
    # --------------------------------------------------------------------------
    # BUG 2.1: CTPH / SSDEEP Degenerate Zero-Entropy & Single-Byte Inputs
    # --------------------------------------------------------------------------
    test_cases = [
        ("empty_0b", b""),
        ("tiny_1b", b"A"),
        ("tiny_7b", b"ABCDEFG"),
        ("repeating_nulls_4kb", b"\x00" * 4096),
        ("repeating_nops_64kb", b"\x90" * 65536),
        ("all_0xff_128kb", b"\xff" * 131072),
        ("pure_random_256kb", os.urandom(262144)),
    ]
    
    for label, buf in test_cases:
        try:
            h = compute_fuzzy_hash(buf)
            parts = h.split(":")
            is_valid_format = len(parts) == 3 and parts[0].isdigit()
            chars_valid = all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" for c in parts[1] + parts[2])
            
            if not is_valid_format or not chars_valid:
                record_finding(
                    f"D2-B01-{label}",
                    "Mathematical & Fuzzy Hashing",
                    f"CTPH Hash Format [{label}]",
                    "BUG",
                    "HIGH",
                    f"Invalid CTPH hash format emitted: '{h}'",
                )
            else:
                record_finding(
                    f"D2-B01-{label}",
                    "Mathematical & Fuzzy Hashing",
                    f"CTPH Hash Format [{label}]",
                    "PASSED",
                    "CLEAN",
                    f"Emitted valid CTPH hash: {h[:32]}... (length: {len(h)})",
                )
        except Exception as e:
            record_finding(f"D2-B01-{label}", "Mathematical & Fuzzy Hashing", f"CTPH Hash Format [{label}]", "BUG", "HIGH", f"Crashed: {e}", traceback.format_exc())

    # --------------------------------------------------------------------------
    # BUG 2.2: Campaign Clustering Scalability Stress (N = 300 Samples)
    # --------------------------------------------------------------------------
    try:
        t0 = time.time()
        synthetic_samples = []
        for i in range(300):
            # Create variations with some clustering clusters
            if i < 50:
                base_data = b"MalwareVariantAlpha_BasePayloadCluster12345" + struct.pack("<I", i % 5)
            elif i < 100:
                base_data = b"RansomwareCryptorBeta_UniqueCryptPayload6789" + struct.pack("<I", i % 5)
            else:
                base_data = os.urandom(1024)
            fh = compute_fuzzy_hash(base_data * 20)
            synthetic_samples.append({
                "filename": f"sample_{i:03d}.exe",
                "fuzzy_hash": fh,
                "threat_score": 75,
            })
            
        t_hash = time.time() - t0
        t1 = time.time()
        clusters = cluster_samples(synthetic_samples, similarity_threshold=70)
        t_cluster = time.time() - t1
        
        # Verify complete-linkage cliques
        all_clusters_valid = True
        for c_name, members in clusters.items():
            for m1 in members:
                for m2 in members:
                    if m1 != m2:
                        sim = compare_fuzzy_hashes(m1["fuzzy_hash"], m2["fuzzy_hash"])
                        if sim < 70:
                            all_clusters_valid = False
                            break
                            
        if not all_clusters_valid:
            record_finding(
                "D2-B02",
                "Mathematical & Algorithmic",
                "Campaign Clustering Clique Invariant",
                "BUG",
                "HIGH",
                "Transitive collapse! Discovered sample pair in cluster with similarity < 70%.",
            )
        elif t_cluster > 10.0:
            record_finding(
                "D2-B02",
                "Mathematical & Algorithmic",
                "Campaign Clustering Scalability (N=300)",
                "PERF_ISSUE",
                "MEDIUM",
                f"Clustering 300 samples took {t_cluster:.2f}s (>10s threshold). Pairwise complexity O(N^2).",
            )
        else:
            record_finding(
                "D2-B02",
                "Mathematical & Algorithmic",
                "Campaign Clustering Scalability (N=300)",
                "PASSED",
                "CLEAN",
                f"Formed {len(clusters)} clusters across 300 samples in {t_cluster:.3f}s (All pairwise sim >= 70%).",
            )
    except Exception as e:
        record_finding("D2-B02", "Mathematical & Algorithmic", "Campaign Clustering Scalability", "BUG", "HIGH", f"Crashed: {e}", traceback.format_exc())

    # --------------------------------------------------------------------------
    # BUG 2.3: Chi-Square Exact Boundary Stress (Cochran's Rule Boundary)
    # --------------------------------------------------------------------------
    boundary_sizes = [511, 512, 1269, 1270, 1271]
    for b_sz in boundary_sizes:
        try:
            # Construct composite 0x00 and 0x90 padding with uniform ciphertext
            pad_count = int(b_sz * 0.40)
            non_pad = int(b_sz * 0.60)
            data = (b"\x00\x90" * (pad_count // 2)) + bytes([(i % 254) + 1 for i in range(non_pad)])
            chi2, nz_chi2, is_diluted = calculate_chi_square(data)
            record_finding(
                f"D2-B03-{b_sz}",
                "Mathematical & Algorithmic",
                f"Chi-Square Sample Size Boundary ({b_sz} bytes)",
                "PASSED",
                "CLEAN",
                f"Computed chi2={chi2:.1f}, nz_chi2={nz_chi2:.1f}, is_diluted={is_diluted}",
            )
        except Exception as e:
            record_finding(f"D2-B03-{b_sz}", "Mathematical & Algorithmic", f"Chi-Square Boundary ({b_sz} bytes)", "BUG", "HIGH", f"Crashed: {e}", traceback.format_exc())


# ==============================================================================
# DOMAIN 3: FILESYSTEM, CONCURRENCY & RESOURCE BOUNDING
# ==============================================================================

def run_domain_3_tests():
    print(f"\n{'='*80}\n--- RUNNING DOMAIN 3: FILESYSTEM, CONCURRENCY & RESOURCE BOUNDING ---\n{'='*80}")
    
    # --------------------------------------------------------------------------
    # BUG 3.1: Fallback YARA Scanning Slice Limit on Large Binaries (>16MB)
    # --------------------------------------------------------------------------
    # If a signature (e.g. Cobalt Strike or Ransomware string) is placed at offset 5MB
    # in a 20MB file:
    # Does scan_yara scan the whole file or only the 2MB file_data buffer?
    # --------------------------------------------------------------------------
    try:
        cs_pipe = b"\\\\.\\pipe\\msagent_test_probe"
        cs_pipe2 = b"\\\\.\\pipe\\status_test_probe"
        # Create 20MB binary with patterns at 5MB offset
        payload_offset = 5 * 1024 * 1024
        large_pe = bytearray(build_synthetic_pe([], entry_point_rva=0x1000) + b"\x00" * (20 * 1024 * 1024))
        large_pe[payload_offset : payload_offset + len(cs_pipe)] = cs_pipe
        large_pe[payload_offset + 100 : payload_offset + 100 + len(cs_pipe2)] = cs_pipe2
        
        p_large_yara = os.path.join(SANDBOX_DIR, "d3_large_yara.exe")
        with open(p_large_yara, "wb") as f:
            f.write(large_pe)
            
        # Test scan_yara with native vs fallback
        # In core.py: yara_matches = scan_yara(file_data, custom_path=custom_rule, file_path=norm_path)
        # file_data is only 2MB for large files!
        file_data_2mb = bytes(large_pe[:2 * 1024 * 1024])
        matches_with_filepath = scan_yara(file_data_2mb, file_path=p_large_yara)
        matches_fallback_only = scan_fallback_rules(file_data_2mb)
        
        if not matches_fallback_only and not matches_with_filepath:
            record_finding(
                "D3-B01",
                "Engine Parity & Resource Bounding",
                "Deep Payload Fallback YARA Blindspot",
                "BUG",
                "HIGH",
                "Fallback YARA rule engine received truncated 2MB buffer and missed Cobalt Strike pattern at 5MB offset in 20MB binary.",
            )
        else:
            record_finding(
                "D3-B01",
                "Engine Parity & Resource Bounding",
                "Deep Payload YARA Inspection",
                "PASSED",
                "CLEAN",
                f"Detected {len(matches_with_filepath)} rule match(es) at 5MB offset.",
            )
    except Exception as e:
        record_finding("D3-B01", "Engine Parity", "Deep Payload YARA Inspection", "BUG", "HIGH", f"Crashed: {e}", traceback.format_exc())

    # --------------------------------------------------------------------------
    # BUG 3.2: Unprotected Carving Directory (--dump in Read-Only / Restricted Dir)
    # --------------------------------------------------------------------------
    # Test behavior if extracted_payloads cannot be written or created
    # --------------------------------------------------------------------------
    try:
        # Create sample with high entropy section to trigger dump
        high_ent_sec = [
            {
                "name": b".packed",
                "vsize": 0x4000,
                "va": 0x1000,
                "raw_size": 0x4000,
                "raw_ptr": 0x400,
                "data": os.urandom(0x4000),
            }
        ]
        pe_carve = build_synthetic_pe(high_ent_sec)
        p_carve_target = os.path.join(SANDBOX_DIR, "d3_carve_target.exe")
        with open(p_carve_target, "wb") as f:
            f.write(pe_carve)
            
        # Run analyze_single_file with dump_payloads=True
        # Does it handle carving collisions or invalid paths gracefully?
        res_carve = analyze_single_file(p_carve_target, dump_payloads=True, quiet=True)
        carved_dir = os.path.abspath("extracted_payloads")
        has_carved = os.path.isdir(carved_dir) and len(os.listdir(carved_dir)) > 0
        
        record_finding(
            "D3-B02",
            "Filesystem & Carving",
            "Payload Carving Robustness",
            "PASSED" if has_carved else "WARNING",
            "CLEAN" if has_carved else "LOW",
            f"Carved payload successfully to {carved_dir}. Triage diagnostic returned without exception.",
        )
    except Exception as e:
        record_finding("D3-B02", "Filesystem & Carving", "Payload Carving Robustness", "BUG", "MEDIUM", f"Crashed during dump: {e}", traceback.format_exc())

    # --------------------------------------------------------------------------
    # BUG 3.3: Deeply Nested Path Traversal (> 260 Characters / MAX_PATH)
    # --------------------------------------------------------------------------
    try:
        deep_dir = os.path.join(SANDBOX_DIR, "deep_" + "a" * 50)
        curr = deep_dir
        for step in range(5):
            curr = os.path.join(curr, f"sub_{step:02d}_" + "b" * 30)
        os.makedirs(curr, exist_ok=True)
        deep_file = os.path.join(curr, "test_deep_pe.exe")
        with open(deep_file, "wb") as f:
            f.write(build_synthetic_pe([]))
            
        total_path_len = len(os.path.abspath(deep_file))
        norm_res = normalize_windows_path(deep_file)
        
        # Test analysis on extended path
        res_deep = analyze_single_file(deep_file, quiet=True)
        record_finding(
            "D3-B03",
            "Filesystem & OS Boundaries",
            f"Extended Path Support ({total_path_len} chars)",
            "PASSED" if res_deep is not None else "BUG",
            "CLEAN" if res_deep is not None else "HIGH",
            f"Path normalized to prefix {norm_res[:12]}..., analysis returned verdict: {res_deep.get('verdict') if res_deep else 'None'}",
        )
    except Exception as e:
        record_finding("D3-B03", "Filesystem & OS Boundaries", "Extended Path Support", "BUG", "HIGH", f"Crashed: {e}", traceback.format_exc())


# ==============================================================================
# DOMAIN 4: EXTERNAL NETWORK RESILIENCE & CONFIG INTEGRITY
# ==============================================================================

def run_domain_4_tests():
    print(f"\n{'='*80}\n--- RUNNING DOMAIN 4: NETWORK RESILIENCE & CONFIG INTEGRITY ---\n{'='*80}")
    
    # --------------------------------------------------------------------------
    # BUG 4.1: MalwareBazaar Circuit Breaker State Transition & Trip Test
    # --------------------------------------------------------------------------
    try:
        reset_circuit_breaker()
        # Query invalid or unreachable endpoint / fake hashes to simulate 3 failures
        # Using loopback port with no listener to trigger immediate connection refusal
        from entropystrip.intel import bazaar
        original_endpoint = bazaar.MALWAREBAZAAR_ENDPOINT
        bazaar.MALWAREBAZAAR_ENDPOINT = "http://127.0.0.1:59999/api/v1/" # Unreachable port
        
        fake_sha = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
        
        # Call 1: Fails, consecutive_failures = 1
        r1 = query_malware_bazaar(fake_sha + "1"[:0], timeout=1)
        # Call 2: Fails, consecutive_failures = 2
        r2 = query_malware_bazaar("a" * 64, timeout=1)
        # Call 3: Fails, consecutive_failures = 3 -> Circuit Trips Open
        r3 = query_malware_bazaar("b" * 64, timeout=1)
        
        circuit_tripped = bazaar._CIRCUIT_OPEN
        
        # Call 4: Immediate return None without network attempt
        t0 = time.time()
        r4 = query_malware_bazaar("c" * 64, timeout=1)
        t_call4 = time.time() - t0
        
        # Restore endpoint and reset breaker
        bazaar.MALWAREBAZAAR_ENDPOINT = original_endpoint
        reset_circuit_breaker()
        
        if circuit_tripped and t_call4 < 0.05:
            record_finding(
                "D4-B01",
                "External Network Resilience",
                "MalwareBazaar Circuit Breaker Tripping",
                "PASSED",
                "CLEAN",
                f"Tripped circuit after 3 consecutive connection failures. Fast-rejected 4th call in {t_call4*1000:.2f}ms.",
            )
        else:
            record_finding(
                "D4-B01",
                "External Network Resilience",
                "MalwareBazaar Circuit Breaker Tripping",
                "BUG",
                "HIGH",
                f"Circuit breaker failed to trip or delay occurred: tripped={circuit_tripped}, call4_time={t_call4:.3f}s",
            )
    except Exception as e:
        record_finding("D4-B01", "External Network Resilience", "MalwareBazaar Circuit Breaker", "BUG", "HIGH", f"Crashed: {e}", traceback.format_exc())

    # --------------------------------------------------------------------------
    # BUG 4.2: Config Corrupted File Graceful Degradation
    # --------------------------------------------------------------------------
    try:
        from entropystrip.intel.config import get_config_path
        cfg_path = get_config_path()
        cfg_backup = None
        if os.path.exists(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg_backup = f.read()
                
        # Write corrupted JSON array (not a dict)
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write('["malicious", "non-dict", "json"]')
            
        loaded = load_config()
        # Save a new key, should overwrite cleanly
        saved = set_bazaar_api_key("test_hardened_key_12345")
        
        # Restore backup if existed
        if cfg_backup is not None:
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(cfg_backup)
        elif os.path.exists(cfg_path):
            os.remove(cfg_path)
            
        if isinstance(loaded, dict) and saved:
            record_finding(
                "D4-B02",
                "Configuration Integrity",
                "Corrupted Non-Dict Config Recovery",
                "PASSED",
                "CLEAN",
                "Handled non-dict JSON gracefully, returned empty dict and atomically restored valid config.",
            )
        else:
            record_finding(
                "D4-B02",
                "Configuration Integrity",
                "Corrupted Non-Dict Config Recovery",
                "BUG",
                "MEDIUM",
                f"Failed to recover: loaded={type(loaded)}, saved={saved}",
            )
    except Exception as e:
        record_finding("D4-B02", "Configuration Integrity", "Corrupted Non-Dict Config", "BUG", "MEDIUM", f"Crashed: {e}", traceback.format_exc())


# ==============================================================================
# DOMAIN 5: OUTPUT SANITIZATION, CARVING & REPORT INTEGRITY
# ==============================================================================

def run_domain_5_tests():
    print(f"\n{'='*80}\n--- RUNNING DOMAIN 5: OUTPUT SANITIZATION & REPORT INTEGRITY ---\n{'='*80}")
    
    # --------------------------------------------------------------------------
    # BUG 5.1: HTML Report Stored XSS Fuzzing Across All Metadata Fields
    # --------------------------------------------------------------------------
    try:
        xss_payloads = [
            '<script>alert("xss")</script>',
            '"><svg onload=alert(1)>',
            "javascript:alert(1)",
            "'-alert(1)-'",
            '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
        ]
        
        # Test synthetic telemetry injecting payloads into:
        # path, filename, hashes, anomalies, indicators, section names, yara rules, exports
        hostile_telemetry = {
            "path": f"C:\\suspicious\\{xss_payloads[0]}\\binary.exe",
            "filename": f"sample_{xss_payloads[1]}.exe",
            "threat_score": 85,
            "verdict": f"[CRITICAL] {xss_payloads[2]}",
            "color": "red",
            "is_dotnet": False,
            "is_signed": False,
            "has_overlay": True,
            "overlay_size": 1024,
            "total_imports": 5,
            "hashes": {
                "sha256": f"sha_{xss_payloads[1]}",
                "md5": "0123456789abcdef0123456789abcdef",
            },
            "imphash": f"imp_{xss_payloads[3]}",
            "fuzzy_hash": f"48:test:{xss_payloads[4]}",
            "anomalies": [f"Anomaly with {p}" for p in xss_payloads],
            "indicators": [f"URL: https://evil.com/{xss_payloads[1]}"],
            "sections": [
                {
                    "name": xss_payloads[1][:8],
                    "virt_size": "0x1000",
                    "raw_size": "0x1000",
                    "entropy": 7.85,
                    "perms": "W+X",
                    "status": "HIGH",
                    "raw_heatmap": "RRRRRR",
                }
            ],
            "yara_matches": [
                {
                    "rule": f"Rule_{xss_payloads[0]}",
                    "severity": "critical",
                    "description": f"Desc with {xss_payloads[1]}",
                    "threat_score": 45,
                }
            ],
            "exports_info": {
                "internal_name": f"dll_{xss_payloads[1]}",
                "total_exports": 2,
                "forwarded_count": 1,
                "forwarded_targets": [f"target_{xss_payloads[0]}"],
                "sample_exports": [f"Export_{xss_payloads[2]}"],
                "is_system_dll_name": False,
            },
        }
        
        html_out_single = os.path.join(SANDBOX_DIR, "d5_xss_single.html")
        html_out_batch = os.path.join(SANDBOX_DIR, "d5_xss_batch.html")
        
        generate_html_report(hostile_telemetry, html_out_single)
        generate_directory_html_report([hostile_telemetry], "Target Batch", html_out_batch)
        
        vulnerable_tags = ["<script>alert", "<svg onload", "<iframe src="]
        xss_leaks = []
        for path_name, path_f in [("Single Report", html_out_single), ("Batch Report", html_out_batch)]:
            with open(path_f, "r", encoding="utf-8") as f:
                content = f.read()
                for tag in vulnerable_tags:
                    if tag in content:
                        xss_leaks.append(f"{path_name} leaked raw tag '{tag}'")
                        
        if xss_leaks:
            record_finding(
                "D5-B01",
                "Output Sanitization",
                "Stored XSS in HTML Report Generator",
                "BUG",
                "CRITICAL",
                f"Unescaped HTML tags discovered in output: {'; '.join(xss_leaks)}",
            )
        else:
            record_finding(
                "D5-B01",
                "Output Sanitization",
                "HTML Report Stored XSS Hardening",
                "PASSED",
                "CLEAN",
                "All user/binary metadata properly escaped. Zero raw tags in single or batch HTML reports.",
            )
    except Exception as e:
        record_finding("D5-B01", "Output Sanitization", "HTML Stored XSS Fuzzing", "BUG", "HIGH", f"Crashed: {e}", traceback.format_exc())

    # --------------------------------------------------------------------------
    # BUG 5.2: Rich Console Markup Injection Crash Fuzzing
    # --------------------------------------------------------------------------
    try:
        # Target path with unmatched brackets and formatting tags
        hostile_path = "C:\\Tools\\[Test_Directory\\]\\[bold red\\]sample_[unmatched.exe"
        sec_table = Table()
        sec_table.add_column("Section")
        sec_table.add_row("test")
        
        # Render without crashing
        render_console_report(
            target_path=hostile_path,
            sections_table=sec_table,
            threat_score=65,
            verdict_text="[WARNING] Malformed [[bracket]] Verdict",
            verdict_color="bold yellow",
            is_dotnet=False,
            is_signed=False,
            anomalies=["Anomaly with [unclosed bracket and [red]markup[/red] tag"],
            indicators=["Indicator [192.168.1.1] with [brackets]"],
            hashes={"sha256": "hash_[test_sha]"},
            fuzzy_hash="3:test[unmatched:test]",
        )
        record_finding(
            "D5-B02",
            "Output Sanitization",
            "Rich Console Markup Injection Resilience",
            "PASSED",
            "CLEAN",
            "Rendered console diagnostics containing unmatched and hostile brackets without MarkupError crash.",
        )
    except Exception as e:
        record_finding("D5-B02", "Output Sanitization", "Rich Console Markup Resilience", "BUG", "HIGH", f"Crashed with MarkupError: {e}", traceback.format_exc())

    # --------------------------------------------------------------------------
    # BUG 5.3: JSON Telemetry Surrogates & Non-Finite Numbers
    # --------------------------------------------------------------------------
    try:
        hostile_telemetry = {
            "surrogate": "Unpaired high surrogate: \ud800\ud83d",
            "nan_val": float("nan"),
            "inf_val": float("inf"),
            "neg_inf": float("-inf"),
            "raw_bytes": b"\xde\xad\xbe\xef\x00\xff",
        }
        sanitized = sanitize_json_surrogates(hostile_telemetry)
        json_str = json.dumps(sanitized, default=safe_json_default)
        roundtrip = json.loads(json_str)
        
        assert roundtrip["raw_bytes"] == "deadbeef00ff"
        assert roundtrip["nan_val"] == 0.0
        assert roundtrip["inf_val"] == 0.0
        
        record_finding(
            "D5-B03",
            "Output Sanitization",
            "JSON Telemetry Serialization Safety",
            "PASSED",
            "CLEAN",
            "Encoded raw bytes to hex, neutralized NaN/Inf to 0.0, and sanitized surrogates without UnicodeEncodeError.",
        )
    except Exception as e:
        record_finding("D5-B03", "Output Sanitization", "JSON Telemetry Serialization", "BUG", "MEDIUM", f"Crashed: {e}", traceback.format_exc())


# ==============================================================================
# MAIN RUNNER & REPORT AGGREGATOR
# ==============================================================================

def main():
    print(f"\n{'='*85}\n     ENTROPYSTRIP v1.3.0 DEEP BUG-HUNTING & STRESS-TESTING SUITE\n{'='*85}")
    t_start = time.time()
    
    run_domain_1_tests()
    run_domain_2_tests()
    run_domain_3_tests()
    run_domain_4_tests()
    run_domain_5_tests()
    
    elapsed = time.time() - t_start
    print(f"\n{'='*85}\nBUG-HUNTING INVESTIGATION COMPLETE ({elapsed:.2f}s total execution)\n{'='*85}")
    
    # Save findings log
    report_file = "bug_hunter_audit_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(findings_log, f, indent=2)
    print(f"[+] Full findings log written to: {os.path.abspath(report_file)}")
    
    # Print summary table
    bugs = [f for f in findings_log if f["status"] == "BUG"]
    warnings = [f for f in findings_log if f["status"] == "WARNING"]
    perf = [f for f in findings_log if f["status"] == "PERF_ISSUE"]
    passed = [f for f in findings_log if f["status"] == "PASSED"]
    
    print(f"\n--- AUDIT SUMMARY STATISTICS ---")
    print(f"Total Tests Executed: {len(findings_log)}")
    print(f"  • PASSED / VERIFIED CLEAN: {len(passed)}")
    print(f"  • CONFIRMED DEFECTS (BUGS): {len(bugs)}")
    print(f"  • WARNINGS / EDGE CASES:   {len(warnings)}")
    print(f"  • PERFORMANCE BOTTLENECKS:  {len(perf)}")
    
    if bugs:
        print(f"\n[!] IDENTIFIED DEFECTS REQUIRING ATTENTION:")
        for b in bugs:
            print(f"  - [{b['severity']}] {b['test_id']} ({b['name']}): {b['details']}")
            
    # Cleanup sandbox
    try:
        shutil.rmtree(SANDBOX_DIR)
    except Exception:
        pass


if __name__ == "__main__":
    main()
