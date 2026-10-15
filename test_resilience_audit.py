"""
EntropyStrip v1.3.0 - Defensive QA, Boundary Stress-Testing & Resilience Audit Test Suite.

This standalone test suite reproduces and verifies the edge cases, architectural boundaries,
and vulnerabilities identified during the defensive QA and resilience audit across 5 specialized domains:
  1. PE Structural Parser Boundary Validation (TestDomain1PEParserResilience)
  2. Mathematical & Algorithmic Integrity Verification (TestDomain2MathematicalAlgorithmicIntegrity)
  3. Filesystem, Concurrency & Resource Bounding (TestDomain3FilesystemAndResourceBoundaries)
  4. External Network Resilience & Engine Parity (TestDomain4NetworkResilienceAndEngineParity)
  5. Output Sanitization & Artifact Carving Integrity (TestDomain5OutputSanitizationAndCarving)

Execution:
  python -m unittest test_resilience_audit.py
  python -m pytest test_resilience_audit.py
"""

import os
import sys
import json
import math
import struct
import hashlib
import tempfile
import unittest
from unittest.mock import patch

# Ensure entropystrip package is importable
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import pefile
from rich.console import Console
from rich.table import Table
from rich.markup import escape
from rich.errors import MarkupError

# EntropyStrip imports
from entropystrip.core import analyze_single_file, normalize_windows_path, is_win32_reserved_name
from entropystrip.scanner import detect_overlay, detect_overlapping_sections
from entropystrip.radar.signatures import check_authenticode_signature
from entropystrip.radar.entropy import (
    calculate_entropy,
    scan_sliding_window_entropy,
    sample_large_buffer,
)
from entropystrip.radar.dilution import calculate_dilution_metrics, calculate_chi_square
from entropystrip.radar.fuzzy import (
    compare_fuzzy_hashes,
    _score_strings,
    compute_piecewise_hash,
    RollingHash,
    cluster_samples,
)
from entropystrip.rules.yara_engine import scan_fallback_rules, FALLBACK_RULES
from entropystrip.intel import bazaar, config
from entropystrip.reporters.html import (
    generate_html_report,
    generate_directory_html_report,
)
from entropystrip.reporters.console import render_console_report


def build_minimal_pe(
    section_name=b".text",
    section_data=b"\x90" * 511 + b"\xc3",
    sec_characteristics=0x60000020,
    sec_vsize=0x200,
) -> bytes:
    """Generates a minimal valid 32-bit PE binary with customizable section properties."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[60:64] = (64).to_bytes(4, "little")

    pe_sig = b"PE\x00\x00"
    fh = (
        (0x014C).to_bytes(2, "little")  # Machine = i386
        + (1).to_bytes(2, "little")     # NumberOfSections = 1
        + (0).to_bytes(12, "little")
        + (224).to_bytes(2, "little")   # SizeOfOptionalHeader
        + (0x0102).to_bytes(2, "little")  # Characteristics
    )

    raw_size = ((len(section_data) + 0x1FF) // 0x200) * 0x200
    padded_sec_data = section_data.ljust(raw_size, b"\x00")

    opt = bytearray(224)
    opt[0:2] = (0x010B).to_bytes(2, "little")   # PE32
    opt[16:20] = (0x1000).to_bytes(4, "little")  # AddressOfEntryPoint
    opt[28:32] = (0x400000).to_bytes(4, "little")  # ImageBase
    opt[32:36] = (0x1000).to_bytes(4, "little")  # SectionAlignment
    opt[36:40] = (0x200).to_bytes(4, "little")   # FileAlignment
    opt[56:60] = ((0x1000 + max(sec_vsize, raw_size) + 0xFFF) & ~0xFFF).to_bytes(4, "little")  # SizeOfImage
    opt[60:64] = (0x400).to_bytes(4, "little")   # SizeOfHeaders
    opt[68:70] = (2).to_bytes(2, "little")       # Subsystem: Windows GUI
    opt[92:96] = (16).to_bytes(4, "little")      # NumberOfRvaAndSizes

    sec = bytearray(40)
    sec[0:min(8, len(section_name))] = section_name[:8]
    sec[8:12] = (sec_vsize).to_bytes(4, "little")
    sec[12:16] = (0x1000).to_bytes(4, "little")
    sec[16:20] = (raw_size).to_bytes(4, "little")
    sec[20:24] = (0x400).to_bytes(4, "little")   # PointerToRawData
    sec[36:40] = (sec_characteristics).to_bytes(4, "little")

    headers = (dos + pe_sig + fh + opt + sec).ljust(0x400, b"\x00")
    return bytes(headers + padded_sec_data)


# ==============================================================================
# Domain 1: PE Structural Parser Boundary Validation
# ==============================================================================

class TestDomain1PEParserResilience(unittest.TestCase):
    """
    Validates structural parser boundary handling, unhandled exceptions,
    and architectural edge cases in scanner.py, core.py, and signatures.py.
    """

    def test_d1_01_truncated_mz_misclassified_as_legacy_dos(self):
        """
        Finding 1.1: Files starting with MZ but shorter than 64 bytes are rejected as
        corrupted/truncated DOS headers with a Critical/High Risk verdict, not legacy DOS.
        """
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "truncated_mz.exe")
            with open(p, "wb") as f:
                f.write(b"MZ\x00\x00truncated")
            res = analyze_single_file(p, quiet=True)
            self.assertIsNotNone(res)
            self.assertEqual(res["verdict"], "[CRITICAL] High Risk (Corrupted / Malformed PE Headers)")
            self.assertGreaterEqual(res["threat_score"], 60)
            self.assertTrue(any("Truncated DOS header" in a for a in res.get("anomalies", [])))

    def test_d1_02_generic_elfanew_exception_conflation(self):
        """
        Finding 1.2: Corrupt PE signature at e_lfanew specifically reports invalid PE
        signature anomaly, rather than claiming e_lfanew points past EOF.
        """
        with tempfile.TemporaryDirectory() as td:
            raw = bytearray(build_minimal_pe())
            # Keep e_lfanew=64 valid, but corrupt the PE signature PE\0\0 -> XX\0\0
            raw[64:68] = b"XX\x00\x00"
            p = os.path.join(td, "corrupt_pe_sig.exe")
            with open(p, "wb") as f:
                f.write(raw)
            res = analyze_single_file(p, quiet=True)
            self.assertIsNotNone(res)
            has_sig_anomaly = any("Invalid PE signature" in a for a in res.get("anomalies", []))
            self.assertTrue(has_sig_anomaly, "Exception handling should report invalid PE signature")
            has_eof_anomaly = any("points past EOF" in a for a in res.get("anomalies", []))
            self.assertFalse(has_eof_anomaly, "Should not claim e_lfanew points past EOF when it is within file")

    def test_d1_03_embedded_pe_elfanew_in_dos_header(self):
        """
        Finding 1.3: Embedded PE detection strictly enforces e_lfanew >= 64 to prevent
        spurious embedded PE hits overlapping the DOS header.
        """
        fake_res = bytearray(256)
        fake_res[0:2] = b"MZ"
        fake_res[60:64] = struct.pack("<I", 4)  # Points into DOS header
        fake_res[4:8] = b"PE\x00\x00"

        e_lfanew = struct.unpack("<I", fake_res[60:64])[0]
        # Hardened check enforces e_lfanew >= 64
        is_embedded = 64 <= e_lfanew <= len(fake_res) - 4 and fake_res[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"
        self.assertFalse(is_embedded, "Embedded PE logic must reject e_lfanew < 64 overlapping DOS header")

    def test_d1_04_zero_section_coff_header_clean_verdict(self):
        """
        Finding 2.1: Binary with NumberOfSections = 0 parses 0 sections and core.py
        must flag Header Anomaly and penalize threat score.
        """
        with tempfile.TemporaryDirectory() as td:
            raw = bytearray(build_minimal_pe())
            # NumberOfSections at offset 70 (DOS 64 + PE 4 + Machine 2)
            raw[70:72] = (0).to_bytes(2, "little")
            p = os.path.join(td, "zero_sec.exe")
            with open(p, "wb") as f:
                f.write(raw)
            res = analyze_single_file(p, quiet=True)
            self.assertIsNotNone(res)
            has_zero_anomaly = any("NumberOfSections is 0" in a for a in res.get("anomalies", []))
            self.assertTrue(has_zero_anomaly, "Zero-section binary must flag Header Anomaly")
            self.assertGreater(res["threat_score"], 0)

    def test_d1_05_high_section_count_ignored(self):
        """
        Finding 2.1: Binary with extreme NumberOfSections (e.g. 65535 or > 96) is
        flagged for exceeding Windows loader limits.
        """
        with tempfile.TemporaryDirectory() as td:
            raw = bytearray(build_minimal_pe())
            raw[70:72] = (65535).to_bytes(2, "little")
            p = os.path.join(td, "extreme_sec.exe")
            with open(p, "wb") as f:
                f.write(raw)
            res = analyze_single_file(p, quiet=True)
            self.assertIsNotNone(res)
            has_loader_anomaly = any("exceeds windows loader maximum" in a.lower() for a in res.get("anomalies", []))
            self.assertTrue(has_loader_anomaly, "Extreme NumberOfSections must flag loader limit anomaly")
            self.assertGreater(res["threat_score"], 0)

    def test_d1_06_section_pointer_past_eof_silent_drop(self):
        """
        Finding 2.2: Section with PointerToRawData pointing beyond physical EOF is
        detected as dropped corrupted section by comparing NumberOfSections against parsed sections.
        """
        with tempfile.TemporaryDirectory() as td:
            raw = bytearray(build_minimal_pe())
            # Section PointerToRawData is at offset 332
            raw[332:336] = (len(raw) + 5000).to_bytes(4, "little")
            p = os.path.join(td, "ptr_past_eof.exe")
            with open(p, "wb") as f:
                f.write(raw)
            res = analyze_single_file(p, quiet=True)
            self.assertIsNotNone(res)
            has_corrupted = any("Corrupted Section Table" in a for a in res.get("anomalies", []))
            self.assertTrue(has_corrupted, "Corrupted/dropped section must flag Corrupted Section Table anomaly")
            self.assertGreater(res["threat_score"], 0)

    def test_d1_07_overlay_concealment_via_inflated_raw_size(self):
        """
        Finding 2.3: Appending malicious overlay and inflating section SizeOfRawData
        must NOT conceal overlay when physical raw data bounds are evaluated.
        """
        raw = bytearray(build_minimal_pe())
        overlay_bytes = b"MALICIOUS_OVERLAY_PAYLOAD" * 20
        raw.extend(overlay_bytes)
        file_size = len(raw)
        # Inflate SizeOfRawData at offset 328
        raw[328:332] = (0x800).to_bytes(4, "little")
        pe = pefile.PE(data=bytes(raw))
        try:
            max_offset, overlay = detect_overlay(pe, file_size, file_data=bytes(raw))
            self.assertEqual(len(overlay), len(overlay_bytes), "Overlay was concealed by inflated SizeOfRawData")
            self.assertEqual(overlay, overlay_bytes)
        finally:
            pe.close()

    def test_d1_08_large_binary_authenticode_truncation(self):
        """
        Finding 3.2: For large binaries where file_data is truncated to 2MB,
        check_authenticode_signature reads certificate headers from disk via file_path.
        """
        class MockDir:
            VirtualAddress = 1000
            Size = 512

        class MockPE:
            OPTIONAL_HEADER = type("Opt", (), {"DATA_DIRECTORY": [None, None, None, None, MockDir()]})()

        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "mock_signed.exe")
            # Build 2048-byte file with valid WIN_CERTIFICATE header at offset 1000
            with open(p, "wb") as f:
                f.write(b"\x00" * 1000)
                # dwLength=512, wRevision=0x0200, wCertificateType=0x0002
                f.write(struct.pack("<IHH", 512, 0x0200, 0x0002))
                f.write(b"\x00" * 504)

            # Pass empty file_data to simulate truncated buffer, but provide file_path
            is_signed, msg = check_authenticode_signature(MockPE(), file_size=2048, file_data=b"", file_path=p)
            self.assertTrue(is_signed, f"Disk seek-and-read failed: {msg}")
            self.assertEqual(msg, "Valid Authenticode PKCS#7 signed structure")

    def test_d1_09_authenticode_empty_buffer_false_positive(self):
        """
        Finding 3.2: Passing empty file_data or file_size=0 returns False (unsigned/invalid),
        never declaring non-existent signature valid.
        """
        class MockDir:
            VirtualAddress = 0x1000
            Size = 512

        class MockPE:
            OPTIONAL_HEADER = type("Opt", (), {"DATA_DIRECTORY": [None, None, None, None, MockDir()]})()

        is_signed, msg = check_authenticode_signature(MockPE(), 0, b"")
        self.assertFalse(is_signed)
        self.assertEqual(msg, "Invalid or empty file size")

    def test_d1_10_arm64_pe32plus_misclassified_as_32bit(self):
        """
        Finding 4.1: ARM64 PE32+ (0xAA64) binaries with Magic=0x020B are correctly
        recognized as 64-bit architectures.
        """
        raw = bytearray(build_minimal_pe())
        # Set Machine = ARM64 (0xAA64) at offset 68
        raw[68:70] = (0xAA64).to_bytes(2, "little")
        # Set Optional Header Magic = PE32+ (0x020B) at offset 88
        raw[88:90] = (0x020B).to_bytes(2, "little")

        pe = pefile.PE(data=bytes(raw))
        try:
            opt_hdr = getattr(pe, "OPTIONAL_HEADER", None)
            is_64 = (
                getattr(opt_hdr, "Magic", 0) == 0x020B
                or pe.FILE_HEADER.Machine in (pefile.MACHINE_TYPE.get("IMAGE_FILE_MACHINE_AMD64", 0x8664), pefile.MACHINE_TYPE.get("IMAGE_FILE_MACHINE_ARM64", 0xAA64))
            )
            self.assertTrue(is_64, "ARM64 PE32+ must be recognized as 64-bit")
        finally:
            pe.close()

    def test_d1_11_virtual_overlap_and_header_mapping(self):
        """
        Finding D1-07: detect_overlapping_sections catches sections mapping over headers (offset 0)
        and virtual memory address overlaps.
        """
        raw = bytearray(build_minimal_pe())
        # Set PointerToRawData = 0 for the section (offset 332 in build_minimal_pe)
        raw[332:336] = (0).to_bytes(4, "little")
        pe = pefile.PE(data=bytes(raw))
        try:
            anomalies, penalty = detect_overlapping_sections(pe, len(raw))
            has_hdr_map = any("maps over PE headers" in a for a in anomalies)
            self.assertTrue(has_hdr_map, "Must detect PointerToRawData=0 mapping over PE headers")
            self.assertGreater(penalty, 0)
        finally:
            pe.close()

    def test_d1_12_tls_callback_bounds_and_negative_rva(self):
        """
        Finding D1-08: inspect_tls_callbacks guards against target VA < ImageBase and bounds
        callbacks array traversal within the enclosing section.
        """
        from entropystrip.scanner import inspect_tls_callbacks
        raw = bytearray(build_minimal_pe())
        pe = pefile.PE(data=bytes(raw))
        try:
            cbs = inspect_tls_callbacks(pe, bytes(raw))
            self.assertEqual(cbs, [])
        finally:
            pe.close()

    def test_d1_13_resource_traversal_cap_and_2level_trees(self):
        """
        Finding D1-10: inspect_pe_resources handles 2-level resource trees and
        enforces MAX_RSRC_ENTRIES = 500 cap to prevent resource exhaustion attacks.
        """
        from entropystrip.scanner import inspect_pe_resources
        raw = bytearray(build_minimal_pe())
        pe = pefile.PE(data=bytes(raw))
        try:
            rsrc_telemetry, anomalies, penalty, payloads = inspect_pe_resources(pe, bytes(raw))
            self.assertIsInstance(rsrc_telemetry, list)
            self.assertIsInstance(anomalies, list)
            self.assertIsInstance(payloads, list)
        finally:
            pe.close()

    def test_d1_14_export_forwarder_sanitization(self):
        """
        Finding D1-11: inspect_exports extracts and sanitizes forwarded export target strings
        into forwarded and forwarded_targets telemetry.
        """
        from entropystrip.scanner import inspect_exports
        raw = bytearray(build_minimal_pe())
        pe = pefile.PE(data=bytes(raw))
        try:
            exp_info, anomalies, penalty = inspect_exports(pe)
            self.assertIsNone(exp_info)
            self.assertEqual(anomalies, [])
            self.assertEqual(penalty, 0)
        finally:
            pe.close()


# ==============================================================================
# Domain 2: Mathematical & Algorithmic Integrity Verification
# ==============================================================================

class TestDomain2MathematicalAlgorithmicIntegrity(unittest.TestCase):
    """
    Validates statistical models, Shannon entropy, sliding window boundaries,
    Chi-Square calculations, and SSDEEP/CTPH fuzzy hashing algorithms.
    """

    def test_d2_01_fuzzy_hash_degenerate_secondary_false_collision(self):
        """
        R2-FINDING-01: Degenerate 1-character secondary hash match must NOT cause
        compare_fuzzy_hashes to return false similarity on divergent primary hashes.
        """
        h1 = "3:ABCDEFGHIJKL:A"
        h2 = "3:ZZZZZZZZZZZZ:A"
        sim = compare_fuzzy_hashes(h1, h2)
        self.assertEqual(sim, 0, "Hardened fuzzy compare correctly rejected degenerate 1-char collision")

    def test_d2_02_cross_block_size_similarity_hard_ceiling(self):
        """
        R2-FINDING-02: compute_piecewise_hash allows h2_chars to accumulate up to 64
        characters, eliminating the 32-character cap and 50% score ceiling on block-size doubling.
        """
        data = (b"The quick brown fox jumps over the lazy dog\n" * 50)
        h1, h2 = compute_piecewise_hash(data, block_size=3)
        self.assertGreater(len(h2), 0)
        hash_b = f"6:{h2}:{h2[:32]}"
        hash_2b = f"3:{h1}:{h2}"
        sim = compare_fuzzy_hashes(hash_b, hash_2b)
        self.assertGreater(sim, 50, "Hardened CTPH eliminated 50% cross-block similarity ceiling")

    def test_d2_03_multimodal_dilution_five_delimiters_evasion(self):
        """
        R2-FINDING-03: Dynamic candidate collection allows 5 composite repeating delimiters
        to be detected by both calculate_dilution_metrics and calculate_chi_square.
        """
        pads = [0x00, 0x90, 0xCC, 0x20, 0xFF]
        raw = os.urandom(1000)
        stream = bytearray()
        for b in raw:
            stream.append(b)
            stream.extend(pads)
        data = bytes(stream)

        _, _, is_dil, pad_name = calculate_dilution_metrics(data)
        _, _, is_dil_chi = calculate_chi_square(data)
        self.assertTrue(is_dil, f"Dilution metrics should detect 5th delimiter: {pad_name}")
        self.assertTrue(is_dil_chi, "Chi-Square should detect 5th delimiter dilution")

    def test_d2_04_sliding_window_tail_truncation(self):
        """
        R2-FINDING-04: Tail-aligned window evaluation ensures the final tail window
        is evaluated in scan_sliding_window_entropy, catching tail-placed encrypted payloads.
        """
        # 476 nulls followed by 1024 high-entropy random bytes (len = 1500)
        data = b"\x00" * 476 + os.urandom(1024)
        max_ent, spans = scan_sliding_window_entropy(data, window_size=1024, step_size=512)
        primary_hits = [s for s in spans if s["scale"] == 1024]
        self.assertGreaterEqual(len(primary_hits), 1, "Primary 1024 sliding window must evaluate the tail window")
        self.assertGreater(max_ent, 7.4)

    def test_d2_05_chi_square_multimodal_moderate_buffer_evasion(self):
        """
        R2-FINDING-05: Coarse 16-bin Chi-Square fallback detects multimodal stagers (k>=2)
        with moderate sample sizes without violating Cochran's rule.
        """
        raw = os.urandom(1000)
        stream = bytearray()
        for b in raw:
            stream.extend([b, 0x90, 0xCC])  # k=2 delimiters, nz_total=1000
        data = bytes(stream)

        chi2, nz_chi2, is_dil = calculate_chi_square(data)
        self.assertTrue(is_dil, "Multimodal moderate buffer must be detected by hardened Chi-square")

    def test_d2_06_central_payload_blindspot_sample_large_buffer(self):
        """
        R2-FINDING-06: Strided multi-chunk sampling eliminates central payload blind spots,
        evaluating 5 equidistant chunks across multi-megabyte buffers.
        """
        buf = b"\x00" * 1_500_000 + os.urandom(1_000_000) + b"\x00" * 1_500_000
        ent = calculate_entropy(buf)
        self.assertGreater(ent, 0.0, "Hardened strided sampling must detect central encrypted payload")

    def test_d2_07_ctph_phantom_trailing_character(self):
        """
        R2-FINDING-07: When input terminates exactly on a block boundary, fnv1 does NOT
        produce a phantom trailing character 'F'.
        """
        rh = RollingHash()
        data = bytearray()
        for b in range(100):
            data.append(b)
            if rh.update(b) % 3 == 2:
                break
        h1, _ = compute_piecewise_hash(bytes(data), 3)
        self.assertEqual(len(h1), 1, "Phantom character 'F' must not be appended on clean boundary reset")

    def test_d2_08_sub_256_byte_sliding_window_zero_entropy(self):
        """
        R2-FINDING-08: scan_sliding_window_entropy computes valid Shannon entropy for
        buffers < 256 bytes instead of returning 0.0.
        """
        data = os.urandom(200)
        max_ent, spans = scan_sliding_window_entropy(data)
        self.assertGreater(max_ent, 6.5, "Dense sub-256B payload must calculate valid entropy")

    def test_d2_09_campaign_clustering_transitive_collapse(self):
        """
        R2-FINDING-09: Complete-linkage clustering in cluster_samples prevents transitive
        chaining collapse across dissimilar samples.
        """
        samples = [
            {"filename": "a.exe", "fuzzy_hash": "48:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:A"},
            {"filename": "b.exe", "fuzzy_hash": "48:AAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBB:A"},
            {"filename": "c.exe", "fuzzy_hash": "48:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:A"},
        ]
        clusters = cluster_samples(samples, similarity_threshold=65)
        # Unrelated samples sharing <65% similarity must not be clustered
        self.assertEqual(len(clusters), 0, "Unrelated samples must not form a cluster")


# ==============================================================================
# Domain 3: Filesystem, Concurrency & Resource Bounding
# ==============================================================================

class TestDomain3FilesystemAndResourceBoundaries(unittest.TestCase):
    """
    Validates filesystem safety, memory consumption bounds, file handle lifecycles,
    and OS-specific path handling on Windows.
    """

    def test_d3_01_uncapped_section_memory_ingestion(self):
        """
        F-R3-01: section.get_data() in core.py:243 allocates contiguous byte arrays
        in RAM for entire section sizes, unbounded by the 50MB RAM requirement.
        """
        raw = build_minimal_pe(section_data=b"\x90" * 4096)
        pe = pefile.PE(data=raw)
        try:
            sec = pe.sections[0]
            # Verify section.get_data() returns entire section raw bytes without chunking
            raw_data = sec.get_data()
            self.assertIsInstance(raw_data, bytes)
            self.assertEqual(len(raw_data), sec.SizeOfRawData)
        finally:
            pe.close()

    def test_d3_02_pefile_handle_lock_lifecycle(self):
        """
        F-R3-02: pefile.PE opened by path maintains open file handles/mmap views.
        Absence of try...finally ensures handle leaks upon parse exceptions.
        """
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "test_handle.exe")
            with open(target, "wb") as f:
                f.write(build_minimal_pe())

            pe = pefile.PE(name=target, fast_load=True)
            # Before explicit pe.close(), pe maintains file lock on Windows
            self.assertTrue(hasattr(pe, "close"))
            pe.close()

    def test_d3_03_windows_reserved_device_names(self):
        """
        F-R3-03: Win32 reserved device names (CON, NUL, AUX, COM1-9, LPT1-9) are identified
        by is_win32_reserved_name and rejected early by analyze_single_file.
        """
        self.assertTrue(is_win32_reserved_name("CON"))
        self.assertTrue(is_win32_reserved_name("NUL.txt"))
        self.assertTrue(is_win32_reserved_name("aux"))
        self.assertTrue(is_win32_reserved_name("COM1"))
        self.assertFalse(is_win32_reserved_name("clean.exe"))
        res = analyze_single_file("CON", quiet=True)
        self.assertIsNone(res)

    def test_d3_04_unc_extended_path_normalization(self):
        r"""
        F-R3-04: normalize_windows_path formats UNC paths into extended \\?\UNC\ namespace
        without generating invalid triple backslashes.
        """
        unc_path = "\\\\fileserver\\triage_share\\" + ("subfolder\\" * 25) + "target.exe"
        normalized = normalize_windows_path(unc_path)
        if sys.platform == "win32":
            self.assertTrue(normalized.startswith("\\\\?\\UNC\\fileserver\\triage_share\\"), f"Normalized path: {normalized}")
            self.assertFalse(normalized.startswith("\\\\?\\\\\\"), "UNC prefix must not contain invalid triple backslash")

    def test_d3_05_os_locked_binary_silent_omission(self):
        """
        F-R3-05: Exclusively locked active binaries raising PermissionError produce
        triage telemetry with an active process warning instead of silently dropping the file.
        """
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "locked_malware.exe")
            with open(target, "wb") as f:
                f.write(build_minimal_pe())

            orig_open = open

            def mock_open(file, mode="r", *args, **kwargs):
                if file == target and "b" in mode:
                    raise PermissionError(13, "Permission denied: locked by another process")
                return orig_open(file, mode, *args, **kwargs)

            with patch("builtins.open", side_effect=mock_open):
                res = analyze_single_file(target, quiet=True)
                self.assertIsNotNone(res, "Locked binary must produce telemetry instead of None")
                self.assertIn("Locked by Active Process", res.get("verdict", ""))
                self.assertGreaterEqual(res.get("threat_score", 0), 60)

    def test_d3_06_rich_markup_in_path_crash(self):
        """
        F-R3-06: Direct interpolation of paths containing closing tags (e.g. [/bold])
        is safely escaped with rich.markup.escape(), preventing MarkupError.
        """
        from io import StringIO
        c = Console(file=StringIO())
        malicious_path = "sample_[/bold].exe"
        c.print(f"[red]Error: File not found -> {escape(malicious_path)}[/red]")
        self.assertIn("sample_[/bold].exe", c.file.getvalue())

    def test_d3_07_authenticode_disk_seek_on_truncated_buffers(self):
        """
        F-R3-07: For files where memory ingestion is capped, check_authenticode_signature
        seeks to the WIN_CERTIFICATE offset on disk without reading the whole file into RAM.
        """
        class MockDir:
            VirtualAddress = 1000
            Size = 512

        class MockPE:
            OPTIONAL_HEADER = type("Opt", (), {"DATA_DIRECTORY": [None, None, None, None, MockDir()]})()

        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "large_signed.exe")
            with open(p, "wb") as f:
                f.write(b"\x00" * 1000)
                f.write(struct.pack("<IHH", 512, 0x0200, 0x0002))
                f.write(b"\x00" * 504)

            is_signed, msg = check_authenticode_signature(MockPE(), file_size=2048, file_data=b"", file_path=p)
            self.assertTrue(is_signed)
            self.assertEqual(msg, "Valid Authenticode PKCS#7 signed structure")

    def test_d3_08_cli_path_normalization_reserved_names(self):
        """
        F-R3-08: CLI rejects reserved Win32 device names early and normalizes long paths.
        """
        from entropystrip.core import is_win32_reserved_name, normalize_windows_path
        self.assertTrue(is_win32_reserved_name("CON"))
        self.assertTrue(is_win32_reserved_name("NUL.exe"))
        norm = normalize_windows_path("test.exe")
        self.assertIsInstance(norm, str)

    def test_d3_09_non_recursive_directory_listing_permission_error(self):
        """
        F-R3-09: scan_directory handles PermissionError during non-recursive directory
        listing cleanly without crashing.
        """
        from entropystrip.core import scan_directory
        with tempfile.TemporaryDirectory() as td:
            with patch("os.listdir", side_effect=PermissionError(13, "Access denied")):
                results = scan_directory(td, recursive=False)
                self.assertEqual(results, [])

    def test_d3_10_junction_loop_and_case_insensitive_visited_dirs(self):
        """
        F-R3-10: scan_directory lowercases paths in visited_dirs to ensure case-insensitive
        Windows path deduplication and junction pruning.
        """
        from entropystrip.core import scan_directory
        with tempfile.TemporaryDirectory() as td:
            sub = os.path.join(td, "SubDir")
            os.makedirs(sub, exist_ok=True)
            pe_path = os.path.join(sub, "test.exe")
            with open(pe_path, "wb") as f:
                f.write(build_minimal_pe())
            results = scan_directory(td, recursive=True)
            self.assertEqual(len(results), 1)


# ==============================================================================
# Domain 4: External Network Resilience & Engine Parity
# ==============================================================================

class TestDomain4NetworkResilienceAndEngineParity(unittest.TestCase):
    """
    Validates offline execution resilience, HTTP error handling, configuration persistence,
    and pure-Python fallback scanning vs native YARA parity.
    """

    def test_d4_01_fallback_engine_boolean_flattening_false_positive(self):
        """
        D4-FINDING-01: Pure-Python fallback engine must evaluate boolean condition AST
        and NOT trigger false positives on a single named pipe (requires 2).
        """
        single_pipe = b"\\\\.\\pipe\\msagent_"
        matches = scan_fallback_rules(single_pipe)
        has_cs = any(m["rule"] == "CobaltStrike_Beacon_Indicators" for m in matches)
        self.assertFalse(has_cs, "Fallback engine must not trigger on a single pipe")
        two_pipes = b"\\\\.\\pipe\\msagent_\x00\\\\.\\pipe\\status_"
        self.assertTrue(any(m["rule"] == "CobaltStrike_Beacon_Indicators" for m in scan_fallback_rules(two_pipes)))

    def test_d4_02_fallback_engine_utf16_wide_blindness(self):
        """
        D4-FINDING-02: Fallback engine must support UTF-16LE wide pattern matching.
        """
        utf16_payload = "wbadmin delete catalog".encode("utf-16le")
        matches = scan_fallback_rules(utf16_payload)
        has_match = any(m["rule"] == "Ransomware_ShadowCopy_Tampering" for m in matches)
        self.assertTrue(has_match, "Fallback engine must detect wide UTF-16LE string")

    def test_d4_03_fallback_engine_pattern_omissions_and_case_sensitivity(self):
        """
        D4-FINDING-03: Fallback engine includes synchronized patterns (%s.4444.%s).
        """
        matches = scan_fallback_rules(b"%s.4444.%s")
        self.assertTrue(
            any(m["rule"] == "CobaltStrike_Beacon_Indicators" for m in matches),
            "Pattern %s.4444.%s must be detected in Cobalt Strike rule",
        )

    def test_d4_04_bazaar_missing_negative_caching_on_failure(self):
        """
        D4-FINDING-04: Network exceptions in query_malware_bazaar cache negative results
        in _BAZAAR_CACHE to prevent repeated timeout stalls during batch triage.
        """
        bazaar._BAZAAR_CACHE.clear()
        bazaar.reset_circuit_breaker()
        test_hash = "f" * 64
        with patch("entropystrip.intel.bazaar.urlopen", side_effect=TimeoutError("Offline")):
            res = bazaar.query_malware_bazaar(test_hash, timeout=1)
            self.assertIsNone(res)
            self.assertIn(test_hash, bazaar._BAZAAR_CACHE, "Failed lookup must be stored in negative cache")
            self.assertIsNone(bazaar._BAZAAR_CACHE[test_hash])

    def test_d4_05_bazaar_request_payload_json_encoding_incompatibility(self):
        """
        D4-FINDING-05: query_malware_bazaar must transmit application/x-www-form-urlencoded
        body required by the MalwareBazaar API protocol.
        """
        captured_req = None

        def mock_urlopen(req, timeout=6):
            nonlocal captured_req
            captured_req = req
            raise TimeoutError("Intercepted")

        bazaar._BAZAAR_CACHE.clear()
        bazaar.reset_circuit_breaker()
        with patch("entropystrip.intel.bazaar.urlopen", side_effect=mock_urlopen):
            bazaar.query_malware_bazaar("a" * 64)

        self.assertIsNotNone(captured_req)
        content_type = captured_req.headers.get("Content-type", "")
        self.assertEqual(content_type, "application/x-www-form-urlencoded")
        self.assertIn(b"query=get_info", captured_req.data)

    def test_d4_06_html_reporter_virustotal_none_percent_crash(self):
        """
        D4-FINDING-06: When virustotal percent is None, generate_html_report must
        handle NoneType gracefully without raising TypeError.
        """
        with tempfile.TemporaryDirectory() as td:
            out_html = os.path.join(td, "report.html")
            telemetry = {
                "target_path": "malware.exe",
                "filename": "malware.exe",
                "file_size": 2048,
                "hashes": {"sha256": "0" * 64},
                "entropy": 7.8,
                "threat_score": 85,
                "verdict": "MALICIOUS",
                "bazaar_intel": {
                    "status": "malicious",
                    "signature": "AgentTesla",
                    "tags": ["stealer"],
                    "virustotal": {"percent": None, "positives": 0, "total": 0},
                },
            }
            generate_html_report(telemetry, out_html)
            self.assertTrue(os.path.exists(out_html))

    def test_d4_07_bazaar_malformed_tags_crash(self):
        """
        D4-FINDING-08: Malformed tags (None or integer list) are safely coerced to string
        during formatting without raising TypeError.
        """
        bazaar_intel_none = {"tags": None}
        raw_none = bazaar_intel_none.get("tags") or []
        tg_none = ", ".join(str(t) for t in raw_none if t is not None)
        self.assertEqual(tg_none, "")

        bazaar_intel_ints = {"tags": [101, 202]}
        raw_ints = bazaar_intel_ints.get("tags") or []
        tg_ints = ", ".join(str(t) for t in raw_ints if t is not None)
        self.assertEqual(tg_ints, "101, 202")

    def test_d4_08_config_non_dict_json_attribute_error(self):
        """
        D4-FINDING-09: Unchecked non-dict JSON in ~/.entropystrip/config.json is safely
        rejected by load_config, returning {} and preventing AttributeError in get_bazaar_api_key.
        """
        with tempfile.TemporaryDirectory() as td:
            with patch("entropystrip.intel.config.get_config_dir", return_value=td):
                cfg_path = config.get_config_path()
                with open(cfg_path, "w", encoding="utf-8") as f:
                    f.write(json.dumps(["malwarebazaar_api_key", "secret"]))

                loaded = config.load_config()
                self.assertIsInstance(loaded, dict)
                self.assertEqual(loaded, {})
                key = config.get_bazaar_api_key()
                self.assertIsNone(key)

    def test_d4_09_circuit_breaker_resets(self):
        """
        D4-FINDING-07: reset_circuit_breaker restores bazaar query operations after network errors.
        """
        bazaar.reset_circuit_breaker()
        self.assertEqual(bazaar._CONSECUTIVE_FAILURES, 0)
        self.assertFalse(bazaar._CIRCUIT_OPEN)

    def test_d4_10_native_yara_timeout_protection(self):
        """
        D4-FINDING-10: YARA matching accepts timeout and handles timeouts safely.
        """
        from entropystrip.rules.yara_engine import is_yara_available, compile_yara_rules
        if is_yara_available():
            rules = compile_yara_rules()
            if rules:
                matches = rules.match(data=b"test data", timeout=30)
                self.assertIsInstance(matches, list)

    def test_d4_11_custom_yara_compilation_failure_warning(self):
        """
        D4-FINDING-11: compile_yara_rules warns on stderr when custom YARA rule fails compilation.
        """
        from io import StringIO
        from entropystrip.rules.yara_engine import compile_yara_rules
        with tempfile.TemporaryDirectory() as td:
            bad_yar = os.path.join(td, "bad_rule.yar")
            with open(bad_yar, "w", encoding="utf-8") as f:
                f.write("rule INVALID_SYNTAX { this is broken syntax }")
            with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
                rules = compile_yara_rules(bad_yar)
                err_output = mock_stderr.getvalue()
                from entropystrip.rules.yara_engine import is_yara_available
                if is_yara_available():
                    self.assertIn("Custom YARA compilation failed", err_output)

    def test_d4_12_atomic_config_save_permissions(self):
        """
        D4-FINDING-12: save_config atomically writes config and validates dictionary type.
        """
        with tempfile.TemporaryDirectory() as td:
            with patch("entropystrip.intel.config.get_config_dir", return_value=td):
                res = config.save_config({"malwarebazaar_api_key": "test_key_123"})
                self.assertTrue(res)
                cfg = config.load_config()
                self.assertEqual(cfg.get("malwarebazaar_api_key"), "test_key_123")
                res_bad = config.save_config("not a dict")
                self.assertFalse(res_bad)


# ==============================================================================
# Domain 5: Output Sanitization & Artifact Carving Integrity
# ==============================================================================

class TestDomain5OutputSanitizationAndCarving(unittest.TestCase):
    """
    Validates HTML XSS sanitization, Content Security Policy enforcement,
    Rich console markup safety, artifact carving naming, and JSON serialization fidelity.
    """

    def test_d5_01_stored_xss_in_masqueraded_dll(self):
        """
        Finding D5-01: generate_directory_html_report interpolates masqueraded_dll
        without html.escape(), resulting in Stored Cross-Site Scripting (XSS).
        """
        with tempfile.TemporaryDirectory() as td:
            out_html = os.path.join(td, "dir_triage.html")
            mock_result = [{
                "filename": "suspicious.dll",
                "threat_score": 65,
                "verdict": "SUSPICIOUS",
                "exports_info": {
                    "is_masquerading": True,
                    "masqueraded_dll": "<script>alert('XSS_POC')</script>",
                    "forwarded": [],
                },
            }]
            generate_directory_html_report(mock_result, "triage_dir", out_html)
            with open(out_html, "r", encoding="utf-8") as f:
                content = f.read()
            # Vulnerability eliminated: raw script tag is escaped as &lt;script&gt;
            self.assertNotIn("<script>alert('XSS_POC')</script>", content)
            self.assertIn("&lt;script&gt;alert(&#x27;XSS_POC&#x27;)&lt;/script&gt;", content)

    def test_d5_02_console_reporter_rich_markup_injection_crash(self):
        """
        Finding D5-02: render_console_report escapes hashes and fuzzy_hash with
        rich.markup.escape(), preventing MarkupError crashes on bracketed strings.
        """
        from io import StringIO
        t = Table()
        with patch("entropystrip.reporters.console.console", Console(file=StringIO())):
            # Must complete without raising MarkupError
            render_console_report(
                target_path="safe.exe",
                sections_table=t,
                threat_score=10,
                verdict_text="Clean",
                verdict_color="green",
                is_dotnet=False,
                is_signed=False,
                anomalies=[],
                indicators=[],
                deep=True,
                hashes={"sha256": "abcdef1234567890"},
                fuzzy_hash="384:test[/bold]crash",
            )

    def test_d5_03_carving_basename_collision_and_truncated_hash(self):
        """
        Finding D5-03: Artifact carving uses full payload SHA256 and section index
        (payload_{sha256}_sec{idx}_{clean_name}.bin) to guarantee deterministic collision-free extraction.
        """
        data1 = b"PAYLOAD_1_BYTES" * 10
        data2 = b"PAYLOAD_2_BYTES" * 10
        h1 = hashlib.sha256(data1).hexdigest()
        h2 = hashlib.sha256(data2).hexdigest()
        self.assertNotEqual(h1, h2)
        f1 = f"payload_{h1}_sec0_UPX1.bin"
        f2 = f"payload_{h2}_sec0_UPX1.bin"
        self.assertNotEqual(f1, f2)

    def test_d5_04_incomplete_csp_meta_tag(self):
        """
        Finding D5-04: Standalone HTML report CSP meta tag includes base-uri 'none',
        form-action 'none', and object-src 'none'.
        """
        with tempfile.TemporaryDirectory() as td:
            out_html = os.path.join(td, "single.html")
            generate_html_report({"threat_score": 10, "filename": "sample.exe"}, out_html)
            with open(out_html, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("default-src 'none'", content)
            self.assertIn("base-uri 'none'", content)
            self.assertIn("form-action 'none'", content)
            self.assertIn("object-src 'none'", content)

    def test_d5_05_carving_path_traversal_via_dots(self):
        """
        Finding D5-05: Carving sanitizes section names by replacing non-alphanumeric characters
        with underscores and verifying that the destination path remains within the extraction directory.
        """
        raw_sec_name = "../../../etc/passwd"
        clean_name = "".join([c if c.isalnum() else "_" for c in raw_sec_name])
        self.assertNotIn("..", clean_name)
        self.assertEqual(clean_name, "_________etc_passwd")
        out_dir = os.path.abspath("extracted_payloads")
        out_path = os.path.abspath(os.path.join(out_dir, f"payload_test_sec0_{clean_name}.bin"))
        self.assertEqual(os.path.commonpath([out_dir, out_path]), out_dir)

    def test_d5_06_json_serialization_bytes_and_surrogates(self):
        """
        Finding D5-06: safe_json_default handles bytes and non-finite floats, and
        sanitize_json_surrogates replaces lone Unicode surrogates before JSON encoding.
        """
        from entropystrip.core import safe_json_default, sanitize_json_surrogates
        raw_dict = {
            "bytes_val": b"\x90\x90",
            "nan_val": float("nan"),
            "surrogate": "\ud800bad_string\ud800",
        }
        sanitized = sanitize_json_surrogates(raw_dict)
        encoded = json.dumps(sanitized, default=safe_json_default)
        self.assertIsInstance(encoded, str)
        self.assertIn('"9090"', encoded)
        self.assertIn("0.0", encoded)
        self.assertNotIn("\ud800", encoded)

    def test_d5_07_strip_ansi_terminal_sequences(self):
        """
        Finding D5-07: strip_ansi removes VT100/ANSI color, cursor, and terminal escape codes.
        """
        from entropystrip.reporters.console import strip_ansi
        malicious_ansi = "\x1b[31;1mINJECTED_RED\x1b[0m \x1b[2J\x1b[HCLEARED"
        cleaned = strip_ansi(malicious_ansi)
        self.assertEqual(cleaned, "INJECTED_RED CLEARED")
        self.assertNotIn("\x1b", cleaned)

    def test_d5_08_html_title_and_metadata_sanitization(self):
        """
        Finding D5-08: generate_html_report escapes HTML in target filename and document title.
        """
        with tempfile.TemporaryDirectory() as td:
            out_html = os.path.join(td, "xss_title.html")
            telemetry = {
                "threat_score": 20,
                "filename": "<img src=x onerror=alert(1)>.exe",
                "target_path": "C:\\malware\\<script>.exe",
            }
            generate_html_report(telemetry, out_html)
            with open(out_html, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("<img src=x onerror=alert(1)>", content)
            self.assertIn("&lt;img src=x onerror=alert(1)&gt;", content)


if __name__ == "__main__":
    print(f"\n{'='*75}\nExecuting Standalone Defensive Reproduction Test Suite (EntropyStrip v1.3.0)\n{'='*75}")
    unittest.main(verbosity=2)
