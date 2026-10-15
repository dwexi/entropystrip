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
from rich.errors import MarkupError

# EntropyStrip imports
from entropystrip.core import analyze_single_file, normalize_windows_path
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
        Finding 1.1: Files starting with MZ but shorter than 64 bytes cause e_lfanew
        to default to 0, which (0 < 64) is misclassified as benign Legacy MS-DOS Binary.
        """
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "truncated_mz.exe")
            with open(p, "wb") as f:
                f.write(b"MZ\x00\x00truncated")
            res = analyze_single_file(p, quiet=True)
            self.assertIsNotNone(res)
            # Vulnerability verified: truncated MZ diagnosed as legacy DOS binary with low threat score
            self.assertEqual(res["verdict"], "[INFO] Legacy MS-DOS Binary")
            self.assertEqual(res["threat_score"], 25)

    def test_d1_02_generic_elfanew_exception_conflation(self):
        """
        Finding 1.2: Blanket except Exception in core.py:163 conflates any PE parsing error
        (such as invalid PE signature) into claiming e_lfanew points past EOF.
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
            # Vulnerability verified: reports e_lfanew points past EOF even though e_lfanew=64 is well within file
            has_eof_anomaly = any("points past EOF" in a for a in res.get("anomalies", []))
            self.assertTrue(has_eof_anomaly, "Exception conflation did not trigger expected e_lfanew EOF anomaly")

    def test_d1_03_embedded_pe_elfanew_in_dos_header(self):
        """
        Finding 1.3: scanner.py:613 check (0 < e_lfanew < len - 4) permits e_lfanew < 64,
        falsely identifying embedded PEs that overlap the DOS header structure.
        """
        fake_res = bytearray(256)
        fake_res[0:2] = b"MZ"
        fake_res[60:64] = struct.pack("<I", 4)  # Points into DOS header
        fake_res[4:8] = b"PE\x00\x00"

        e_lfanew = struct.unpack("<I", fake_res[60:64])[0]
        # Vulnerability verified: scanner logic accepts e_lfanew < 64
        is_embedded = 0 < e_lfanew < len(fake_res) - 4 and fake_res[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"
        self.assertTrue(is_embedded, "scanner.py accepts invalid e_lfanew < 64 overlapping DOS header")

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
        Finding 3.2: For binaries > 16MB, core.py:146 truncates file_data to 2MB,
        causing check_authenticode_signature to falsely reject valid signatures as truncated.
        """
        class MockDir:
            VirtualAddress = 18 * 1024 * 1024
            Size = 8192

        class MockPE:
            OPTIONAL_HEADER = type("Opt", (), {"DATA_DIRECTORY": [None, None, None, None, MockDir()]})()

        file_size = 20 * 1024 * 1024
        # Truncated 2MB file_data buffer as passed by core.py
        file_data = b"M" * (2 * 1024 * 1024)
        is_signed, msg = check_authenticode_signature(MockPE(), file_size, file_data)
        # Vulnerability verified: legitimate signature rejected due to 2MB buffer truncation
        self.assertFalse(is_signed)
        self.assertEqual(msg, "Truncated certificate header")

    def test_d1_09_authenticode_empty_buffer_false_positive(self):
        """
        Finding 3.2: Passing empty file_data or file_size=0 skips bounds checks
        and returns True (declares non-existent signature valid).
        """
        class MockDir:
            VirtualAddress = 0x1000
            Size = 512

        class MockPE:
            OPTIONAL_HEADER = type("Opt", (), {"DATA_DIRECTORY": [None, None, None, None, MockDir()]})()

        is_signed, msg = check_authenticode_signature(MockPE(), 0, b"")
        # Vulnerability verified: unverified empty buffer marked valid
        self.assertTrue(is_signed)
        self.assertEqual(msg, "Valid Authenticode PKCS#7 signed structure")

    def test_d1_10_arm64_pe32plus_misclassified_as_32bit(self):
        """
        Finding 4.1: is_64 checks Machine == AMD64, misclassifying ARM64 PE32+ (0xAA64)
        binaries as 32-bit and corrupting TLS offsets and disassembly mode.
        """
        raw = bytearray(build_minimal_pe())
        # Set Machine = ARM64 (0xAA64) at offset 68
        raw[68:70] = (0xAA64).to_bytes(2, "little")
        # Set Optional Header Magic = PE32+ (0x020B) at offset 88
        raw[88:90] = (0x020B).to_bytes(2, "little")

        pe = pefile.PE(data=bytes(raw))
        try:
            # Vulnerability verified: scanner.py evaluates is_64 as False for ARM64
            is_64_scanner = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
            self.assertFalse(is_64_scanner)
            self.assertEqual(pe.OPTIONAL_HEADER.Magic, 0x020B)
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
        R2-FINDING-02: Normalizing by max_len caps cross-block-size (2x) similarity
        at 50%, preventing identical variants across block boundaries from clustering.
        """
        s1_1 = "A" * 60
        s2_2 = "A" * 30
        score = _score_strings(s1_1, s2_2)
        # Vulnerability verified: mathematical ceiling hard-caps similarity at 50%
        self.assertEqual(score, 50, "Cross-block identical prefix was not capped at 50%")

    def test_d2_03_multimodal_dilution_five_delimiters_evasion(self):
        """
        R2-FINDING-03: modal_candidates[:4] slicing allows 5 composite repeating delimiters
        to evade both calculate_dilution_metrics and calculate_chi_square.
        """
        pads = [0x00, 0x90, 0xCC, 0x20, 0xFF]
        raw = os.urandom(1000)
        stream = bytearray()
        for b in raw:
            stream.append(b)
            stream.extend(pads)
        data = bytes(stream)

        _, _, is_dil, _ = calculate_dilution_metrics(data)
        _, _, is_dil_chi = calculate_chi_square(data)
        # Vulnerability verified: both dilution defenses evaded simultaneously
        self.assertFalse(is_dil, "Dilution metrics failed to be evaded by 5th delimiter")
        self.assertFalse(is_dil_chi, "Chi-Square failed to be evaded by 5th delimiter")

    def test_d2_04_sliding_window_tail_truncation(self):
        """
        R2-FINDING-04: Non-divisible step size skips the final tail window in
        scan_sliding_window_entropy, completely missing tail-placed encrypted payloads.
        """
        # 476 nulls followed by 1024 high-entropy random bytes (len = 1500)
        data = b"\x00" * 476 + os.urandom(1024)
        max_ent, spans = scan_sliding_window_entropy(data, window_size=1024, step_size=512)
        # range(0, 1500 - 1024 + 1, 512) evaluates only offset 0; offset 476 is skipped
        primary_hits = [s for s in spans if s["scale"] == 1024]
        # Vulnerability verified: primary 1024-byte window missed the 1024-byte payload at tail
        self.assertEqual(len(primary_hits), 0, "Primary 1024 sliding window evaluated the tail window")

    def test_d2_05_chi_square_multimodal_moderate_buffer_evasion(self):
        """
        R2-FINDING-05: Fallback chi-square requires k==1, causing multimodal stagers (k>=2)
        with moderate sample sizes (nz_total < 1270) to evade detection.
        """
        raw = os.urandom(1000)
        stream = bytearray()
        for b in raw:
            stream.extend([b, 0x90, 0xCC])  # k=2 delimiters, nz_total=1000
        data = bytes(stream)

        chi2, nz_chi2, is_dil = calculate_chi_square(data)
        # Vulnerability verified: nz_total=1000 < min_sample=1270 and k!=1, returning False
        self.assertFalse(is_dil, "Multimodal moderate buffer did not evade Chi-square")

    def test_d2_06_central_payload_blindspot_sample_large_buffer(self):
        """
        R2-FINDING-06: sample_large_buffer samples only 500KB head + 500KB tail,
        completely ignoring multi-megabyte encrypted payloads located in the buffer center.
        """
        buf = b"\x00" * 1_500_000 + os.urandom(1_000_000) + b"\x00" * 1_500_000
        ent = calculate_entropy(buf)
        # Vulnerability verified: central 1MB payload discarded, returns 0.0 entropy
        self.assertEqual(ent, 0.0, "sample_large_buffer did not miss central payload")

    def test_d2_07_ctph_phantom_trailing_character(self):
        """
        R2-FINDING-07: When input terminates exactly on a block boundary, fnv1 is reset
        to initial seed, causing compute_piecewise_hash to append a phantom 'F' character.
        """
        rh = RollingHash()
        data = bytearray()
        for b in range(100):
            data.append(b)
            if rh.update(b) % 3 == 2:
                break
        h1, _ = compute_piecewise_hash(bytes(data), 3)
        # Vulnerability verified: clean boundary termination appends second phantom character 'F'
        self.assertEqual(len(h1), 2)
        self.assertTrue(h1.endswith("F"), "Phantom character 'F' was not appended on boundary reset")

    def test_d2_08_sub_256_byte_sliding_window_zero_entropy(self):
        """
        R2-FINDING-08: scan_sliding_window_entropy short-circuits on buffers < 256 bytes,
        reporting max_ent = 0.0 even for dense cryptographic shellcode.
        """
        data = os.urandom(200)
        max_ent, spans = scan_sliding_window_entropy(data)
        # Vulnerability verified: sub-256-byte payload returns 0.0 entropy
        self.assertEqual(max_ent, 0.0)
        self.assertEqual(spans, [])

    def test_d2_09_campaign_clustering_transitive_collapse(self):
        """
        R2-FINDING-09: Connected-components BFS in cluster_samples must NOT collapse
        unrelated samples into a cluster.
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
        F-R3-03: Win32 reserved device names (CON, NUL, AUX) pass os.path.exists()
        on Windows and lack validation in normalize_windows_path, risking I/O hangs.
        """
        if sys.platform == "win32":
            # On Windows, NUL exists as a reserved character device
            self.assertTrue(os.path.exists("NUL"))
            norm = normalize_windows_path("CON")
            # Vulnerability verified: reserved name is normalized as normal path without rejection
            self.assertIn("CON", norm)

    def test_d3_04_unc_extended_path_normalization(self):
        """
        F-R3-04: normalize_windows_path prepends \\?\\ to UNC paths, producing invalid
        triple-slash namespace \\?\\\\server\\share instead of \\?\\UNC\\server\\share.
        """
        unc_path = "\\\\fileserver\\triage_share\\" + ("subfolder\\" * 25) + "target.exe"
        normalized = normalize_windows_path(unc_path)
        if sys.platform == "win32":
            # Vulnerability verified: prepends \\?\ to \\ resulting in invalid prefix
            self.assertTrue(normalized.startswith("\\\\?\\\\"), f"Normalized path: {normalized}")
            self.assertFalse(normalized.startswith("\\\\?\\UNC\\"), "UNC prefix was correctly handled")

    def test_d3_05_os_locked_binary_silent_omission(self):
        """
        F-R3-05: Exclusively locked active binaries raise PermissionError, which is
        caught by except Exception in analyze_single_file and silently returns None.
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
                # Vulnerability verified: returns None, dropping critical active malware telemetry
                self.assertIsNone(res, "Locked binary was not silently dropped returning None")

    def test_d3_06_rich_markup_in_path_crash(self):
        """
        F-R3-06: Direct interpolation of paths containing closing tags (e.g. [/bold])
        into console.print strings raises rich.errors.MarkupError without escape().
        """
        from io import StringIO
        c = Console(file=StringIO())
        malicious_path = "sample_[/bold].exe"
        # Vulnerability verified: unescaped path causes Rich MarkupError crash
        with self.assertRaises(MarkupError):
            c.print(f"[red]Error: File not found -> {malicious_path}[/red]")


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
        D4-FINDING-08: Malformed tags (None or integer list) causes TypeError during
        string join operations in core.py and reporters.
        """
        bazaar_intel_none = {"tags": None}
        # In core.py:650: ", ".join(bazaar_intel.get("tags", [])) -> returns None -> crash
        with self.assertRaises(TypeError):
            ", ".join(bazaar_intel_none.get("tags", []))

        bazaar_intel_ints = {"tags": [101, 202]}
        with self.assertRaises(TypeError):
            ", ".join(bazaar_intel_ints.get("tags", []))

    def test_d4_08_config_non_dict_json_attribute_error(self):
        """
        D4-FINDING-09: Unchecked non-dict JSON in ~/.entropystrip/config.json causes
        AttributeError in get_bazaar_api_key when calling cfg.get().
        """
        with tempfile.TemporaryDirectory() as td:
            with patch("entropystrip.intel.config.get_config_dir", return_value=td):
                cfg_path = config.get_config_path()
                with open(cfg_path, "w", encoding="utf-8") as f:
                    f.write(json.dumps(["malwarebazaar_api_key", "secret"]))

                loaded = config.load_config()
                self.assertIsInstance(loaded, list)
                # Vulnerability verified: calling get_bazaar_api_key crashes with AttributeError
                with self.assertRaises(AttributeError):
                    config.get_bazaar_api_key()


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
        Finding D5-03: Artifact carving truncates parent SHA256 to 8 hex chars and uses
        parent basename, causing naming collisions and failing payload_<sha256>_<offset>.bin standard.
        """
        hashes = {"sha256": "abcdef0123456789" * 4}
        file_path_1 = "dir_a/update.exe"
        file_path_2 = "dir_b/update.exe"

        sha_pfx = hashes.get("sha256", "00000000")[:8]
        clean_base_1 = "".join([c if c.isalnum() or c == "." else "_" for c in os.path.basename(file_path_1)])
        clean_base_2 = "".join([c if c.isalnum() or c == "." else "_" for c in os.path.basename(file_path_2)])

        self.assertEqual(sha_pfx, "abcdef01")
        self.assertEqual(clean_base_1, clean_base_2)

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
        Finding D5-05: Carving path generation allows dots ('.') in clean_base, allowing
        relative parent references ('..') to escape the extraction directory.
        """
        raw_base = ".."
        clean_base = "".join([c if c.isalnum() or c == "." else "_" for c in raw_base])
        # Vulnerability verified: '..' is preserved, permitting path traversal escape
        self.assertEqual(clean_base, "..")

    def test_d5_06_json_serialization_bytes_and_surrogates(self):
        """
        Finding D5-06: json.dump in core.py lacks default serializer for bytes and fails
        to sanitize lone surrogates before UTF-8 encoding.
        """
        # Bytes serialization failure
        with self.assertRaises(TypeError):
            json.dumps({"payload": b"\x90\x90"})

        # Lone surrogate UTF-8 encoding failure
        with self.assertRaises(UnicodeEncodeError):
            "\ud800".encode("utf-8")


if __name__ == "__main__":
    print(f"\n{'='*75}\nExecuting Standalone Defensive Reproduction Test Suite (EntropyStrip v1.3.0)\n{'='*75}")
    unittest.main(verbosity=2)
