"""
Comprehensive unit and integration test suite for EntropyStrip advanced triage features:
- Pure-Python Fuzzy Hashing (SSDEEP/CTPH) & Campaign Clustering
- YARA Rule Engine (Fallback & Native compilation)
- PE Resource (.rsrc) Tree Deep Traversal & Steganography Detection
- Export Address Table (EAT) & DLL Side-Loading / Masquerading Triage
- MalwareBazaar Threat Intelligence Client & Offline Defaults
- Core Telemetry & Reporter Schema Integration
"""

import os
import sys
import json
import struct
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import pefile

from entropystrip.radar.fuzzy import (
    compute_fuzzy_hash,
    compare_fuzzy_hashes,
    cluster_samples,
)
from entropystrip.rules.yara_engine import (
    scan_yara,
    scan_fallback_rules,
    is_yara_available,
    FALLBACK_RULES,
)
from entropystrip.scanner import (
    inspect_pe_resources,
    inspect_exports,
    KNOWN_HIJACKABLE_SYSTEM_DLLS,
)
from entropystrip.intel.config import (
    get_bazaar_api_key,
    set_bazaar_api_key,
    load_config,
    save_config,
)
from entropystrip.intel.bazaar import query_malware_bazaar
from entropystrip.core import analyze_single_file, scan_directory
from entropystrip.models import TriageDiagnostic


class TestFuzzyHashingAndClustering(unittest.TestCase):
    """Verifies pure-Python CTPH/SSDEEP rolling hash and campaign clustering."""

    def test_fuzzy_hash_structure(self):
        data = b"EntropyStrip Pure-Python SSDEEP implementation testing string repeated. " * 50
        h = compute_fuzzy_hash(data)
        self.assertIsInstance(h, str)
        parts = h.split(":")
        self.assertEqual(len(parts), 3, "SSDEEP hash must follow <block_size>:<h1 trick>:<h2 trick>")
        self.assertTrue(parts[0].isdigit(), "Block size must be numeric")
        self.assertGreater(len(parts[1]), 0)

    def test_fuzzy_hash_identical_buffers(self):
        data = b"A" * 2048 + b"B" * 2048 + b"C" * 2048
        h1 = compute_fuzzy_hash(data)
        h2 = compute_fuzzy_hash(data)
        self.assertEqual(h1, h2)
        score = compare_fuzzy_hashes(h1, h2)
        self.assertEqual(score, 100)

    def test_fuzzy_hash_similar_buffers(self):
        base = (b"Standard malware payload loader body chunk with lots of instructions. " * 30)
        sample1 = base + b"MUTATION_VARIANT_ALPHA_12345" + (b"\x90" * 200)
        sample2 = base + b"MUTATION_VARIANT_BRAVO_67890" + (b"\x90" * 200)

        h1 = compute_fuzzy_hash(sample1)
        h2 = compute_fuzzy_hash(sample2)
        sim = compare_fuzzy_hashes(h1, h2)
        self.assertGreater(sim, 65, f"Expected high similarity for minor mutation, got {sim}")

    def test_fuzzy_hash_divergent_buffers(self):
        data1 = b"\x00\x01\x02\x03\x04\x05\x06\x07" * 200
        data2 = b"Completely different ASCII prose text with no binary similarity whatsoever." * 50
        h1 = compute_fuzzy_hash(data1)
        h2 = compute_fuzzy_hash(data2)
        sim = compare_fuzzy_hashes(h1, h2)
        self.assertLess(sim, 30, f"Expected low similarity for divergent data, got {sim}")

    def test_campaign_clustering(self):
        base_a = (b"CobaltStrike beacon payload framework standard loop. " * 40)
        base_b = (b"Legitimate clean utility compiler runtime boilerplate code. " * 40)

        sample_a1 = {"filename": "beacon1.exe", "fuzzy_hash": compute_fuzzy_hash(base_a + b"_var1")}
        sample_a2 = {"filename": "beacon2.exe", "fuzzy_hash": compute_fuzzy_hash(base_a + b"_var2")}
        sample_a3 = {"filename": "beacon3.exe", "fuzzy_hash": compute_fuzzy_hash(base_a + b"_var3")}
        sample_b1 = {"filename": "clean1.exe", "fuzzy_hash": compute_fuzzy_hash(base_b + b"_v1")}
        sample_b2 = {"filename": "clean2.exe", "fuzzy_hash": compute_fuzzy_hash(base_b + b"_v2")}

        samples = [sample_a1, sample_a2, sample_a3, sample_b1, sample_b2]
        clusters = cluster_samples(samples, similarity_threshold=70)

        self.assertGreaterEqual(len(clusters), 2, "Expected at least 2 distinct campaign clusters")
        # Ensure sample_a1, sample_a2, sample_a3 share a cluster
        self.assertIn("cluster_id", sample_a1)
        self.assertEqual(sample_a1["cluster_id"], sample_a2["cluster_id"])
        self.assertEqual(sample_a1["cluster_id"], sample_a3["cluster_id"])
        # Ensure sample_b1 and sample_b2 share a different cluster
        self.assertEqual(sample_b1["cluster_id"], sample_b2["cluster_id"])
        self.assertNotEqual(sample_a1["cluster_id"], sample_b1["cluster_id"])


class TestYaraEngine(unittest.TestCase):
    """Verifies YARA rule compilation, default rules, and pure-Python fallback execution."""

    def test_fallback_engine_cobalt_strike(self):
        payload = b"\x90\x90\x90\\\\.\\pipe\\msagent_5f3a\x00\x00\x90\x90"
        matches = scan_fallback_rules(payload)
        self.assertTrue(any(m["rule"] == "CobaltStrike_Beacon_Indicators" for m in matches))
        match = next(m for m in matches if m["rule"] == "CobaltStrike_Beacon_Indicators")
        self.assertEqual(match["severity"], "critical")
        self.assertEqual(match["mitre"], "T1071.001")
        self.assertGreaterEqual(match["threat_score"], 45)

    def test_fallback_engine_ransomware_shadow_tampering(self):
        payload = b"cmd.exe /c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} recoveryenabled No"
        matches = scan_fallback_rules(payload)
        self.assertTrue(any(m["rule"] == "Ransomware_ShadowCopy_Tampering" for m in matches))

    def test_fallback_engine_reflective_loader(self):
        payload = b"Module export table header: ReflectiveLoader found in memory buffer"
        matches = scan_fallback_rules(payload)
        self.assertTrue(any(m["rule"] == "Reflective_DLL_Injection_Signature" for m in matches))

    def test_scan_yara_facade(self):
        data = b"Testing shellcode egg hunter: \x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e"
        matches = scan_yara(data)
        self.assertTrue(len(matches) > 0)
        self.assertTrue(any("EggHunter" in m["rule"] for m in matches))


class TestPEInspectionEngines(unittest.TestCase):
    """Verifies PE Resource Tree (.rsrc) and Export Address Table (EAT) triage."""

    def setUp(self):
        self.simulated_exe = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "simulated_malware.exe",
        )

    def test_inspect_exports_clean(self):
        if not os.path.isfile(self.simulated_exe):
            self.skipTest("simulated_malware.exe not present in workspace")

        pe = pefile.PE(self.simulated_exe)
        exp_info, anomalies, penalty = inspect_exports(pe, self.simulated_exe)
        # simulated_malware is an EXE with typically 0 exports
        if exp_info is not None:
            self.assertIsInstance(exp_info["total_exports"], int)
            self.assertIsInstance(exp_info["forwarded_count"], int)
        pe.close()

    def test_inspect_exports_system_dll_masquerade(self):
        if not os.path.isfile(self.simulated_exe):
            self.skipTest("simulated_malware.exe not present in workspace")

        pe = pefile.PE(self.simulated_exe)
        # Test simulating a DLL named version.dll placed outside System32
        fake_path = r"C:\Users\Target\Downloads\version.dll"
        exp_mock = MagicMock()
        exp_mock.name = b"version.dll"
        exp_mock.symbols = []
        pe.DIRECTORY_ENTRY_EXPORT = exp_mock

        exp_info, anomalies, penalty = inspect_exports(pe, fake_path)
        self.assertIsNotNone(exp_info)
        self.assertTrue(exp_info["is_system_dll_name"])
        self.assertTrue(any("DLL Side-Loading" in a for a in anomalies))
        self.assertGreaterEqual(penalty, 35)
        pe.close()

    def test_inspect_pe_resources_detection(self):
        if not os.path.isfile(self.simulated_exe):
            self.skipTest("simulated_malware.exe not present in workspace")

        with open(self.simulated_exe, "rb") as f:
            data = f.read()
        pe = pefile.PE(data=data)

        rsrcs, anomalies, penalty, carveables = inspect_pe_resources(pe, data)
        self.assertIsInstance(rsrcs, list)
        self.assertIsInstance(anomalies, list)
        self.assertIsInstance(penalty, int)
        self.assertIsInstance(carveables, list)
        pe.close()


class TestMalwareBazaarClient(unittest.TestCase):
    """Verifies MalwareBazaar API lookup, credentials resolution, and forensic safety."""

    def test_api_key_resolution_hierarchy(self):
        # 1. Explicit key
        self.assertEqual(get_bazaar_api_key("explicit_test_key"), "explicit_test_key")

        # 2. Environment variable
        with patch.dict(os.environ, {"MALWAREBAZAAR_API_KEY": "env_test_key"}):
            self.assertEqual(get_bazaar_api_key(None), "env_test_key")

    def test_malware_bazaar_mock_hit(self):
        fake_response = {
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "signature": "RedLineStealer",
                    "file_type": "exe",
                    "file_type_mime": "application/x-dosexec",
                    "tags": ["stealer", "redline", "malware"],
                    "reporter": "abuse_ch",
                    "first_seen": "2026-01-01 12:00:00",
                    "last_seen": "2026-02-01 12:00:00",
                    "delivery_method": "phishing",
                    "intelligence": {
                        "virustotal": {
                            "percent": 88.5,
                            "positives": 54,
                            "total": 61,
                        }
                    },
                }
            ],
        }

        with patch("entropystrip.intel.bazaar.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(fake_response).encode("utf-8")
            mock_urlopen.return_value.__enter__.return_value = mock_resp

            result = query_malware_bazaar("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            self.assertIsNotNone(result)
            self.assertEqual(result["status"], "malicious")
            self.assertEqual(result["signature"], "RedLineStealer")
            self.assertIn("redline", result["tags"])
            self.assertEqual(result["virustotal"]["positives"], 54)

    def test_malware_bazaar_graceful_timeout_handling(self):
        with patch("entropystrip.intel.bazaar.urlopen", side_effect=TimeoutError("Request timed out")):
            result = query_malware_bazaar("1111111111111111111111111111111111111111111111111111111111111111")
            self.assertIsNone(result, "Network failure must fail gracefully to None without throwing exceptions")


class TestCoreIntegration(unittest.TestCase):
    """Verifies end-to-end telemetry generation and CLI arguments."""

    def setUp(self):
        self.simulated_exe = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "simulated_malware.exe",
        )

    def test_analyze_single_file_with_advanced_features(self):
        if not os.path.isfile(self.simulated_exe):
            self.skipTest("simulated_malware.exe not present in workspace")

        with tempfile.TemporaryDirectory() as tmpdir:
            json_out = os.path.join(tmpdir, "out.json")
            html_out = os.path.join(tmpdir, "out.html")

            telemetry = analyze_single_file(
                self.simulated_exe,
                quiet=True,
                json_out=json_out,
                html_out=html_out,
                deep=True,
                enable_yara=True,
                enable_bazaar=False,
            )

            self.assertIsNotNone(telemetry)
            self.assertIn("fuzzy_hash", telemetry)
            self.assertIn("yara_matches", telemetry)
            self.assertIn("resources_info", telemetry)
            self.assertIn("exports_info", telemetry)
            self.assertTrue(os.path.isfile(json_out))
            self.assertTrue(os.path.isfile(html_out))

            with open(json_out, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("fuzzy_hash", data)
            self.assertIn("threat_score", data)

            with open(html_out, "r", encoding="utf-8") as f:
                html_content = f.read()
            self.assertIn("EntropyStrip", html_content)


if __name__ == "__main__":
    unittest.main()
