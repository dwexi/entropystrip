"""
Comprehensive verification test suite for EntropyStrip HTML and JSON reporting.
"""

import os
import sys
import json
import subprocess
from entropystrip.core import analyze_single_file, scan_directory

POC_DIR = "poc_tests_suite"
TMP_DIR = "test_reports_out"
os.makedirs(TMP_DIR, exist_ok=True)


def test_single_file_reporting():
    print("[*] Testing single-file HTML & JSON reporting...")
    
    # Test sample with diluted overlay
    target_diluted = os.path.join(POC_DIR, "03_bypass_nop_dilution.exe")
    json_path = os.path.join(TMP_DIR, "single_diluted.json")
    html_path = os.path.join(TMP_DIR, "single_diluted.html")
    
    if os.path.exists(json_path):
        os.remove(json_path)
    if os.path.exists(html_path):
        os.remove(html_path)
        
    res = analyze_single_file(target_diluted, html_out=html_path, json_out=json_path, quiet=True)
    assert res is not None, "analyze_single_file returned None for valid PE"
    assert os.path.exists(json_path), f"JSON report was not written to {json_path}"
    assert os.path.exists(html_path), f"HTML report was not written to {html_path}"
    
    # Verify JSON structure and status cleanliness
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    assert data["filename"] == "03_bypass_nop_dilution.exe"
    assert "sections" in data
    
    for s in data["sections"]:
        status = s["status"]
        assert "[" not in status and "]" not in status, f"Section {s['name']} has corrupted status with brackets: {status}"
        assert "red" not in status and "bold" not in status, f"Section {s['name']} has corrupted status with color names: {status}"
        if s["name"] == "[OVERLAY]":
            assert status == "DILUTED", f"Expected overlay status DILUTED, got {status}"
            
    # Verify HTML contents
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    
    assert "03_bypass_nop_dilution.exe" in html_content
    assert "DILUTED" in html_content
    assert "]DILUTED[" not in html_content, "Mangled status ]DILUTED[ leaked into HTML"
    assert "<span class=\"badge\"" in html_content
    print("    [+] Single-file diluted test passed.")

    # Test sample with concealed sliding-window spike
    target_concealed = os.path.join(POC_DIR, "05_bypass_sub_window.exe")
    json_concealed = os.path.join(TMP_DIR, "single_concealed.json")
    html_concealed = os.path.join(TMP_DIR, "single_concealed.html")
    
    res2 = analyze_single_file(target_concealed, html_out=html_concealed, json_out=json_concealed, quiet=True)
    assert res2 is not None
    with open(json_concealed, "r", encoding="utf-8") as f:
        data2 = json.load(f)
    overlay_sec = next((s for s in data2["sections"] if s["name"] == "[OVERLAY]"), None)
    assert overlay_sec is not None
    assert overlay_sec["status"] == "CONCEALED", f"Expected overlay status CONCEALED, got {overlay_sec['status']}"
    print("    [+] Single-file concealed test passed.")


def test_disassembly_sanitization():
    print("[*] Testing entry point disassembly sanitization...")
    target = "simulated_malware.exe"
    if not os.path.exists(target):
        target = os.path.join(POC_DIR, "00_baseline_clean.exe")
        
    json_path = os.path.join(TMP_DIR, "disasm_test.json")
    html_path = os.path.join(TMP_DIR, "disasm_test.html")
    
    res = analyze_single_file(target, html_out=html_path, json_out=json_path, deep=True, quiet=True)
    assert res is not None
    
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    ep_disasm = data.get("ep_disasm")
    if ep_disasm:
        assert "[dim]" not in ep_disasm and "[/dim]" not in ep_disasm, f"Terminal markup [dim] found in ep_disasm: {ep_disasm}"
        assert "[red]" not in ep_disasm and "[/red]" not in ep_disasm, f"Terminal markup [red] found in ep_disasm: {ep_disasm}"
        
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    assert "[dim]" not in html_content
    assert "[/dim]" not in html_content
    print("    [+] Disassembly sanitization passed.")


def test_directory_reporting():
    print("[*] Testing directory scan HTML & JSON reporting...")
    json_path = os.path.join(TMP_DIR, "dir_triage.json")
    html_path = os.path.join(TMP_DIR, "dir_triage.html")
    
    if os.path.exists(json_path):
        os.remove(json_path)
    if os.path.exists(html_path):
        os.remove(html_path)
        
    results = scan_directory(POC_DIR, html_out=html_path, json_out=json_path, deep=True)
    assert len(results) >= 10, f"Expected at least 10 results from {POC_DIR}, got {len(results)}"
    assert os.path.exists(json_path), f"Directory JSON report was not written to {json_path}"
    assert os.path.exists(html_path), f"Directory HTML report was not written to {html_path}"
    
    with open(json_path, "r", encoding="utf-8") as f:
        dir_data = json.load(f)
        
    assert "target_directory" in dir_data
    assert "total_scanned" in dir_data
    assert dir_data["total_scanned"] == len(results)
    assert "summary" in dir_data
    assert "results" in dir_data
    assert len(dir_data["results"]) == len(results)
    assert dir_data["summary"]["critical"] >= 0
    assert dir_data["summary"]["suspicious"] >= 1
    
    with open(html_path, "r", encoding="utf-8") as f:
        dir_html = f.read()
        
    assert "Incident Triage Leaderboard" in dir_html
    assert "Total Binaries" in dir_html
    assert "01_bypass_fake_nsis.exe" in dir_html
    assert "03_bypass_nop_dilution.exe" in dir_html
    print("    [+] Directory scan HTML & JSON reporting passed.")


def test_cli_execution():
    print("[*] Testing CLI invocation with --html and --json flags...")
    single_out_html = os.path.join(TMP_DIR, "cli_single.html")
    single_out_json = os.path.join(TMP_DIR, "cli_single.json")
    sample = os.path.join(POC_DIR, "00_baseline_clean.exe")
    
    proc = subprocess.run(
        [sys.executable, "-m", "entropystrip.cli", sample, "--html", single_out_html, "--json", single_out_json],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    assert "JSON telemetry written:" in proc.stdout, "Missing confirmation of JSON telemetry written in stdout"
    assert "HTML report generated:" in proc.stdout, "Missing confirmation of HTML report generated in stdout"
    assert os.path.exists(single_out_html)
    assert os.path.exists(single_out_json)
    print("    [+] CLI single-file execution passed.")
    
    dir_out_html = os.path.join(TMP_DIR, "cli_dir.html")
    dir_out_json = os.path.join(TMP_DIR, "cli_dir.json")
    proc_dir = subprocess.run(
        [sys.executable, "-m", "entropystrip.cli", POC_DIR, "--html", dir_out_html, "--json", dir_out_json],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    assert "JSON telemetry written:" in proc_dir.stdout, "Missing confirmation of directory JSON telemetry written in stdout"
    assert "HTML report generated:" in proc_dir.stdout, "Missing confirmation of directory HTML report generated in stdout"
    assert os.path.exists(dir_out_html)
    assert os.path.exists(dir_out_json)
    print("    [+] CLI directory execution passed.")


if __name__ == "__main__":
    print(f"\n{'='*70}\nRunning EntropyStrip Report Integrity Suite\n{'='*70}")
    test_single_file_reporting()
    test_disassembly_sanitization()
    test_directory_reporting()
    test_cli_execution()
    print(f"{'='*70}\n[+] ALL REPORTING INTEGRITY TESTS PASSED SUCCESSFULLY!\n{'='*70}\n")
