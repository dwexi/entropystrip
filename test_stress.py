import os
import struct
import shutil
import subprocess
import pefile

TEST_DIR = os.path.abspath("stress_samples")

def create_samples():
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)
    os.makedirs(TEST_DIR, exist_ok=True)

    print("[*] Generating stress test & adversarial PE samples...")

    # 1. Zero-byte file
    with open(os.path.join(TEST_DIR, "01_zero_bytes.exe"), "wb") as f:
        pass

    # 2. 16 bytes of random junk
    with open(os.path.join(TEST_DIR, "02_random_noise.exe"), "wb") as f:
        f.write(os.urandom(16))

    # 3. Truncated MZ header (only 2 bytes)
    with open(os.path.join(TEST_DIR, "03_truncated_mz.exe"), "wb") as f:
        f.write(b"MZ\x00\x00\x00")

    # 4. MZ header with e_lfanew pointing beyond EOF
    with open(os.path.join(TEST_DIR, "04_out_of_bounds_pe_offset.exe"), "wb") as f:
        buf = bytearray(64)
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 60, 0x100000) # e_lfanew = 1MB (file is only 64 bytes)
        f.write(buf)

    # 5. Non-PE file with .exe extension (Valid PNG image)
    with open(os.path.join(TEST_DIR, "05_fake_png_as_exe.exe"), "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + os.urandom(64))

    # 6. Valid base binary for mutation (copy notepad or simulated_malware)
    base_pe_path = os.path.abspath("simulated_malware.exe")
    if not os.path.exists(base_pe_path):
        base_pe_path = r"C:\Windows\System32\notepad.exe"

    with open(base_pe_path, "rb") as f:
        base_data = bytearray(f.read())

    # 7. Invalid Entry Point RVA (AddressOfEntryPoint = 0xDEADBEEF)
    try:
        pe = pefile.PE(data=base_data)
        # Find offset of AddressOfEntryPoint in OptionalHeader
        ep_offset = pe.OPTIONAL_HEADER.get_field_absolute_offset('AddressOfEntryPoint')
        corrupt_ep = bytearray(base_data)
        struct.pack_into("<I", corrupt_ep, ep_offset, 0xDEADBEEF)
        with open(os.path.join(TEST_DIR, "07_invalid_entry_point.exe"), "wb") as f:
            f.write(corrupt_ep)
    except Exception as e:
        print(f"[-] Could not generate invalid EP sample: {e}")

    # 8. Corrupted Section Count (NumberOfSections = 0xFFFF)
    try:
        pe = pefile.PE(data=base_data)
        num_sec_offset = pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections')
        corrupt_sections = bytearray(base_data)
        struct.pack_into("<H", corrupt_sections, num_sec_offset, 0xFFFF)
        with open(os.path.join(TEST_DIR, "08_overflow_section_count.exe"), "wb") as f:
            f.write(corrupt_sections)
    except Exception as e:
        print(f"[-] Could not generate corrupted section count sample: {e}")

    # 9. Huge Overlay (15MB of random bytes appended)
    with open(os.path.join(TEST_DIR, "09_massive_overlay.exe"), "wb") as f:
        f.write(base_data + os.urandom(15 * 1024 * 1024))

    # 10. Evasion: Entropy Dilution (Null-Byte Interleaving)
    # Attackers interleave encrypted shellcode with null bytes to lower overall Shannon entropy from 7.9 to 4.5
    raw_shellcode = os.urandom(4096)
    diluted = bytearray()
    for b in raw_shellcode:
        diluted.extend([b, 0x00, 0x00, 0x00]) # 1 byte payload, 3 null bytes
    with open(os.path.join(TEST_DIR, "10_entropy_dilution_payload.exe"), "wb") as f:
        f.write(base_data + diluted)

    # 11. Malformed Linux ELF with corrupted headers
    with open(os.path.join(TEST_DIR, "11_corrupted_elf.exe"), "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00" + os.urandom(32))

    # 12. Filename with complex symbols, spaces, parentheses
    special_name = "12_special_#@!_()_name.exe"
    with open(os.path.join(TEST_DIR, special_name), "wb") as f:
        f.write(base_data)

    print(f"[+] Successfully generated 12 adversarial test cases in {TEST_DIR}")

def run_tests():
    print("\n[*] Commencing Stress Test against main.py...")
    test_files = sorted(os.listdir(TEST_DIR))
    
    passed = 0
    failed = 0
    crashed = []

    for tf in test_files:
        full_path = os.path.join(TEST_DIR, tf)
        cmd = ["python", "main.py", full_path, "--deep"]
        
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        
        if proc.returncode == 0:
            print(f"  [PASS] {tf}")
            passed += 1
        else:
            print(f"  [CRASH / FAIL] {tf} (Exit code {proc.returncode})")
            print(f"     STDERR: {proc.stderr.strip()[:200]}")
            crashed.append((tf, proc.stderr.strip()))
            failed += 1

    # Also test directory scan on the entire stress folder
    print("\n[*] Testing Directory Triage on stress_samples/ folder...")
    dir_proc = subprocess.run(["python", "main.py", TEST_DIR, "-r"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    if dir_proc.returncode == 0:
        print("  [PASS] Directory scan completed without crashing.")
    else:
        print(f"  [CRASH] Directory scan crashed: {dir_proc.stderr.strip()[:200]}")
        crashed.append(("DIR_SCAN", dir_proc.stderr.strip()))

    print(f"\n[SUMMARY] Passed: {passed}/{len(test_files)}, Crashes: {failed}")
    return crashed

if __name__ == "__main__":
    create_samples()
    run_tests()
