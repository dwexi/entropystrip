# entropystrip

[![PyPI version](https://img.shields.io/pypi/v/entropystrip.svg?color=blue)](https://pypi.org/project/entropystrip/)
[![Python versions](https://img.shields.io/pypi/pyversions/entropystrip.svg)](https://pypi.org/project/entropystrip/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

```text
___________       __                               _________ __         .__        
\_   _____/ _____/  |________  ____ ______ ___.__./   _____//  |________|__|_____  
 |    __)_ /    \   __\_  __ \/  _ \\____ <   |  |\_____  \\   __\_  __ \  \____ \ 
 |        \   |  \  |  |  | \(  <_> )  |_> >___  |/        \|  |  |  | \/  |  |_> >
/_______  /___|  /__|  |__|   \____/|   __// ____/_______  /|__|  |__|  |__|   __/ 
        \/     \/                   |__|   \/            \/                |__|    
```


---

## What it does

Most modern malware hides behind packers, obfuscated loaders, or encrypted stagers designed to slip past naive whole-file entropy scanners. Rather than relying on static byte signatures, `entropystrip` evaluates:

1. **Sliding-Window Sub-Section Radar:** Dual-resolution (1024-byte and 256-byte) sliding windows detect concentrated cryptographic payloads hidden inside large low-entropy sections or overlays.
2. **Generalized Dilution Defense & Chi-Square ($\chi^2$):** Defeats padding evasions (interleaved nulls, NOP sleds) by analyzing modal byte distributions and statistical uniformity.
3. **String-Based Staging Primitives:** Flags memory-staging primitives (`UuidFromString`, `RtlIpv4StringToAddress`) and detects formatted UUID shellcode clusters.
4. **Memory Permissions (W+X):** Identifies sections marked simultaneously as Writable and Executable (`IMAGE_SCN_MEM_WRITE` and `IMAGE_SCN_MEM_EXECUTE`).
5. **Overlay & Certificate Radar:** Measures unmapped trailing bytes and structurally validates `WIN_CERTIFICATE` Authenticode tables to distinguish true certificates from droppers.
6. **MITRE ATT&CK Mapping:** Automatically correlates findings to adversary technique IDs (`T1027`, `T1027.001`, `T1027.002`, `T1055`, `T1497`, `T1129`).
7. **Installer Whitelisting:** Validates structural NSIS (`0xdeadbeef`) and setup headers to eliminate false positives on legitimate software.
8. **Automated Payload Carving:** `--dump` extracts suspicious sections and overlays straight to disk for offline deobfuscation.
9. **Directory Incident Triage:** Walks directories and ranks all binaries on an incident triage leaderboard.

---

## Installation

Requirements: Python 3.8+ on Windows, Linux, or macOS.

```bash
pip install entropystrip
```

Or install directly from source:

```bash
git clone https://github.com/dwexi/entropystrip.git
cd entropystrip
pip install -e .
```

---

## Usage

```text
usage: entropystrip [-h] [-r] [--dump] [--deep] [--html HTML] [--json JSON] target

EntropyStrip: PE De-obfuscator & Triage Engine

positional arguments:
  target         Path to Windows executable (.exe / .dll) or directory to scan

options:
  -h, --help     show this help message and exit
  -r, --recursive
                 recursively scan subdirectories if target is a folder
  --dump         carve and write high-entropy payloads to extracted_payloads/
  --deep         deep forensic triage: MITRE ATT&CK mapping, entry point disassembly, hashes
  --html HTML    write minimalist HTML report to specified path
  --json JSON    write machine-readable JSON telemetry to specified path
```

### Examples

**Analyze a single binary:**
```bash
python main.py target.exe
```

**Deep forensic triage with MITRE ATT&CK mapping & disassembly:**
```bash
python main.py suspicious.exe --deep
```

**Analyze and extract hidden payload buffers:**
```bash
python main.py suspicious.exe --dump
```
Carved payloads are written to `extracted_payloads/<target>_<section>.bin`.

**Export a standalone HTML report:**
```bash
python main.py sample.exe --html report.html
```

**Triage an entire directory of unknown files:**
```bash
python main.py "C:\IncidentTriage" -r
```

---

## Entropy Scale Reference

Shannon entropy measures information density from 0.00 to 8.00 bits per byte:

$$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$

| Entropy Range | Expected Content | Notes |
|---|---|---|
| `0.00 - 2.00` | Zero-padding, sparse tables | Common in uninitialized data or alignment padding |
| `2.00 - 5.50` | Standard ASCII, configurations | Normal application metadata, strings |
| `5.50 - 6.60` | Native compiled machine code | Standard x86/x64 instructions (`.text`) |
| `6.60 - 7.30` | Compressed assets | Bitmaps, icons, zlib/deflate streams |
| `7.40 - 8.00` | Cryptographic ciphertext | AES/RC4 encrypted payloads or tightly packed shellcode |

---

## License

MIT License. See [LICENSE](LICENSE) for details.
