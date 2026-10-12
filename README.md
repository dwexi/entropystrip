# entropystrip

[![PyPI version](https://img.shields.io/pypi/v/entropystrip.svg?color=blue)](https://pypi.org/project/entropystrip/)
[![Python versions](https://img.shields.io/pypi/pyversions/entropystrip.svg)](https://pypi.org/project/entropystrip/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A fast CLI tool for Windows PE triage, sliding-window entropy analysis, and detecting concealed payloads in loaders and crypters.

```text
___________       __                               _________ __         .__        
\_   _____/ _____/  |________  ____ ______ ___.__./   _____//  |________|__|_____  
 |    __)_ /    \   __\_  __ \/  _ \\____ <   |  |\_____  \\   __\_  __ \  \____ \ 
 |        \   |  \  |  |  | \(  <_> )  |_> >___  |/        \|  |  |  | \/  |  |_> >
/_______  /___|  /__|  |__|   \____/|   __// ____/_______  /|__|  |__|  |__|   __/ 
        \/     \/                   |__|   \/            \/                |__|    
```

---

## Why EntropyStrip?

Most quick-triage tools compute Shannon entropy across entire PE sections or whole files. Attackers exploit this averaging effect in modern loaders:

* **Dilution by size:** Stashing 20 KB of encrypted shellcode inside a 1 MB `.rdata` section padded with zeros keeps the section-wide entropy below 5.5.
* **Dilution by padding:** Interleaving ciphertext with NOP sleds (`0x90`) or repeating delimiters pulls the score down to benign code levels.
* **String staging:** Converting shellcode into UUID arrays (`UuidFromStringA`) or IPv4 addresses (`RtlIpv4StringToAddressA`) keeps disk entropy around 4.0 until runtime reassembly.

EntropyStrip addresses these blind spots with sub-section analysis and structural checks.

---

## Key Capabilities

* **Sliding-window inspection:** Scans sections and overlays in 1024-byte and 256-byte windows with adaptive stepping to catch concentrated payloads regardless of total section size.
* **Dilution and Chi-Square checks:** Evaluates modal byte distribution and opcode uniformity to flag padded ciphertext.
* **Memory staging detection:** Identifies `UuidFromString` and `RtlIpv4StringToAddress` staging primitives and clusters of formatted UUID strings.
* **Memory permissions:** Flags self-modifying code in sections marked both Writable and Executable (W+X).
* **Authenticode and installer verification:** Validates PE `WIN_CERTIFICATE` directory bounds and NSIS `0xdeadbeef` headers so signed software and installers are not falsely scored.
* **Rich Header inspection:** Detects stripped or invalid MSVC Rich Headers in native binaries.
* **Payload carving:** Use `--dump` to extract suspicious buffers directly to disk for Ghidra or x64dbg.
* **Directory triage:** Pass a folder path to scan directories and rank binaries on an incident triage leaderboard.

---

## Installation

Requires Python 3.8+ on Windows, Linux, or macOS.

```bash
pip install entropystrip
```

Or install from source:

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
  --html HTML    write standalone HTML report to specified path
  --json JSON    write machine-readable JSON telemetry to specified path
```

### Examples

**Analyze a single binary:**
```bash
entropystrip target.exe
```

**Deep forensic triage with MITRE ATT&CK mapping & disassembly:**
```bash
entropystrip suspicious.exe --deep
```

**Extract hidden payload buffers:**
```bash
entropystrip suspicious.exe --dump
```
Carved payloads are written to `extracted_payloads/<target>_<section>.bin`.

**Export a standalone HTML report:**
```bash
entropystrip sample.exe --html report.html
```

**Triage an entire directory of files:**
```bash
entropystrip "C:\IncidentTriage" -r
```

---

## Entropy Reference

Shannon entropy measures information density from 0.00 to 8.00 bits per byte:

| Entropy Range | Typical Content | Notes |
|---|---|---|
| `0.00 - 2.00` | Zero-padding, sparse tables | Alignment padding, uninitialized buffers |
| `2.00 - 5.50` | Standard ASCII, configurations | Application metadata, readable strings |
| `5.50 - 6.60` | Native compiled machine code | Standard x86/x64 instructions (`.text`) |
| `6.60 - 7.30` | Compressed assets | Bitmaps, icons, zlib/deflate streams |
| `7.40 - 8.00` | Cryptographic ciphertext | Encrypted payloads or packed shellcode |

---

## License

MIT License. See [LICENSE](LICENSE) for details.
