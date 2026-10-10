# entropystrip

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

Most modern malware hides behind packers (like UPX, VMProtect, or Themida) or stashes encrypted payloads in PE resource directories or trailing file overlays. Rather than relying on static byte signatures, `entropystrip` evaluates:

1. **Section Entropy:** Calculates block-level Shannon entropy across every PE section to locate encrypted or compressed buffers ($H > 7.20$).
2. **Memory Permissions:** Identifies sections marked simultaneously as Writable and Executable (`IMAGE_SCN_MEM_WRITE` and `IMAGE_SCN_MEM_EXECUTE`), which indicates self-modifying code or runtime unpackers.
3. **PE Overlays:** Measures trailing bytes appended past the end of the last mapped section.
4. **Import Table Size & Composition:** Flags binaries with unusually small IATs (e.g. only importing `LoadLibrary` / `GetProcAddress`) or sensitive process injection primitives (`VirtualAlloc`, `WriteProcessMemory`, `QueueUserAPC`).
5. **.NET Classification:** Inspects the COM descriptor directory to separate managed CLR assemblies from native binaries, avoiding false positives on standard C# applications.
6. **Payload Carving:** Extracts identified high-entropy sections or overlays straight to raw binary files on disk for further analysis.
7. **Directory Triage:** Walks directories or drives and ranks all found binaries by threat score.

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
