# Changelog

All notable changes to EntropyStrip are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.3.0] - 2026-10-15

### Added
- **Pure-Python SSDEEP / CTPH Fuzzy Hashing**:
  - Implemented rolling Context-Triggered Piecewise Hashing with 64-character base64 representations in `entropystrip.radar.fuzzy`.
  - Added Levenshtein distance string similarity comparator ($0–100\%$).
  - Implemented automated campaign clustering ($\ge 70\%$ similarity threshold) to group related binary variants and threat campaigns.
- **YARA Signature Scanning Engine**:
  - Added native `yara-python` integration with bundled detection rules in `entropystrip/rules/defaults/threats.yar`.
  - Default rules target Cobalt Strike Beacons, Ransomware volume shadow copy deletion (`vssadmin`, `wmic`, `bcdedit`), suspicious PowerShell download cradles, Reflective DLL Loaders, and EggHunter shellcode stubs.
  - Added pure-Python fallback scanning engine for zero-dependency environments without native C-extensions.
  - Added `--yara [RULE_PATH]` CLI argument supporting bundled rules or custom user rule files.
- **PE Resource Tree (.rsrc) Steganography & Payload Carving**:
  - Recursive traversal across resource directory levels (`Type -> Name -> Lang`) in `entropystrip.scanner`.
  - Detection of hidden PE/MZ steganography inside resource payloads (`RT_RCDATA`, `RT_ICON`, etc.).
  - Shannon entropy scoring per resource entry to flag encrypted and obfuscated payloads.
- **Export Address Table (EAT) Forwarding & DLL Proxying Analysis**:
  - Detection of forwarded exports pointing to external DLL targets in `entropystrip.scanner`.
  - Detection of system DLL masquerading (`version.dll`, `dbghelp.dll`, `userenv.dll`, etc.) for DLL hijacking, proxying, and sideloading risk analysis.
- **MalwareBazaar (abuse.ch) Threat Intelligence Integration**:
  - Added REST API threat intelligence client in `entropystrip.intel.bazaar`.
  - Automated hash lookup for malware family classification, community tags, first-seen timestamps, and VirusTotal detection ratios.
  - Built-in in-memory caching (`_BAZAAR_CACHE`) to eliminate redundant queries during batch directory scans.
  - Added 3-tier key resolution: CLI argument `--bazaar-key <KEY>`, saved configuration (`~/.entropystrip/config.json`), and environment variable `MALWAREBAZAAR_API_KEY`.
  - Added `--set-bazaar-key <KEY>` CLI helper for persistent configuration.
- **Enhanced Directory Triage & Interactive HTML Reports**:
  - Added rich interactive Leaderboard in console and standalone HTML dashboard (`generate_directory_html_report`).
  - Added top metric summary cards (Total Binaries, Critical Risk, Suspicious, Clean, YARA Detections, Threat Intel Hits).
  - Added Automated Campaign Clusters box displaying grouped binaries.
  - Added per-binary diagnostic detail cards containing full SHA-256, SSDEEP fuzzy hash, YARA detection tables, MalwareBazaar intel cards, Resource anomaly tables, and Export forwarding tables.
  - Added explicit startup engine indicators and completion audit telemetry.
- **Architectural Resilience & Boundary Hardening (51-Finding Audit Remediation)**:
  - **PE Structural Parser Boundaries**: Guarded against truncated DOS headers (<64B), enforced section table bounds ($1 \le NumberOfSections \le 96$), detected dropped sections past EOF, computed overlays against physical section bounds to defeat inflated `SizeOfRawData` evasion, detected virtual memory overlaps and offset-0 header mapping, clamped TLS callback traversal within section bounds, supported ARM64 PE32+ via Optional Header Magic, and capped resource directory traversal to 500 entries with 2-level tree support.
  - **Mathematical Radar & Heuristics**: Prevented degenerate 1-character fuzzy hash collisions ($\ge 4$ char guard), uncapped cross-block-size piecewise hashing ceiling, expanded multimodal dilution to dynamic delimiter sets, added Cochran's rule compliant 16-bin coarse Chi-Square fallback, added tail-aligned sliding window remainder evaluation, implemented strided 5-chunk sampling across large buffers to eliminate central payload blind spots, and implemented complete-linkage campaign clustering.
  - **Filesystem & Concurrency Boundaries**: Guaranteed scoped file handle release via `pe.close()` context cleanup, enforced $<50\text{ MB}$ RAM budget via 2MB section caps, added early rejection of Win32 reserved device names (`CON`, `PRN`, `AUX`, `NUL`, etc.), normalized long UNC paths (`\\?\UNC\server\share`), recorded forensic telemetry for OS-locked binaries (`PermissionError`), guarded non-recursive directory queries, and prevented infinite directory traversal loops across NTFS junctions.
  - **External Network & Rule Engine Parity**: Switched MalwareBazaar API client to `application/x-www-form-urlencoded` POST requests with negative caching and 3-failure circuit breaker, added boolean condition AST evaluation and UTF-16LE wide string decoding to the pure-Python fallback rule engine, enforced 30s native YARA execution timeouts, and implemented atomic config saves with `0600` permissions.
  - **Output Sanitization & Forensic Artifacts**: Eliminated Stored XSS in HTML reports with comprehensive escaping and strict CSP (`default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none';`), escaped Rich console markup, stripped ANSI/VT100 escape codes from binary metadata, eliminated forensic carving naming collisions via `payload_<sha256>_sec<idx>_<name>.bin`, guarded carving directories against path traversal, and sanitized JSON telemetry for bytes, surrogates, and non-finite floats.
  - **Automated Resilience Test Suite**: Added `test_resilience_audit.py` with 53 comprehensive unit tests validating every audit finding.

### Changed
- Refactored `entropystrip.core` single-file and directory scanning routines to incorporate all 5 new triage engines and scoped resource lifecycles.
- Refactored `entropystrip.cli` argument parsing to auto-infer `--bazaar` when `--bazaar-key` is supplied and reject Win32 reserved device names early.
- Updated Windows installer packaging with PyInstaller to bundle default YARA rules and support standalone deployment.

---

## [1.2.3] - 2026-10-14

### Added
- Multi-modal repeating byte padding dilution radar (detecting `0xCC`, `0x90`, and multi-byte alternating patterns).
- Dual-scale sliding window entropy analysis for localized payload detection in low-entropy sections.
- Pearson's Chi-Square ($\chi^2$) distribution test for distinguishing encrypted vs. compressed payloads.
- Polyglot container detection (embedded ZIP, JAR, and 7z archives in PE overlays).
- Disassembly stub extraction at entry point using Capstone.
- MITRE ATT&CK technique mapping in console and HTML reports.
