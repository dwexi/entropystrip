# Changelog

All notable changes to EntropyStrip are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.3.0] - 2026-10-15

### Added
- Pure-Python SSDEEP and Context-Triggered Piecewise Hashing (CTPH) in `entropystrip.radar.fuzzy` with 64-character base64 hash representations.
- Levenshtein distance string similarity scoring (0 to 100 percent) and automated campaign clustering for binaries with 70 percent or higher similarity.
- YARA scanning engine (`--yara [RULE_PATH]`) with native `yara-python` support and bundled rules in `entropystrip/rules/defaults/threats.yar` for Cobalt Strike, ransomware shadow copy deletion, PowerShell download cradles, reflective DLL loaders, and egg hunters.
- Pure-Python fallback YARA engine for environments without compiled C extensions, with boolean AST evaluation (Cobalt Strike named pipes, ransomware conjunctions) and UTF-16LE wide string searches.
- Recursive resource tree (`.rsrc`) parser in `entropystrip.scanner` that checks entry entropy, detects embedded executables (PE steganography), and carves suspicious `RT_RCDATA` payloads.
- Export Address Table (EAT) inspector that detects forwarded exports and flags Windows system library masquerading (`version.dll`, `dbghelp.dll`, etc.) to spot DLL sideloading and proxying.
- MalwareBazaar threat intelligence client (`--bazaar`, `--bazaar-key`) that queries the abuse.ch API for malware family names, community tags, first-seen dates, and VirusTotal ratios.
- Negative caching and a three-strike circuit breaker in the MalwareBazaar client to avoid timeout stalls on offline or rate-limited networks.
- Interactive incident triage leaderboard in terminal output and standalone HTML reports (`--html`), with summary cards and campaign clusters.
- Standalone 53-test automated resilience suite (`test_resilience_audit.py`) covering PE parser bounds, math heuristics, filesystem edge cases, network fallbacks, and output sanitization.

### Fixed
- Overlay detection now measures physical raw data bounds rather than header-declared `SizeOfRawData`, which prevents inflated section sizes from hiding appended payloads.
- Guaranteed `pe.close()` execution via `try...finally` cleanup to prevent file locking issues on Windows (`WinError 32`).
- Capped per-section buffering at 2 MB during ingestion, keeping process RAM under 50 MB on multi-gigabyte binaries.
- Strided 5-chunk sampling across large buffers in `sample_large_buffer`, eliminating blind spots for payloads in the middle of multi-megabyte files.
- Rejection of Win32 reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) before filesystem operations to prevent terminal hangs.
- Path normalization for long network shares using the `\\?\UNC\server\share` namespace format.
- Telemetry capture for files locked by running processes (`PermissionError`) instead of silently dropping them from scan results.
- Protected non-recursive directory scans against unhandled `PermissionError` or `OSError` exceptions.
- Circular loop prevention across NTFS junction points and case-insensitive path tracking during recursive traversal.
- Guarded TLS callback resolution against negative RVAs (`target_va < image_base`) and bounded traversal to the enclosing section.
- Added ARM64 PE32+ detection via Optional Header Magic (`0x020B`) rather than architecture constants alone.
- Section table bounds checking to flag dropped sections past EOF and invalid section counts (0 or over 96).
- Guarded against truncated DOS headers under 64 bytes and validated embedded PE headers to require at least 248 bytes of clearance.
- Fuzzy hash comparison guard requiring at least 4 characters and a shared 4-character substring to prevent 1-character false matches.
- Dynamic candidate accumulation in multimodal dilution detection, replacing the previous 4-delimiter limit.
- 16-bin coarse chi-square fallback to satisfy Cochran's sample size rule for moderate multimodal stagers.
- Sliding-window remainder tail check so the final block in a section is evaluated.
- Sub-256-byte entropy calculation fallback so short stagers receive valid scores instead of 0.0.
- Complete-linkage clustering to prevent transitive chaining between unrelated samples.
- MalwareBazaar request body switched to `application/x-www-form-urlencoded` format required by the API.
- Native YARA execution timeout set to 30 seconds to defend against catastrophic backtracking.
- Safe handling of `None` VirusTotal ratios in HTML report generation.
- Safe string coercion for tags lists to avoid `TypeError` on unexpected API output.
- Config parser dictionary validation so corrupted or list-based JSON files return an empty dictionary instead of throwing `AttributeError`.
- Entry point and TLS callback disassembly fall back to `pe.get_data` when physical file offsets exceed the initial buffer slice on large binaries.
- ARM64 disassembly mode set to `CS_ARCH_ARM64` and `CS_MODE_ARM` in Capstone, correcting instruction decoding on 64-bit ARM Windows binaries.
- System32 DLL masquerade detection verifies the directory path boundary against the real Windows directory, blocking path bypasses from deceptive subdirectories.
- Reserved Win32 device name filtering strips trailing spaces and periods, blocking filesystem evasions like `NUL.` or `CON `.
- Pure-Python fallback YARA engine reads up to 16 MB directly from disk for large binaries, catching threat signatures located in overlays and tail sections.

### Security
- Stored XSS defense in HTML reports: properly escaped masqueraded DLL names, binary paths, hashes, and document titles.
- Strict Content Security Policy meta tag added to HTML reports (`default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; object-src 'none';`).
- Rich console markup escaping on all binary paths, hashes, error strings, and anomalies to prevent terminal display errors.
- Filtered VT100 and ANSI terminal escape codes (`strip_ansi`) from untrusted strings to prevent terminal injection.
- Deterministic payload carving naming (`payload_<sha256>_sec<idx>_<name>.bin`) with path traversal checks (`os.path.commonpath`) to prevent directory escape.
- Safe JSON serialization that encodes raw bytes as hex, strips Unicode surrogates, and converts NaN or infinite floats to 0.0.
- Atomic configuration file writes using temporary files and restricted file permissions (0600 mode).

### Changed
- CLI automatically activates MalwareBazaar lookup when `--bazaar-key` is supplied.
- Standalone Windows PyInstaller executable bundles default YARA rules for offline triage.

---

## [1.2.3] - 2026-10-14

### Added
- Multi-modal repeating byte padding dilution radar (detecting `0xCC`, `0x90`, and multi-byte alternating patterns).
- Dual-scale sliding window entropy analysis for localized payload detection in low-entropy sections.
- Pearson's Chi-Square ($\chi^2$) distribution test for distinguishing encrypted vs. compressed payloads.
- Polyglot container detection (embedded ZIP, JAR, and 7z archives in PE overlays).
- Disassembly stub extraction at entry point using Capstone.
- MITRE ATT&CK technique mapping in console and HTML reports.
