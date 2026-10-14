"""
Core analysis coordinator and public API facade for EntropyStrip.
"""

import os
import sys
import json
import struct
from typing import Optional, Dict, Any, List, Tuple
import pefile
from rich.table import Table
from rich.markup import escape

from .models import TriageDiagnostic
from .radar.entropy import (
    calculate_entropy,
    scan_sliding_window_entropy,
    get_entropy_heatmap_string,
)
from .radar.dilution import (
    calculate_dilution_metrics,
    calculate_chi_square,
)
from .radar.staging import (
    detect_encoded_payload,
    detect_string_staging,
    STRING_STAGING_APIS,
)
from .radar.signatures import (
    detect_installer,
    check_authenticode_signature,
)
from .scanner import (
    compute_hashes,
    compute_file_hashes,
    inspect_imports,
    is_dotnet_assembly,
    check_rich_header,
    detect_overlay,
    harvest_indicators,
    disassemble_entry_point,
    map_mitre_techniques,
    KNOWN_PACKER_SECTIONS,
    sanitize_section_name,
    detect_overlapping_sections,
    inspect_tls_callbacks,
    inspect_pe_resources,
    inspect_exports,
)
from .rules import scan_yara
from .intel import query_malware_bazaar
from .radar.fuzzy import compute_fuzzy_hash, cluster_samples
from .reporters.console import (
    console,
    render_console_report,
    render_triage_leaderboard,
)
from .reporters.html import generate_html_report, generate_directory_html_report

def main() -> None:
    from .cli import main as cli_main
    cli_main()

# Re-export public radar and scanning utilities for backward compatibility
__all__ = [
    "main",
    "analyze_single_file",
    "scan_directory",
    "calculate_entropy",
    "scan_sliding_window_entropy",
    "get_entropy_heatmap_string",
    "calculate_dilution_metrics",
    "calculate_chi_square",
    "detect_encoded_payload",
    "detect_string_staging",
    "detect_installer",
    "check_authenticode_signature",
    "check_rich_header",
    "detect_overlay",
    "harvest_indicators",
    "disassemble_entry_point",
    "map_mitre_techniques",
    "sanitize_section_name",
    "detect_overlapping_sections",
    "inspect_tls_callbacks",
    "inspect_pe_resources",
    "inspect_exports",
    "scan_yara",
    "query_malware_bazaar",
    "compute_fuzzy_hash",
    "cluster_samples",
    "generate_html_report",
    "generate_directory_html_report",
]


def normalize_windows_path(p: str) -> str:
    """Normalizes path and prepends extended-length \\\\?\\ prefix on Windows if path exceeds 240 chars."""
    if not p:
        return p
    clean = p.strip().strip('"\'')
    try:
        norm = os.path.normpath(os.path.abspath(clean))
        if sys.platform == "win32" and not norm.startswith("\\\\?\\") and len(norm) >= 240:
            return f"\\\\?\\{norm}"
        return norm
    except Exception:
        return clean


def analyze_single_file(
    file_path: str,
    dump_payloads: bool = False,
    quiet: bool = False,
    html_out: Optional[str] = None,
    json_out: Optional[str] = None,
    deep: bool = False,
    yara_rule_path: Optional[str] = None,
    enable_yara: bool = False,
    enable_bazaar: bool = False,
    bazaar_key: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Analyzes a single PE binary for obfuscation, high entropy, and evasion heuristics."""
    norm_path = normalize_windows_path(file_path)
    if not os.path.exists(norm_path):
        if not quiet:
            console.print(f"[red]Error: File not found -> {file_path}[/red]")
        return None

    try:
        file_size = os.path.getsize(norm_path)
    except Exception as e:
        if not quiet:
            console.print(f"[dim]Cannot access {os.path.basename(file_path)}: {e}[/dim]")
        return None

    is_large_file = file_size > 16 * 1024 * 1024
    file_data = b""
    pe = None

    try:
        if not is_large_file:
            with open(norm_path, "rb") as f:
                file_data = f.read()
        else:
            with open(norm_path, "rb") as f:
                file_data = f.read(2 * 1024 * 1024)

        # Clean rejection of non-PE formats (e.g. Linux ELF)
        if file_data[:4] == b"\x7fELF":
            if not quiet:
                console.print(
                    f"[yellow][!] Unsupported format: Linux ELF binary ({os.path.basename(file_path)}). "
                    f"EntropyStrip is purpose-built for Windows PE32/PE32+ executables.[/yellow]"
                )
            return None

        if is_large_file:
            pe = pefile.PE(name=norm_path, fast_load=True)
            pe.parse_data_directories()
        else:
            pe = pefile.PE(data=file_data)
    except Exception:
        # Check if the file starts with MZ but has corrupted or fuzzed headers
        if file_data[:2] == b"MZ":
            e_lfanew = 0
            if len(file_data) >= 64:
                e_lfanew = struct.unpack("<I", file_data[60:64])[0]

            if e_lfanew < 64:
                anomalies = ["Legacy 16-bit MS-DOS binary (e_lfanew < 64, no valid PE32 header)."]
                threat_score = 25
                verdict_text = "[INFO] Legacy MS-DOS Binary"
                verdict_color = "dim"
            else:
                anomalies = [
                    f"Header Anomaly: Corrupted DOS e_lfanew pointer ({hex(e_lfanew)}) points past EOF or into malformed headers."
                ]
                threat_score = 70
                verdict_text = "[CRITICAL] High Risk (Corrupted / Malformed PE Headers)"
                verdict_color = "bold red"

            f_hashes = compute_hashes(file_data) if not is_large_file else compute_file_hashes(norm_path)
            f_fuzzy = compute_fuzzy_hash(file_data) if file_data else None
            diagnostic = TriageDiagnostic(
                filename=os.path.basename(file_path),
                path=file_path,
                hashes=f_hashes,
                imphash=None,
                fuzzy_hash=f_fuzzy,
                threat_score=threat_score,
                verdict=verdict_text,
                color=verdict_color,
                is_dotnet=False,
                is_signed=False,
                has_overlay=False,
                overlay_size=0,
                total_imports=0,
                anomalies=anomalies,
                mitre=[("T1027", "Obfuscated Files or Information", "Malformed PE headers to impede static triage")],
                sections=[],
            )
            return diagnostic.to_dict()

        if not quiet:
            console.print(f"[dim]Skipping (Invalid PE or locked): {os.path.basename(file_path)}[/dim]")
        return None

    hashes = compute_hashes(file_data) if not is_large_file else compute_file_hashes(norm_path)
    fuzzy_hash = compute_fuzzy_hash(file_data) if file_data else None
    try:
        imphash_val = pe.get_imphash()
    except Exception:
        imphash_val = None

    anomalies: List[str] = []
    threat_score = 0
    high_entropy_sections: List[Tuple[str, bytes, float]] = []
    has_wx = False
    is_diluted = False
    has_concealed = False
    has_staging = False
    sections_telemetry: List[Dict[str, Any]] = []

    table = Table(title="Section Architecture & Entropy", show_header=True, header_style="bold")
    table.add_column("Section", style="cyan", justify="center")
    table.add_column("Virt Size", style="dim", justify="right")
    table.add_column("Raw Size", style="dim", justify="right")
    table.add_column("Entropy", justify="right")
    table.add_column("Perms", justify="center")
    table.add_column("Entropy Strip", justify="left")
    table.add_column("Status", justify="center")

    # Detect physical section layout anomalies (overlapping sections, zero-length, raw size past EOF)
    overlap_anomalies, overlap_penalty = detect_overlapping_sections(pe, file_size)
    if overlap_anomalies:
        anomalies.extend(overlap_anomalies)
        threat_score += overlap_penalty

    for section in pe.sections:
        name = sanitize_section_name(section.Name).lower()

        raw_data = section.get_data()
        entropy = calculate_entropy(raw_data)

        # Check for null-byte or repeated-byte padding dilution
        non_pad_ent, pad_ratio, is_dilution_hit, pad_name = calculate_dilution_metrics(raw_data)
        if is_dilution_hit:
            is_diluted = True
            anomalies.append(
                f"Section '{name}': Evasion detected! {pad_name} dilution masking high-entropy payload "
                f"(Real Entropy: {non_pad_ent:.2f}, Pad Ratio: {pad_ratio*100:.0f}%)."
            )
            threat_score += 40
            high_entropy_sections.append((name, raw_data, non_pad_ent))

        # Chi-Square goodness-of-fit test for uniform ciphertext
        chi2, nz_chi2, is_diluted_uniform = calculate_chi_square(raw_data)
        if is_diluted_uniform and not is_dilution_hit:
            is_diluted = True
            anomalies.append(
                f"Section '{name}': Chi-Square (χ²={nz_chi2:.1f}) confirms uniform ciphertext distribution despite low global entropy."
            )
            threat_score += 35
            high_entropy_sections.append((name, raw_data, 7.5))

        # Check for Base64 payload in section
        has_b64, b64_ent, b64_desc = detect_encoded_payload(raw_data)
        if has_b64 and entropy <= 6.6:
            anomalies.append(f"Section '{name}': {b64_desc}. Obfuscated payload risk.")
            threat_score += 30
            high_entropy_sections.append((f"{name}_base64", raw_data, b64_ent))

        is_exec = bool(section.Characteristics & 0x20000000)
        is_write = bool(section.Characteristics & 0x80000000)

        # Sub-section sliding window analysis
        has_local_spike = False
        local_max_ent = 0.0
        if entropy <= 7.2 and len(raw_data) >= 512:
            local_max_ent, anomalous_spans = scan_sliding_window_entropy(raw_data)
            if anomalous_spans:
                span = anomalous_spans[0]
                span_len = span["end"] - span["start"]
                span_data = raw_data[span["start"] : span["end"]]

                is_benign_asset = False
                if name in (".rsrc", ".data", ".rdata") and not is_exec and not is_write:
                    if (
                        span_data.startswith(b"\x89PNG")
                        or span_data.startswith(b"\x00\x00\x01\x00")
                        or span_data.startswith(b"PK\x03\x04")
                        or span_data.startswith(b"BM")
                    ):
                        is_benign_asset = True
                    elif name == ".rsrc":
                        is_benign_asset = True

                if is_benign_asset:
                    anomalies.append(
                        f"Section '{name}': Compressed resource asset detected (Local H={local_max_ent:.2f} at offset {hex(span['start'])}, ~{span_len} bytes)."
                    )
                    threat_score += 5
                elif not is_exec and not is_write:
                    has_local_spike = True
                    has_concealed = True
                    anomalies.append(
                        f"Section '{name}': High-density data cluster detected via sliding window (Local H={local_max_ent:.2f} at offset {hex(span['start'])}, ~{span_len} bytes) in read-only section."
                    )
                    threat_score += 15
                    high_entropy_sections.append((f"{name}_concealed", span_data, local_max_ent))
                else:
                    has_local_spike = True
                    has_concealed = True
                    anomalies.append(
                        f"Section '{name}': Concealed payload detected via sliding window! (Local H={local_max_ent:.2f} at offset {hex(span['start'])}, ~{span_len} bytes) in executable/writable code space!"
                    )
                    threat_score += 35
                    high_entropy_sections.append((f"{name}_concealed", span_data, local_max_ent))

        perms = ""
        perms_raw = "R"
        if is_write and is_exec:
            perms = "[bold red]W+X[/bold red]"
            perms_raw = "W+X"
            has_wx = True
            anomalies.append(f"Section '{name}' is Writable + Executable (W+X self-modifying code risk).")
            threat_score += 25
        elif is_exec:
            perms = "[green]R+X[/green]"
            perms_raw = "R+X"
        elif is_write:
            perms = "[blue]R+W[/blue]"
            perms_raw = "R+W"
        else:
            perms = "[dim]R[/dim]"

        if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
            anomalies.append(
                f"Section '{name}' has 0 raw data on disk but reserves {hex(section.Misc_VirtualSize)} in RAM."
            )
            threat_score += 25

        if name in KNOWN_PACKER_SECTIONS:
            anomalies.append(f"Known packer section name: '{name}'.")
            threat_score += 30

        raw_heatmap_chars = []
        chunk_sz = max(1, len(raw_data) // 30) if raw_data else 1
        for i in range(30):
            st = i * chunk_sz
            en = len(raw_data) if i == 29 else st + chunk_sz
            chk = raw_data[st:en]
            if chk:
                c_ent = calculate_entropy(chk)
                raw_heatmap_chars.append(
                    "R"
                    if c_ent > 7.4
                    else ("Y" if c_ent > 6.6 else ("G" if c_ent > 5.0 else ("B" if c_ent > 1.0 else "D")))
                )

        if entropy > 7.4:
            entropy_str = f"[bold red]{entropy:.2f}[/bold red]"
            status = "[red]HIGH[/red]"
            high_entropy_sections.append((name, raw_data, entropy))
            threat_score += 35
            anomalies.append(f"Section '{name}' has high entropy ({entropy:.2f} / 8.00).")
        elif is_dilution_hit or is_diluted_uniform:
            entropy_str = f"[bold red]{entropy:.2f}*[/bold red]"
            status = "[red]DILUTED[/red]"
        elif has_local_spike:
            entropy_str = f"[bold red]{entropy:.2f}![/bold red]"
            status = "[bold red]CONCEALED[/bold red]"
        elif entropy > 6.6:
            if name == ".rsrc":
                entropy_str = f"[bold green]{entropy:.2f}[/bold green]"
                status = "[green]OK[/green]"
            else:
                entropy_str = f"[bold yellow]{entropy:.2f}[/bold yellow]"
                status = "[yellow]SUSP[/yellow]"
                threat_score += 10
        else:
            entropy_str = f"[bold green]{entropy:.2f}[/bold green]"
            status = "[green]OK[/green]"

        heatmap_visual = get_entropy_heatmap_string(raw_data)

        table.add_row(
            escape(name),
            hex(section.Misc_VirtualSize),
            hex(section.SizeOfRawData),
            entropy_str,
            perms,
            heatmap_visual,
            status,
        )

        sections_telemetry.append(
            {
                "name": name,
                "virt_size": hex(section.Misc_VirtualSize),
                "raw_size": hex(section.SizeOfRawData),
                "entropy": entropy,
                "perms": perms_raw,
                "status": "HIGH"
                if entropy > 7.4
                else (
                    "DILUTED"
                    if (is_dilution_hit or is_diluted_uniform)
                    else ("CONCEALED" if has_local_spike else ("SUSP" if entropy > 6.6 else "OK"))
                ),
                "raw_heatmap": "".join(raw_heatmap_chars),
            }
        )

    is_dotnet = is_dotnet_assembly(pe)
    is_signed, cert_msg = check_authenticode_signature(pe, file_size, file_data)
    if "Malformed or forged" in cert_msg or "out of bounds" in cert_msg:
        anomalies.append(f"Security Directory Anomaly: {cert_msg}.")
        threat_score += 30

    # Enumerate TLS callbacks (pre-entrypoint execution stagers)
    tls_callbacks = inspect_tls_callbacks(pe, file_data)
    if tls_callbacks:
        cb_vas = ", ".join([cb["va"] for cb in tls_callbacks[:4]])
        anomalies.append(
            f"Pre-entrypoint TLS callbacks detected ({len(tls_callbacks)} registered: {cb_vas}). Potential staging / anti-debug risk."
        )
        threat_score += 25

    max_offset, overlay_data = detect_overlay(pe, file_size, file_data=file_data, file_path=norm_path)
    has_overlay = file_size > max_offset and max_offset > 0
    overlay_size = file_size - max_offset if has_overlay else 0
    overlay_entropy = 0.0
    is_cert_overlay = False
    polyglot_type = None

    if has_overlay:
        overlay_entropy = calculate_entropy(overlay_data)

        status = "[green]OK[/green]"
        status_clean = "OK"

        # Check for Polyglot container archives in overlay (ZIP, 7z, RAR, PDF)
        if len(overlay_data) >= 4:
            if (
                overlay_data.startswith(b"PK\x03\x04")
                or overlay_data.startswith(b"PK\x05\x06")
                or b"PK\x03\x04" in overlay_data[:1024]
            ):
                polyglot_type = "ZIP / JAR Archive"
            elif overlay_data.startswith(b"7z\xbc\xaf\x27\x1c"):
                polyglot_type = "7-Zip Archive"
            elif overlay_data.startswith(b"Rar!\x1a\x07"):
                polyglot_type = "RAR Archive"
            elif overlay_data.startswith(b"%PDF-"):
                polyglot_type = "PDF Document"

        if polyglot_type:
            anomalies.append(
                f"Polyglot Container: Embedded {polyglot_type} detected in overlay. Steganography / dropper evasion risk (T1027.009)."
            )
            threat_score += 45
            status = "[bold red]POLYGLOT[/bold red]"
            status_clean = "POLYGLOT"
            high_entropy_sections.append(("overlay_polyglot", overlay_data, 7.5))

        # Validate whether overlay is strictly the Authenticode certificate table
        if is_signed and hasattr(pe, "OPTIONAL_HEADER") and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
            sec_va = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress
            sec_sz = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
            if sec_va == max_offset and sec_sz <= len(overlay_data):
                is_cert_overlay = True
                trailing_extra = len(overlay_data) - sec_sz
                if trailing_extra == 0:
                    status = "[dim]SIGNED[/dim]"
                    status_clean = "SIGNED"
                    anomalies.append(
                        f"Overlay is valid Authenticode digital signature table ({len(overlay_data)} bytes)."
                    )
                else:
                    status = "[yellow]SUSP[/yellow]"
                    status_clean = "SUSP"
                    anomalies.append(
                        f"Overlay contains Authenticode signature ({sec_sz} bytes) plus {trailing_extra} unmapped trailing bytes past certificate!"
                    )
                    threat_score += 25

        if not is_cert_overlay:
            # Check for Base64 payload in overlay
            has_b64, b64_ent, b64_desc = detect_encoded_payload(overlay_data)
            if has_b64:
                anomalies.append(f"Overlay: {b64_desc}. Obfuscated payload risk.")
                threat_score += 35
                high_entropy_sections.append(("overlay_base64", overlay_data, b64_ent))
                status = "[red]OBFUSCATED[/red]"
                status_clean = "OBFUSCATED"

            # Check for dilution evasion in overlay
            ov_non_pad, ov_pad_ratio, ov_diluted, ov_pad_name = calculate_dilution_metrics(overlay_data)
            ov_chi2, ov_nz_chi2, ov_diluted_uniform = calculate_chi_square(overlay_data)

            if ov_diluted or ov_diluted_uniform:
                is_diluted = True
                disp_ent = ov_non_pad if ov_diluted else 7.5
                anomalies.append(
                    f"Overlay evasion detected! {ov_pad_name} dilution/Chi-Square masking high-entropy payload (Real Payload Entropy: {disp_ent:.2f})."
                )
                threat_score += 45
                high_entropy_sections.append(("overlay", overlay_data, disp_ent))
                status = "[red]DILUTED[/red]"
                status_clean = "DILUTED"
            elif overlay_entropy > 7.2:
                anomalies.append(
                    f"Overlay detected ({len(overlay_data)} bytes) with high entropy ({overlay_entropy:.2f}). Steganography/Dropper risk."
                )
                threat_score += 35
                high_entropy_sections.append(("overlay", overlay_data, overlay_entropy))
                status = "[red]HIGH[/red]"
                status_clean = "HIGH"
            else:
                ov_has_local_spike = False
                if len(overlay_data) >= 512:
                    ov_max_win, ov_anomalous_spans = scan_sliding_window_entropy(overlay_data)
                    if ov_anomalous_spans:
                        ov_has_local_spike = True
                        has_concealed = True
                        ov_span = ov_anomalous_spans[0]
                        ov_len = ov_span["end"] - ov_span["start"]
                        anomalies.append(
                            f"Overlay: Concealed payload detected via sliding window! (Local H={ov_max_win:.2f} at offset {hex(ov_span['start'])}, ~{ov_len} bytes) despite overall overlay H={overlay_entropy:.2f}."
                        )
                        threat_score += 35
                        high_entropy_sections.append(
                            ("overlay_concealed", overlay_data[ov_span["start"] : ov_span["end"]], ov_max_win)
                        )
                        status = "[bold red]CONCEALED[/bold red]"
                        status_clean = "CONCEALED"

                if not ov_has_local_spike:
                    anomalies.append(f"Overlay detected ({len(overlay_data)} bytes, entropy {overlay_entropy:.2f}).")
                    threat_score += 10
                    status = "[yellow]SUSP[/yellow]"
                    status_clean = "SUSP"

        raw_heatmap_chars = []
        chunk_sz = max(1, len(overlay_data) // 30)
        for i in range(30):
            st = i * chunk_sz
            en = len(overlay_data) if i == 29 else st + chunk_sz
            chk = overlay_data[st:en]
            if chk:
                c_ent = calculate_entropy(chk)
                raw_heatmap_chars.append(
                    "R"
                    if c_ent > 7.4
                    else ("Y" if c_ent > 6.6 else ("G" if c_ent > 5.0 else ("B" if c_ent > 1.0 else "D")))
                )

        table.add_row(
            "[dim][OVERLAY][/dim]",
            "-",
            hex(len(overlay_data)),
            f"{overlay_entropy:.2f}",
            "[dim]DATA[/dim]",
            get_entropy_heatmap_string(overlay_data),
            status,
        )

        sections_telemetry.append(
            {
                "name": "[OVERLAY]",
                "virt_size": "-",
                "raw_size": hex(len(overlay_data)),
                "entropy": overlay_entropy,
                "perms": "DATA",
                "status": status_clean,
                "raw_heatmap": "".join(raw_heatmap_chars),
            }
        )

    installer_type = detect_installer(file_data, overlay_data, pe=pe)

    # Validate MSVC Rich Header integrity
    has_rich, rich_ck, rich_status = check_rich_header(pe)
    if not has_rich and "Stripped" in rich_status:
        anomalies.append(f"Compiler anomaly: {rich_status}.")
        threat_score += 15

    total_imports, flagged_apis = inspect_imports(pe)
    if not is_dotnet:
        if total_imports < 15 and file_size > 30000:
            anomalies.append(f"Unusually small import table ({total_imports} functions).")
            threat_score += 20

    if flagged_apis:
        anomalies.append(f"Sensitive APIs: {', '.join(flagged_apis)}")
        threat_score += 15

    # Memory staging detection
    staging_apis, uuid_count, has_uuid_cluster, ip_count, has_ip_cluster = detect_string_staging(
        file_data, flagged_apis
    )
    if staging_apis or has_uuid_cluster or has_ip_cluster:
        has_staging = True
        parts = []
        if staging_apis:
            parts.append(f"Staging APIs: {', '.join(staging_apis)}")
        if has_uuid_cluster:
            parts.append(f"UUID array cluster: {uuid_count} formatted strings")
        if has_ip_cluster:
            parts.append(f"IP address array cluster: {ip_count} formatted strings")
        anomalies.append(f"String-based shellcode staging primitive detected ({'; '.join(parts)}).")
        threat_score += 35

    # PE Resource Tree Inspection (.rsrc deep traversal & embedded PE / RC_DATA detection)
    rsrc_telemetry, rsrc_anomalies, rsrc_penalty, rsrc_carveables = inspect_pe_resources(pe, file_data)
    if rsrc_anomalies:
        anomalies.extend(rsrc_anomalies)
        threat_score += rsrc_penalty
    if rsrc_carveables:
        high_entropy_sections.extend(rsrc_carveables)

    # Export Address Table (EAT) Inspection & DLL Side-Loading / Masquerading
    exp_info, exp_anomalies, exp_penalty = inspect_exports(pe, norm_path)
    if exp_anomalies:
        anomalies.extend(exp_anomalies)
        threat_score += exp_penalty

    # YARA Rules Engine Scanning (Bundled threats.yar or custom user rule)
    yara_matches: List[Dict[str, Any]] = []
    if enable_yara or yara_rule_path is not None:
        custom_rule = None if yara_rule_path in (None, "__default__") else yara_rule_path
        yara_matches = scan_yara(file_data, custom_path=custom_rule, file_path=norm_path)
        for ym in yara_matches:
            rule_nm = ym.get("rule", "UnknownRule")
            rule_desc = ym.get("description", "")
            rule_score = ym.get("threat_score", 35)
            anomalies.append(f"YARA Detection: [{rule_nm}] - {rule_desc}" if rule_desc else f"YARA Detection: [{rule_nm}]")
            threat_score += rule_score

    # MalwareBazaar Threat Intelligence API Query (Opt-in via --bazaar)
    bazaar_intel: Optional[Dict[str, Any]] = None
    if enable_bazaar:
        sha256_hash = hashes.get("sha256", "")
        if sha256_hash:
            bazaar_intel = query_malware_bazaar(sha256_hash, api_key=bazaar_key)
            if bazaar_intel and bazaar_intel.get("status") == "malicious":
                fam = bazaar_intel.get("signature") or "Known Threat"
                tg = ", ".join(bazaar_intel.get("tags", []))
                tg_str = f" (Tags: {tg})" if tg else ""
                anomalies.append(f"MalwareBazaar Threat Intelligence: Confirmed malicious sample! Family: '{fam}'{tg_str}")
                threat_score += 45

    # Installer and Authenticode whitelisting
    exec_high_entropy = any(
        s.get("perms") in ("R+X", "W+X") and s.get("entropy", 0) > 7.0 for s in sections_telemetry
    )
    is_trusted_installer = installer_type in (
        "Nullsoft NSIS Setup",
        "Inno Setup",
        "WiX / Burn Bootstrapper",
        "InstallShield Setup",
    )
    if (is_trusted_installer or is_signed) and not has_wx and not has_staging and not exec_high_entropy:
        discount = 35 if is_trusted_installer else 20
        old_score = threat_score
        threat_score = max(0, threat_score - discount)
        src = installer_type if is_trusted_installer else "Valid Authenticode Digital Signature"
        anomalies.append(
            f"Whitelisting discount: Verified {src}. Resource/overlay compressed assets discounted (-{discount} pts: {old_score} -> {threat_score})."
        )
    elif installer_type == "Unverified NSIS Marker":
        anomalies.append(
            "Suspicious: Unverified NSIS marker in overlay without valid installer structure (potential evasion spoof)."
        )
        threat_score += 25

    indicators: List[str] = []
    for s_name, s_bytes, s_ent in high_entropy_sections:
        indicators.extend(harvest_indicators(s_bytes))
    indicators = list(set(indicators))

    # Standard UPX Calibration
    has_upx0 = any(s["name"] == "upx0" for s in sections_telemetry)
    has_upx1 = any(s["name"] == "upx1" for s in sections_telemetry)
    has_upx_sig = (
        b"UPX!" in file_data
        or (has_overlay and b"UPX!" in overlay_data)
        or any(b"UPX!" in s[1] for s in high_entropy_sections)
    )

    if has_upx0 and has_upx1 and has_upx_sig:
        has_non_upx_wx = any(
            (section.Characteristics & 0x20000000) and (section.Characteristics & 0x80000000)
            for section in pe.sections
            if sanitize_section_name(section.Name).lower() not in ("upx0", "upx1", "upx2")
        )
        has_hostile = (
            has_non_upx_wx
            or has_staging
            or is_diluted
            or (polyglot_type is not None)
            or any(api in ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread") for api in flagged_apis)
        )
        if not has_hostile:
            threat_score = min(threat_score, 45)
            anomalies.append(
                "Packer Calibration: Standard UPX compression format verified (UPX! marker). "
                "Threat score calibrated to 45 (benign packed utility baseline)."
            )

    threat_score = min(100, threat_score)

    if threat_score >= 70:
        verdict_color = "red"
        verdict_text = "[CRITICAL] High Risk (Packed / Obfuscated)"
    elif threat_score >= 35:
        verdict_color = "yellow"
        verdict_text = "[WARNING] Suspicious (Anomalies Present)"
    else:
        verdict_color = "green"
        verdict_text = "[OK] Clean / Low Risk"

    mitre_techniques = map_mitre_techniques(
        anomalies,
        flagged_apis,
        has_wx,
        len(high_entropy_sections) > 0,
        has_overlay,
        is_diluted,
        has_staging=has_staging,
        has_concealed=has_concealed,
    )
    ep_disasm = disassemble_entry_point(pe, file_data) if deep else None

    if not quiet:
        render_console_report(
            target_path=file_path,
            sections_table=table,
            threat_score=threat_score,
            verdict_text=verdict_text,
            verdict_color=verdict_color,
            is_dotnet=is_dotnet,
            is_signed=is_signed,
            anomalies=anomalies,
            indicators=indicators,
            mitre_techniques=mitre_techniques,
            ep_disasm=ep_disasm,
            hashes=hashes,
            imphash_val=imphash_val,
            deep=deep,
            tls_callbacks=tls_callbacks,
            fuzzy_hash=fuzzy_hash,
            bazaar_intel=bazaar_intel,
            yara_matches=yara_matches,
            resources_info=rsrc_telemetry,
            exports_info=exp_info,
        )

    if dump_payloads and high_entropy_sections:
        out_dir = "extracted_payloads"
        os.makedirs(out_dir, exist_ok=True)
        sha_pfx = hashes.get("sha256", "00000000")[:8]
        clean_base = "".join([c if c.isalnum() or c == "." else "_" for c in os.path.basename(file_path)])
        for idx, (s_name, data, ent) in enumerate(high_entropy_sections):
            clean_name = "".join([c if c.isalnum() else "_" for c in s_name])
            out_path = os.path.join(out_dir, f"{sha_pfx}_{clean_base}_sec{idx}_{clean_name}.bin")
            with open(out_path, "wb") as f:
                f.write(data)
            if not quiet:
                console.print(f"[green][+] Carved payload ({len(data)} bytes) -> {out_path}[/green]")

    if is_large_file and pe and hasattr(pe, "close"):
        try:
            pe.close()
        except Exception:
            pass

    diagnostic = TriageDiagnostic(
        filename=os.path.basename(file_path),
        path=file_path,
        hashes=hashes,
        imphash=imphash_val,
        threat_score=threat_score,
        verdict=verdict_text,
        color=verdict_color,
        is_dotnet=is_dotnet,
        is_signed=is_signed,
        has_overlay=has_overlay,
        overlay_size=len(overlay_data),
        total_imports=total_imports,
        anomalies=anomalies,
        mitre=mitre_techniques,
        ep_disasm=ep_disasm,
        indicators=indicators,
        sections=sections_telemetry,
        wx=has_wx,
        yara_matches=yara_matches,
        bazaar_intel=bazaar_intel,
        fuzzy_hash=fuzzy_hash,
        exports_info=exp_info,
        resources_info=rsrc_telemetry,
    )
    telemetry_data = diagnostic.to_dict()

    if json_out:
        out_dir = os.path.dirname(os.path.abspath(json_out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(telemetry_data, f, indent=2)
        if not quiet:
            console.print(f"[green][+] JSON telemetry written:[/green] {os.path.abspath(json_out)}")

    if html_out:
        generate_html_report(telemetry_data, html_out)
        if not quiet:
            console.print(f"[green][+] HTML report generated:[/green] {os.path.abspath(html_out)}")

    return telemetry_data


def scan_directory(
    dir_path: str,
    recursive: bool = False,
    dump_payloads: bool = False,
    html_out: Optional[str] = None,
    json_out: Optional[str] = None,
    deep: bool = False,
    yara_rule_path: Optional[str] = None,
    enable_yara: bool = False,
    enable_bazaar: bool = False,
    bazaar_key: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Walks directory, ranks found binaries on incident triage leaderboard, and exports HTML/JSON reports."""
    norm_dir = normalize_windows_path(dir_path)
    if not os.path.isdir(norm_dir):
        console.print(f"[red]Error: Directory not found -> {dir_path}[/red]")
        return []

    console.print(f"\n[bold magenta][*] Scanning Directory:[/bold magenta] {dir_path}")
    if enable_yara or yara_rule_path is not None:
        rule_desc = os.path.basename(yara_rule_path) if (yara_rule_path and yara_rule_path != "__default__") else "bundled threats.yar"
        console.print(f"[dim]  • YARA Engine: Active (Scanning with {rule_desc})[/dim]")
    if enable_bazaar:
        console.print("[dim]  • Threat Intel: Active (Querying MalwareBazaar abuse.ch API)[/dim]")

    results: List[Dict[str, Any]] = []

    target_extensions = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi", ".bin"}

    if recursive:
        visited_dirs = set()
        for root, dirs, files in os.walk(norm_dir, followlinks=False):
            try:
                real_root = os.path.realpath(root)
            except Exception:
                real_root = root

            if real_root in visited_dirs:
                dirs.clear()
                continue
            visited_dirs.add(real_root)

            # Prevent traversing circular junction loops or reparse points
            pruned_dirs = []
            for d in dirs:
                sub_path = os.path.join(root, d)
                try:
                    real_sub = os.path.realpath(sub_path)
                    if real_sub in visited_dirs or (sys.platform == "win32" and os.path.islink(sub_path)):
                        continue
                    pruned_dirs.append(d)
                except Exception:
                    pass
            dirs[:] = pruned_dirs

            for file in files:
                if any(file.lower().endswith(ext) for ext in target_extensions):
                    full_p = os.path.join(root, file)
                    try:
                        res = analyze_single_file(
                            full_p,
                            dump_payloads=dump_payloads,
                            quiet=True,
                            deep=deep,
                            yara_rule_path=yara_rule_path,
                            enable_yara=enable_yara,
                            enable_bazaar=enable_bazaar,
                            bazaar_key=bazaar_key,
                        )
                        if res:
                            results.append(res)
                    except PermissionError:
                        console.print(f"[dim]Permission denied: {os.path.basename(full_p)}[/dim]")
                    except Exception as e:
                        console.print(f"[dim]Skipping {os.path.basename(full_p)}: {e}[/dim]")
    else:
        for item in os.listdir(norm_dir):
            full_p = os.path.join(norm_dir, item)
            try:
                if os.path.isfile(full_p) and any(item.lower().endswith(ext) for ext in target_extensions):
                    res = analyze_single_file(
                        full_p,
                        dump_payloads=dump_payloads,
                        quiet=True,
                        deep=deep,
                        yara_rule_path=yara_rule_path,
                        enable_yara=enable_yara,
                        enable_bazaar=enable_bazaar,
                        bazaar_key=bazaar_key,
                    )
                    if res:
                        results.append(res)
            except PermissionError:
                console.print(f"[dim]Permission denied: {os.path.basename(full_p)}[/dim]")
            except Exception as e:
                console.print(f"[dim]Skipping {os.path.basename(full_p)}: {e}[/dim]")

    if not results:
        console.print("[dim]No Windows PE binaries found in directory.[/dim]")
        return []

    # Run Automated Fuzzy Hash Campaign Clustering
    clusters = cluster_samples(results, similarity_threshold=70)

    results.sort(key=lambda x: x["threat_score"], reverse=True)
    render_triage_leaderboard(
        results,
        clusters=clusters,
        yara_enabled=(enable_yara or yara_rule_path is not None),
        bazaar_enabled=enable_bazaar,
    )

    if json_out:
        out_dir = os.path.dirname(os.path.abspath(json_out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        summary = {
            "critical": sum(1 for r in results if r.get("threat_score", 0) >= 70),
            "suspicious": sum(1 for r in results if 35 <= r.get("threat_score", 0) < 70),
            "clean": sum(1 for r in results if r.get("threat_score", 0) < 35),
        }
        clusters_export = {
            c_name: [m.get("filename") for m in members]
            for c_name, members in clusters.items()
        }
        directory_telemetry = {
            "target_directory": dir_path,
            "total_scanned": len(results),
            "summary": summary,
            "campaign_clusters": clusters_export,
            "results": results,
        }
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(directory_telemetry, f, indent=2)
        console.print(f"[green][+] JSON telemetry written:[/green] {os.path.abspath(json_out)}")

    if html_out:
        generate_directory_html_report(
            results,
            dir_path,
            html_out,
            yara_enabled=(enable_yara or yara_rule_path is not None),
            bazaar_enabled=enable_bazaar,
        )
        console.print(f"[green][+] HTML report generated:[/green] {os.path.abspath(html_out)}")

    return results
