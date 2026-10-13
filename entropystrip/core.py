"""
Core analysis coordinator and public API facade for EntropyStrip.
"""

import os
import sys
import json
from typing import Optional, Dict, Any, List, Tuple
import pefile
from rich.table import Table

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
    inspect_imports,
    is_dotnet_assembly,
    check_rich_header,
    detect_overlay,
    harvest_indicators,
    disassemble_entry_point,
    map_mitre_techniques,
    KNOWN_PACKER_SECTIONS,
)
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
    "generate_html_report",
    "generate_directory_html_report",
]


def analyze_single_file(
    file_path: str,
    dump_payloads: bool = False,
    quiet: bool = False,
    html_out: Optional[str] = None,
    json_out: Optional[str] = None,
    deep: bool = False,
) -> Optional[Dict[str, Any]]:
    """Analyzes a single PE binary for obfuscation, high entropy, and evasion heuristics."""
    if not os.path.exists(file_path):
        if not quiet:
            console.print(f"[red]Error: File not found -> {file_path}[/red]")
        return None

    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
        file_size = len(file_data)

        # Clean rejection of non-PE formats
        if file_data[:4] == b"\x7fELF":
            if not quiet:
                console.print(
                    f"[yellow][!] Unsupported format: Linux ELF binary ({os.path.basename(file_path)}). "
                    f"EntropyStrip is purpose-built for Windows PE32/PE32+ executables.[/yellow]"
                )
            return None

        pe = pefile.PE(data=file_data)
    except Exception:
        if not quiet:
            console.print(f"[dim]Skipping (Invalid PE or locked): {os.path.basename(file_path)}[/dim]")
        return None

    hashes = compute_hashes(file_data)
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

    for section in pe.sections:
        try:
            name = section.Name.decode("utf-8").rstrip("\x00").lower()
        except UnicodeDecodeError:
            name = str(section.Name)

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
            name,
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

    max_offset, overlay_data = detect_overlay(pe, file_size, file_data)
    has_overlay = len(overlay_data) > 0
    overlay_entropy = 0.0
    is_cert_overlay = False

    if has_overlay:
        overlay_entropy = calculate_entropy(overlay_data)

        status = "[green]OK[/green]"
        status_clean = "OK"

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
        )

    if dump_payloads and high_entropy_sections:
        out_dir = "extracted_payloads"
        os.makedirs(out_dir, exist_ok=True)
        for s_name, data, ent in high_entropy_sections:
            clean_name = "".join([c if c.isalnum() else "_" for c in s_name])
            out_path = os.path.join(out_dir, f"{os.path.basename(file_path)}_{clean_name}.bin")
            with open(out_path, "wb") as f:
                f.write(data)
            if not quiet:
                console.print(f"[green][+] Carved payload ({len(data)} bytes) -> {out_path}[/green]")

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
) -> List[Dict[str, Any]]:
    """Walks directory, ranks found binaries on incident triage leaderboard, and exports HTML/JSON reports."""
    dir_path = os.path.abspath(os.path.normpath(dir_path.strip().strip('"\'')))
    if not os.path.isdir(dir_path):
        console.print(f"[red]Error: Directory not found -> {dir_path}[/red]")
        return []

    console.print(f"\n[bold magenta][*] Scanning Directory:[/bold magenta] {dir_path}")
    results: List[Dict[str, Any]] = []

    target_extensions = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi", ".bin"}

    if recursive:
        for root, _, files in os.walk(dir_path):
            for file in files:
                if any(file.lower().endswith(ext) for ext in target_extensions):
                    full_p = os.path.join(root, file)
                    res = analyze_single_file(full_p, dump_payloads=dump_payloads, quiet=True, deep=deep)
                    if res:
                        results.append(res)
    else:
        for item in os.listdir(dir_path):
            full_p = os.path.join(dir_path, item)
            if os.path.isfile(full_p) and any(item.lower().endswith(ext) for ext in target_extensions):
                res = analyze_single_file(full_p, dump_payloads=dump_payloads, quiet=True, deep=deep)
                if res:
                    results.append(res)

    if not results:
        console.print("[dim]No Windows PE binaries found in directory.[/dim]")
        return []

    results.sort(key=lambda x: x["threat_score"], reverse=True)
    render_triage_leaderboard(results)

    if json_out:
        out_dir = os.path.dirname(os.path.abspath(json_out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        summary = {
            "critical": sum(1 for r in results if r.get("threat_score", 0) >= 70),
            "suspicious": sum(1 for r in results if 35 <= r.get("threat_score", 0) < 70),
            "clean": sum(1 for r in results if r.get("threat_score", 0) < 35),
        }
        directory_telemetry = {
            "target_directory": dir_path,
            "total_scanned": len(results),
            "summary": summary,
            "results": results,
        }
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(directory_telemetry, f, indent=2)
        console.print(f"[green][+] JSON telemetry written:[/green] {os.path.abspath(json_out)}")

    if html_out:
        generate_directory_html_report(results, dir_path, html_out)
        console.print(f"[green][+] HTML report generated:[/green] {os.path.abspath(html_out)}")

    return results
