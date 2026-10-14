"""
Standalone dark-mode HTML report generator with strict output sanitization.
Provides both single-binary diagnostics and multi-binary incident triage dashboards.
"""

import os
import html
from typing import Dict, Any, List, Union


def _get_status_badge(status_str: str) -> str:
    """Returns a styled HTML badge for section status."""
    clean = str(status_str).strip()
    c = "#8b949e"
    bg = "rgba(255, 255, 255, 0.05)"
    
    if clean in ("HIGH", "DILUTED", "CONCEALED", "OBFUSCATED"):
        c = "#e06c75"
        bg = "rgba(224, 108, 117, 0.15)"
    elif clean == "SUSP":
        c = "#e5c07b"
        bg = "rgba(229, 192, 123, 0.15)"
    elif clean in ("OK", "NORMAL", "CLEAN"):
        c = "#98c379"
        bg = "rgba(152, 195, 121, 0.15)"
    elif clean == "SIGNED":
        c = "#61afef"
        bg = "rgba(97, 175, 239, 0.15)"
        
    return f'<span class="badge" style="color:{c}; background:{bg};">{html.escape(clean)}</span>'


def generate_html_report(telemetry: Union[Dict[str, Any], List[Dict[str, Any]]], output_path: str) -> None:
    """Generates a self-contained HTML triage report for a single file or directory batch."""
    if isinstance(telemetry, list):
        generate_directory_html_report(telemetry, "Batch Triage", output_path)
        return
    if isinstance(telemetry, dict) and "results" in telemetry and isinstance(telemetry["results"], list):
        target_dir = telemetry.get("target_directory", "Incident Triage")
        generate_directory_html_report(telemetry["results"], target_dir, output_path)
        return

    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    score = telemetry.get("threat_score", 0)
    status_color = (
        "#e06c75"
        if score >= 70
        else ("#e5c07b" if score >= 35 else "#98c379")
    )

    hashes = telemetry.get("hashes") or {}
    sha256_val = hashes.get("sha256", "-")
    imphash_val = telemetry.get("imphash") or "-"
    fuzzy_val = telemetry.get("fuzzy_hash") or "-"

    sections_html = ""
    for s in telemetry.get("sections", []):
        heatmap_blocks = ""
        for char in s.get("raw_heatmap", ""):
            c = (
                "#e06c75"
                if char == "R"
                else (
                    "#e5c07b"
                    if char == "Y"
                    else ("#98c379" if char == "G" else ("#61afef" if char == "B" else "#3e4451"))
                )
            )
            heatmap_blocks += f'<span style="color:{c};">■</span>'

        status_badge = _get_status_badge(s.get("status", "OK"))

        sections_html += f"""
        <tr>
            <td style="font-family:ui-monospace,monospace; font-weight:600;">{html.escape(str(s.get('name', '')))}</td>
            <td style="font-family:ui-monospace,monospace; text-align:right;">{html.escape(str(s.get('virt_size', '-')))}</td>
            <td style="font-family:ui-monospace,monospace; text-align:right;">{html.escape(str(s.get('raw_size', '-')))}</td>
            <td style="font-family:ui-monospace,monospace; text-align:right; font-weight:600;">{s.get('entropy', 0.0):.2f}</td>
            <td style="text-align:center;"><span class="badge">{html.escape(str(s.get('perms', '-')))}</span></td>
            <td style="letter-spacing:1px;">{heatmap_blocks}</td>
            <td style="text-align:center;">{status_badge}</td>
        </tr>
        """

    anomalies_html = (
        "".join([f"<li>{html.escape(a)}</li>" for a in telemetry.get("anomalies", [])])
        if telemetry.get("anomalies")
        else "<li>No anomalies detected.</li>"
    )
    indicators_html = (
        "".join([f"<li>{html.escape(i)}</li>" for i in telemetry.get("indicators", [])])
        if telemetry.get("indicators")
        else "<li>No network indicators extracted.</li>"
    )

    mitre_html = ""
    if telemetry.get("mitre"):
        for tid, tname, tdesc in telemetry["mitre"]:
            mitre_html += (
                f"<tr><td style='font-family:monospace; font-weight:600; color:#61afef;'>{html.escape(str(tid))}</td>"
                f"<td style='font-weight:600;'>{html.escape(str(tname))}</td>"
                f"<td>{html.escape(str(tdesc))}</td></tr>"
            )

    bazaar_html = ""
    bazaar = telemetry.get("bazaar_intel")
    if bazaar and bazaar.get("status") == "malicious":
        vt = bazaar.get("virustotal") or {}
        vt_str = f"{vt.get('percent', 0.0):.1f}% ({vt.get('positives', 0)}/{vt.get('total', 0)})" if vt else "N/A"
        bazaar_html = f"""
        <div class="findings-card" style="border-left: 3px solid #e06c75; margin-bottom: 20px;">
            <h3 style="color:#e06c75;">MalwareBazaar Threat Intelligence (abuse.ch)</h3>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:8px;">
                <div><span style="color:#5c6370; font-size:10px;">SIGNATURE:</span> <b style="color:#e06c75;">{html.escape(str(bazaar.get('signature', 'Unknown Threat')))}</b></div>
                <div><span style="color:#5c6370; font-size:10px;">TAGS:</span> <span>{html.escape(', '.join(bazaar.get('tags', [])))}</span></div>
                <div><span style="color:#5c6370; font-size:10px;">FIRST SEEN:</span> <span>{html.escape(str(bazaar.get('first_seen', '-')))}</span></div>
                <div><span style="color:#5c6370; font-size:10px;">VIRUSTOTAL:</span> <span style="color:#e06c75; font-weight:600;">{html.escape(vt_str)}</span></div>
            </div>
        </div>
        """

    yara_html = ""
    yara_hits = telemetry.get("yara_matches", [])
    if yara_hits:
        y_rows = "".join([
            f"<tr><td style='color:#e06c75; font-weight:600;'>{html.escape(str(y.get('rule', y) if isinstance(y, dict) else str(y)))}</td>"
            f"<td style='text-align:center;'><span class='badge' style='color:#e06c75;'>{html.escape(str(y.get('severity', 'HIGH')).upper() if isinstance(y, dict) else 'DETECTED')}</span></td>"
            f"<td>{html.escape(str(y.get('description', '')) if isinstance(y, dict) else '')}</td></tr>"
            for y in yara_hits
        ])
        yara_html = f"""
        <div style="font-weight: 600; margin-bottom: 8px; color: #e6edf3; font-size: 12px; text-transform: uppercase;">YARA Rule Detections</div>
        <table>
            <thead>
                <tr>
                    <th>Rule Name</th>
                    <th style="text-align:center;">Severity</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {y_rows}
            </tbody>
        </table>
        """

    resources_html = ""
    rsrcs = [r for r in telemetry.get("resources_info", []) if r.get("is_suspicious") or r.get("entropy", 0) > 6.5]
    if rsrcs:
        r_rows = "".join([
            f"<tr><td style='font-weight:600;'>{html.escape(str(r.get('type', '')))}</td>"
            f"<td style='font-family:monospace;'>{html.escape(str(r.get('id', '')))}</td>"
            f"<td style='text-align:right; font-family:monospace;'>{html.escape(str(r.get('size_hex', '')))}</td>"
            f"<td style='text-align:right; font-weight:600;'>{r.get('entropy', 0.0):.2f}</td>"
            f"<td style='text-align:center;'>{_get_status_badge(r.get('status', 'OK'))}</td></tr>"
            for r in rsrcs
        ])
        resources_html = f"""
        <div style="font-weight: 600; margin-bottom: 8px; color: #e6edf3; font-size: 12px; text-transform: uppercase;">PE Resource Tree (.rsrc Diagnostics)</div>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>ID / Name</th>
                    <th style="text-align:right;">Size</th>
                    <th style="text-align:right;">Entropy</th>
                    <th style="text-align:center;">Status</th>
                </tr>
            </thead>
            <tbody>
                {r_rows}
            </tbody>
        </table>
        """

    exports_html = ""
    exp = telemetry.get("exports_info")
    if exp:
        fwd = exp.get("forwarded_count", 0)
        tot = exp.get("total_exports", 0)
        sys_match = exp.get("is_system_dll_name", False)
        status_txt = "HIGH RISK (Known Hijackable System DLL Name)" if sys_match else "Standard DLL"
        exports_html = f"""
        <div class="findings-card" style="border-left: 3px solid {'#e06c75' if (fwd or sys_match) else '#282c34'}; margin-bottom: 20px;">
            <h3>Export Address Table (EAT) & DLL Hijacking Triage</h3>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:8px;">
                <div><span style="color:#5c6370; font-size:10px;">INTERNAL NAME:</span> <b>{html.escape(str(exp.get('internal_name') or 'None'))}</b></div>
                <div><span style="color:#5c6370; font-size:10px;">TOTAL EXPORTS:</span> <span>{tot}</span></div>
                <div><span style="color:#5c6370; font-size:10px;">FORWARDED PROXIES:</span> <b style="color:{'#e06c75' if fwd else '#abb2bf'};">{fwd}</b></div>
                <div><span style="color:#5c6370; font-size:10px;">SIDE-LOADING RISK:</span> <b style="color:{'#e06c75' if sys_match else '#98c379'};">{html.escape(status_txt)}</b></div>
            </div>
        </div>
        """

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>EntropyStrip - {html.escape(str(telemetry.get('filename', 'Unknown')))}</title>
<style>
    body {{
        background: #0f141c;
        color: #abb2bf;
        font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
        margin: 0;
        padding: 32px 20px;
        line-height: 1.45;
        font-size: 13px;
    }}
    .container {{
        max-width: 900px;
        margin: 0 auto;
    }}
    .header {{
        border-bottom: 1px solid #282c34;
        padding-bottom: 16px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: baseline;
    }}
    h1 {{
        font-size: 16px;
        margin: 0;
        color: #e6edf3;
        font-weight: 600;
        letter-spacing: 0.5px;
    }}
    .target-path {{
        color: #5c6370;
        font-size: 12px;
        margin-top: 4px;
        word-break: break-all;
    }}
    .meta-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 12px;
        margin-bottom: 24px;
    }}
    .meta-item {{
        background: #161b22;
        border: 1px solid #282c34;
        border-radius: 4px;
        padding: 10px 14px;
    }}
    .meta-label {{
        font-size: 10px;
        color: #5c6370;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 2px;
    }}
    .meta-val {{
        font-size: 12px;
        color: #abb2bf;
        word-break: break-all;
    }}
    .score-card {{
        background: #161b22;
        border: 1px solid #282c34;
        border-left: 3px solid {status_color};
        border-radius: 4px;
        padding: 16px;
        margin-bottom: 24px;
    }}
    .score-num {{
        font-size: 26px;
        font-weight: 700;
        color: {status_color};
    }}
    .verdict-tag {{
        display: inline-block;
        padding: 2px 8px;
        border-radius: 3px;
        font-size: 11px;
        font-weight: 600;
        margin-left: 8px;
        background: rgba(255, 255, 255, 0.05);
        color: {status_color};
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 24px;
        background: #161b22;
        border: 1px solid #282c34;
        border-radius: 4px;
        overflow: hidden;
    }}
    th, td {{
        padding: 8px 12px;
        text-align: left;
        border-bottom: 1px solid #21262d;
    }}
    th {{
        background: #1f242c;
        color: #e6edf3;
        font-weight: 600;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    tr:last-child td {{ border-bottom: none; }}
    .badge {{
        display: inline-block;
        padding: 2px 7px;
        border-radius: 3px;
        font-size: 10px;
        font-family: ui-monospace, monospace;
        font-weight: 600;
        background: #21262d;
        color: #8b949e;
    }}
    .findings-card {{
        background: #161b22;
        border: 1px solid #282c34;
        border-radius: 4px;
        padding: 14px 16px;
        margin-bottom: 20px;
    }}
    .findings-card h3 {{
        margin-top: 0;
        margin-bottom: 8px;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #e6edf3;
    }}
    ul {{
        margin: 0;
        padding-left: 18px;
        color: #abb2bf;
    }}
    li {{ margin-bottom: 4px; }}
    pre {{
        background: #090d13;
        border: 1px solid #21262d;
        padding: 12px;
        border-radius: 4px;
        overflow-x: auto;
        color: #abb2bf;
        font-size: 11px;
        line-height: 1.4;
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>EntropyStrip Triage Diagnostic</h1>
            <div class="target-path">{html.escape(str(telemetry.get('path', '')))}</div>
        </div>
        <div style="color: #5c6370; font-size: 11px;">v1.3.0</div>
    </div>

    <div class="meta-grid">
        <div class="meta-item">
            <div class="meta-label">SHA256</div>
            <div class="meta-val">{html.escape(str(sha256_val))}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Imphash</div>
            <div class="meta-val">{html.escape(str(imphash_val))}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">SSDEEP (Fuzzy Hash)</div>
            <div class="meta-val" style="font-size:10px;">{html.escape(str(fuzzy_val))}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Architecture</div>
            <div class="meta-val">{'Managed (.NET)' if telemetry.get('is_dotnet') else 'Native PE'} | {'Signed' if telemetry.get('is_signed') else 'Unsigned'}</div>
        </div>
    </div>

    <div class="score-card">
        <div style="display: flex; align-items: baseline;">
            <span class="score-num">{score}</span>
            <span style="color: #5c6370; font-size: 14px; margin-left: 4px;">/ 100</span>
            <span class="verdict-tag">{html.escape(str(telemetry.get('verdict', 'Unknown')))}</span>
        </div>
    </div>

    {bazaar_html}
    {yara_html}
    {exports_html}

    <div style="font-weight: 600; margin-bottom: 8px; color: #e6edf3; font-size: 12px; text-transform: uppercase;">Section Architecture & Entropy Strip</div>
    <table>
        <thead>
            <tr>
                <th>Section</th>
                <th style="text-align:right;">Virt Size</th>
                <th style="text-align:right;">Raw Size</th>
                <th style="text-align:right;">Entropy</th>
                <th style="text-align:center;">Perms</th>
                <th>Entropy Strip</th>
                <th style="text-align:center;">Status</th>
            </tr>
        </thead>
        <tbody>
            {sections_html}
        </tbody>
    </table>

    {resources_html}

    <div class="findings-card">
        <h3>Structural Findings & Anomalies</h3>
        <ul>{anomalies_html}</ul>
    </div>

    {f'''
    <div class="findings-card">
        <h3>Extracted Indicators of Compromise (IoCs)</h3>
        <ul>{indicators_html}</ul>
    </div>
    ''' if telemetry.get("indicators") else ''}

    {f'''
    <div style="font-weight: 600; margin-bottom: 8px; color: #e6edf3; font-size: 12px; text-transform: uppercase;">MITRE ATT&CK Mapping</div>
    <table>
        <thead>
            <tr>
                <th>Technique ID</th>
                <th>Technique Name</th>
                <th>Triggered By</th>
            </tr>
        </thead>
        <tbody>
            {mitre_html}
        </tbody>
    </table>
    ''' if mitre_html else ''}

    {f'''
    <div class="findings-card">
        <h3>Entry Point Disassembly Stub</h3>
        <pre>{html.escape(str(telemetry.get("ep_disasm", "")))}</pre>
    </div>
    ''' if telemetry.get("ep_disasm") else ''}

</div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_html)


def generate_directory_html_report(
    results: List[Dict[str, Any]],
    target_dir: str,
    output_path: str,
    yara_enabled: bool = False,
    bazaar_enabled: bool = False,
) -> None:
    """Generates a self-contained HTML triage dashboard for a directory of binaries."""
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    sorted_results = sorted(results, key=lambda x: x.get("threat_score", 0), reverse=True)
    total_count = len(sorted_results)
    crit_count = sum(1 for r in sorted_results if r.get("threat_score", 0) >= 70)
    susp_count = sum(1 for r in sorted_results if 35 <= r.get("threat_score", 0) < 70)
    clean_count = sum(1 for r in sorted_results if r.get("threat_score", 0) < 35)
    yara_hits_total = sum(len(r.get("yara_matches", [])) for r in sorted_results)
    bazaar_hits_total = sum(1 for r in sorted_results if r.get("bazaar_intel") and r["bazaar_intel"].get("status") == "malicious")

    rows_html = ""
    details_html = ""

    for idx, r in enumerate(sorted_results, 1):
        score = r.get("threat_score", 0)
        c = "#e06c75" if score >= 70 else ("#e5c07b" if score >= 35 else "#98c379")
        top_anomaly = r["anomalies"][0] if r.get("anomalies") else "Clean structure"
        sha256 = (r.get("hashes") or {}).get("sha256", "-")
        short_sha = sha256[:16] + "..." if len(sha256) > 16 else sha256

        wx_badge = (
            '<span class="badge" style="color:#e06c75; background:rgba(224,108,117,0.15);">YES</span>'
            if r.get("wx")
            else '<span class="badge">NO</span>'
        )
        overlay_badge = (
            '<span class="badge" style="color:#e06c75; background:rgba(224,108,117,0.15);">YES</span>'
            if r.get("has_overlay")
            else '<span class="badge">NO</span>'
        )
        dotnet_badge = (
            '<span class="badge" style="color:#61afef; background:rgba(97,175,239,0.15);">.NET</span>'
            if r.get("is_dotnet")
            else '<span class="badge">Native</span>'
        )

        rows_html += f"""
        <tr>
            <td style="color:#5c6370; text-align:right;">{idx}</td>
            <td style="font-weight:600;"><a href="#target-{idx}" style="color:#61afef; text-decoration:none;">{html.escape(r.get('filename', ''))}</a></td>
            <td style="text-align:center;"><span style="color:{c}; font-weight:700;">{score}</span></td>
            <td style="color:{c}; font-weight:600;">{html.escape(r.get('verdict', ''))}</td>
            <td style="text-align:center;">{wx_badge}</td>
            <td style="text-align:center;">{dotnet_badge}</td>
            <td style="text-align:center;">{overlay_badge}</td>
            <td style="color:#abb2bf; font-size:12px;">{html.escape(top_anomaly)}</td>
            <td style="font-family:monospace; font-size:11px; color:#5c6370;" title="{html.escape(sha256)}">{html.escape(short_sha)}</td>
        </tr>
        """

        # Build collapsible details section for each binary
        anom_list = "".join([f"<li>{html.escape(a)}</li>" for a in r.get("anomalies", [])]) or "<li>Clean structure.</li>"
        
        mitre_list = ""
        if r.get("mitre"):
            mitre_list = "<h4>MITRE ATT&CK</h4><ul>" + "".join(
                [f"<li><b>{html.escape(tid)}:</b> {html.escape(tname)}: <i>{html.escape(tdesc)}</i></li>" for tid, tname, tdesc in r["mitre"]]
            ) + "</ul>"

        indicators_list = ""
        if r.get("indicators"):
            indicators_list = "<h4>Indicators of Compromise</h4><ul>" + "".join(
                [f"<li><code>{html.escape(i)}</code></li>" for i in r["indicators"]]
            ) + "</ul>"

        # YARA section
        yara_section = ""
        yara_hits = r.get("yara_matches", [])
        if yara_hits:
            y_rows = "".join([
                f"<tr><td style='color:#e06c75; font-weight:600;'>{html.escape(str(y.get('rule', y) if isinstance(y, dict) else str(y)))}</td>"
                f"<td style='text-align:center;'><span class='badge' style='color:#e06c75;'>{html.escape(str(y.get('severity', 'HIGH')).upper() if isinstance(y, dict) else 'DETECTED')}</span></td>"
                f"<td>{html.escape(str(y.get('description', '')) if isinstance(y, dict) else '')}</td></tr>"
                for y in yara_hits
            ])
            yara_section = f"""
            <h4 style="margin:12px 0 4px 0; font-size:11px; color:#e06c75; text-transform:uppercase;">YARA Rule Detections</h4>
            <table style="margin-bottom:8px;">
                <thead><tr><th>Rule Name</th><th style="text-align:center;">Severity</th><th>Description</th></tr></thead>
                <tbody>{y_rows}</tbody>
            </table>
            """

        # MalwareBazaar section
        bazaar_section = ""
        bazaar = r.get("bazaar_intel")
        if bazaar and bazaar.get("status") == "malicious":
            vt = bazaar.get("virustotal") or {}
            vt_str = f"{vt.get('percent', 0.0):.1f}% ({vt.get('positives', 0)}/{vt.get('total', 0)})" if vt else "N/A"
            bazaar_section = f"""
            <div style="background:#1f242c; border-left:3px solid #e06c75; padding:8px 12px; margin:8px 0; border-radius:3px;">
                <b style="color:#e06c75;">MalwareBazaar Threat Intel (abuse.ch):</b> {html.escape(str(bazaar.get('signature', 'Unknown Threat')))}
                <span style="color:#5c6370; font-size:11px;"> | VT: {html.escape(vt_str)} | First seen: {html.escape(str(bazaar.get('first_seen', '-')))}</span>
            </div>
            """

        # Resource Tree section (.rsrc steganography / payload)
        rsrc_section = ""
        susp_rsrcs = [res for res in r.get("resources_info", []) if res.get("is_suspicious") or res.get("entropy", 0) > 6.5]
        if susp_rsrcs:
            r_rows = "".join([
                f"<tr><td style='font-weight:600;'>{html.escape(str(res.get('type', '')))}</td>"
                f"<td style='font-family:monospace;'>{html.escape(str(res.get('id', '')))}</td>"
                f"<td style='text-align:right;'>{res.get('entropy', 0.0):.2f}</td>"
                f"<td>{html.escape(str(res.get('status', 'OK')))}</td></tr>"
                for res in susp_rsrcs
            ])
            rsrc_section = f"""
            <h4 style="margin:12px 0 4px 0; font-size:11px; color:#e5c07b; text-transform:uppercase;">Resource Tree Anomaly (.rsrc Steganography / Payload)</h4>
            <table style="margin-bottom:8px;">
                <thead><tr><th>Type</th><th>ID</th><th style="text-align:right;">Entropy</th><th>Status / Findings</th></tr></thead>
                <tbody>{r_rows}</tbody>
            </table>
            """

        # Export table proxying
        export_section = ""
        exp_info = r.get("exports_info") or {}
        forwarded = exp_info.get("forwarded", [])
        if forwarded or exp_info.get("is_masquerading"):
            f_rows = "".join([
                f"<tr><td style='font-family:monospace;'>{html.escape(str(f.get('function', '')))}</td>"
                f"<td style='font-family:monospace; color:#e5c07b;'>{html.escape(str(f.get('forward_target', '')))}</td></tr>"
                for f in forwarded
            ])
            masq_note = f"<div style='color:#e06c75; font-size:11px; margin-bottom:4px;'>Masquerading Anomaly: Exports match system DLL ({exp_info.get('masqueraded_dll', '')}) - Proxying Risk</div>" if exp_info.get("is_masquerading") else ""
            export_section = f"""
            <h4 style="margin:12px 0 4px 0; font-size:11px; color:#e5c07b; text-transform:uppercase;">Export Forwarding &amp; Proxying (EAT)</h4>
            {masq_note}
            <table style="margin-bottom:8px;">
                <thead><tr><th>Function Name</th><th>Forwarded Target DLL</th></tr></thead>
                <tbody>{f_rows}</tbody>
            </table>
            """

        fuzzy_info = f" &nbsp;|&nbsp; SSDEEP: <span style='font-family:monospace; color:#61afef;'>{html.escape(r.get('fuzzy_hash') or '')}</span>" if r.get("fuzzy_hash") else ""

        details_html += f"""
        <div id="target-{idx}" class="findings-card" style="margin-top:16px;">
            <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:8px;">
                <h3 style="margin:0; font-size:14px; color:#e6edf3;">#{idx}. {html.escape(r.get('filename', ''))} <span style="color:{c}; font-size:12px;">[{score}/100 - {html.escape(r.get('verdict', ''))}]</span></h3>
                <span style="font-size:11px; color:#5c6370;">{html.escape(r.get('path', ''))}</span>
            </div>
            <div style="font-size:11px; color:#5c6370; margin-bottom:8px; font-family:monospace;">SHA256: {html.escape(sha256)}{fuzzy_info}</div>
            {bazaar_section}
            {yara_section}
            {rsrc_section}
            {export_section}
            <h4 style="margin:8px 0 4px 0; font-size:11px; color:#e6edf3; text-transform:uppercase;">Findings</h4>
            <ul>{anom_list}</ul>
            {indicators_list}
            {mitre_list}
        </div>
        """

    clusters_html = ""
    clustered = {}
    for r in sorted_results:
        cid = r.get("cluster_id")
        if cid:
            clustered.setdefault(cid, []).append(r)

    if clustered:
        c_items = "".join([
            f"<div style='margin-bottom:8px;'><b style='color:#61afef;'>{html.escape(cid)}</b> ({len(members)} binaries): "
            f"<span style='color:#abb2bf;'>{', '.join([html.escape(m.get('filename', '')) for m in members])}</span></div>"
            for cid, members in clustered.items()
        ])
        clusters_html = f"""
        <div class="findings-card" style="border-left: 3px solid #61afef; margin-bottom: 24px;">
            <h4 style="color:#61afef; margin-top:0;">Automated Campaign Clusters (Fuzzy Hash Similarity &ge; 70%)</h4>
            {c_items}
        </div>
        """

    yara_card = ""
    if yara_enabled or yara_hits_total > 0:
        y_color = "#e06c75" if yara_hits_total > 0 else "#98c379"
        yara_card = f"""
        <div class="summary-card" style="border-left: 3px solid {y_color};">
            <div class="summary-val" style="color: {y_color};">{yara_hits_total}</div>
            <div class="summary-label">YARA Detections</div>
        </div>
        """

    bazaar_card = ""
    if bazaar_enabled or bazaar_hits_total > 0:
        b_color = "#e06c75" if bazaar_hits_total > 0 else "#98c379"
        bazaar_card = f"""
        <div class="summary-card" style="border-left: 3px solid {b_color};">
            <div class="summary-val" style="color: {b_color};">{bazaar_hits_total}</div>
            <div class="summary-label">Threat Intel Hits</div>
        </div>
        """

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>EntropyStrip - Incident Triage Leaderboard</title>
<style>
    body {{
        background: #0f141c;
        color: #abb2bf;
        font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
        margin: 0;
        padding: 32px 20px;
        line-height: 1.45;
        font-size: 13px;
    }}
    .container {{
        max-width: 1100px;
        margin: 0 auto;
    }}
    .header {{
        border-bottom: 1px solid #282c34;
        padding-bottom: 16px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: baseline;
    }}
    h1 {{
        font-size: 18px;
        margin: 0;
        color: #e6edf3;
        font-weight: 600;
        letter-spacing: 0.5px;
    }}
    .target-path {{
        color: #5c6370;
        font-size: 12px;
        margin-top: 4px;
        word-break: break-all;
    }}
    .summary-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
        margin-bottom: 24px;
    }}
    .summary-card {{
        background: #161b22;
        border: 1px solid #282c34;
        border-radius: 4px;
        padding: 14px 16px;
    }}
    .summary-val {{
        font-size: 24px;
        font-weight: 700;
        margin-bottom: 4px;
    }}
    .summary-label {{
        font-size: 11px;
        color: #5c6370;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 24px;
        background: #161b22;
        border: 1px solid #282c34;
        border-radius: 4px;
        overflow: hidden;
    }}
    th, td {{
        padding: 8px 12px;
        text-align: left;
        border-bottom: 1px solid #21262d;
    }}
    th {{
        background: #1f242c;
        color: #e6edf3;
        font-weight: 600;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    tr:last-child td {{ border-bottom: none; }}
    .badge {{
        display: inline-block;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 10px;
        font-family: ui-monospace, monospace;
        font-weight: 600;
        background: #21262d;
        color: #8b949e;
    }}
    .findings-card {{
        background: #161b22;
        border: 1px solid #282c34;
        border-radius: 4px;
        padding: 14px 16px;
        margin-bottom: 16px;
    }}
    .findings-card h4 {{
        margin: 8px 0 4px 0;
        font-size: 11px;
        color: #e6edf3;
        text-transform: uppercase;
    }}
    ul {{
        margin: 0;
        padding-left: 18px;
        color: #abb2bf;
    }}
    li {{ margin-bottom: 4px; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>Incident Triage Leaderboard</h1>
            <div class="target-path">{html.escape(target_dir)}</div>
        </div>
        <div style="color: #5c6370; font-size: 11px;">v1.3.0</div>
    </div>

    <div class="summary-grid">
        <div class="summary-card">
            <div class="summary-val" style="color: #e6edf3;">{total_count}</div>
            <div class="summary-label">Total Binaries</div>
        </div>
        <div class="summary-card" style="border-left: 3px solid #e06c75;">
            <div class="summary-val" style="color: #e06c75;">{crit_count}</div>
            <div class="summary-label">Critical Risk (&ge;70)</div>
        </div>
        <div class="summary-card" style="border-left: 3px solid #e5c07b;">
            <div class="summary-val" style="color: #e5c07b;">{susp_count}</div>
            <div class="summary-label">Suspicious (35-69)</div>
        </div>
        <div class="summary-card" style="border-left: 3px solid #98c379;">
            <div class="summary-val" style="color: #98c379;">{clean_count}</div>
            <div class="summary-label">Clean / Low Risk (&lt;35)</div>
        </div>
        {yara_card}
        {bazaar_card}
    </div>

    {clusters_html}

    <div style="font-weight: 600; margin-bottom: 8px; color: #e6edf3; font-size: 12px; text-transform: uppercase;">Ranked Binaries</div>
    <table>
        <thead>
            <tr>
                <th style="text-align:right;">#</th>
                <th>Binary</th>
                <th style="text-align:center;">Score</th>
                <th>Verdict</th>
                <th style="text-align:center;">W+X</th>
                <th style="text-align:center;">Format</th>
                <th style="text-align:center;">Overlay</th>
                <th>Primary Flag</th>
                <th>SHA256</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>

    <div style="font-weight: 600; margin-top: 32px; margin-bottom: 12px; color: #e6edf3; font-size: 12px; text-transform: uppercase;">Binary Diagnostics Detail</div>
    {details_html}

</div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_html)
