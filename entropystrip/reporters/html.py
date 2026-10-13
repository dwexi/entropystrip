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

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
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
        <div style="color: #5c6370; font-size: 11px;">v1.2.2</div>
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
            <div class="meta-label">Architecture</div>
            <div class="meta-val">{'Managed (.NET)' if telemetry.get('is_dotnet') else 'Native PE'} | {'Signed' if telemetry.get('is_signed') else 'Unsigned'}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Imports</div>
            <div class="meta-val">{telemetry.get('total_imports', 0)} Functions</div>
        </div>
    </div>

    <div class="score-card">
        <div style="display: flex; align-items: baseline;">
            <span class="score-num">{score}</span>
            <span style="color: #5c6370; font-size: 14px; margin-left: 4px;">/ 100</span>
            <span class="verdict-tag">{html.escape(str(telemetry.get('verdict', 'Unknown')))}</span>
        </div>
    </div>

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


def generate_directory_html_report(results: List[Dict[str, Any]], target_dir: str, output_path: str) -> None:
    """Generates a self-contained HTML triage dashboard for a directory of binaries."""
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    sorted_results = sorted(results, key=lambda x: x.get("threat_score", 0), reverse=True)
    total_count = len(sorted_results)
    crit_count = sum(1 for r in sorted_results if r.get("threat_score", 0) >= 70)
    susp_count = sum(1 for r in sorted_results if 35 <= r.get("threat_score", 0) < 70)
    clean_count = sum(1 for r in sorted_results if r.get("threat_score", 0) < 35)

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
                [f"<li><b>{html.escape(tid)}:</b> {html.escape(tname)} &mdash; <i>{html.escape(tdesc)}</i></li>" for tid, tname, tdesc in r["mitre"]]
            ) + "</ul>"

        indicators_list = ""
        if r.get("indicators"):
            indicators_list = "<h4>Indicators of Compromise</h4><ul>" + "".join(
                [f"<li><code>{html.escape(i)}</code></li>" for i in r["indicators"]]
            ) + "</ul>"

        details_html += f"""
        <div id="target-{idx}" class="findings-card" style="margin-top:16px;">
            <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:8px;">
                <h3 style="margin:0; font-size:14px; color:#e6edf3;">#{idx}. {html.escape(r.get('filename', ''))} <span style="color:{c}; font-size:12px;">[{score}/100 - {html.escape(r.get('verdict', ''))}]</span></h3>
                <span style="font-size:11px; color:#5c6370;">{html.escape(r.get('path', ''))}</span>
            </div>
            <div style="font-size:11px; color:#5c6370; margin-bottom:8px; font-family:monospace;">SHA256: {html.escape(sha256)}</div>
            <h4 style="margin:8px 0 4px 0; font-size:11px; color:#e6edf3; text-transform:uppercase;">Findings</h4>
            <ul>{anom_list}</ul>
            {indicators_list}
            {mitre_list}
        </div>
        """

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
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
        <div style="color: #5c6370; font-size: 11px;">v1.2.2</div>
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
    </div>

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
