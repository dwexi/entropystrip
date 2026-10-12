"""
Standalone dark-mode HTML report generator with strict output sanitization.
"""

import os
import html
from typing import Dict, Any


def generate_html_report(telemetry: Dict[str, Any], output_path: str) -> None:
    """Generates a self-contained HTML triage report."""
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    status_color = (
        "#e06c75"
        if telemetry["threat_score"] >= 70
        else ("#e5c07b" if telemetry["threat_score"] >= 35 else "#98c379")
    )

    sha256_val = telemetry.get("hashes", {}).get("sha256", "-")
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

        sections_html += f"""
        <tr>
            <td style="font-family:ui-monospace,monospace; font-weight:600;">{html.escape(s['name'])}</td>
            <td style="font-family:ui-monospace,monospace; text-align:right;">{s['virt_size']}</td>
            <td style="font-family:ui-monospace,monospace; text-align:right;">{s['raw_size']}</td>
            <td style="font-family:ui-monospace,monospace; text-align:right; font-weight:600;">{s['entropy']:.2f}</td>
            <td style="text-align:center;"><span class="badge">{html.escape(str(s['perms']))}</span></td>
            <td style="letter-spacing:1px;">{heatmap_blocks}</td>
            <td style="text-align:center; font-family:ui-monospace,monospace; font-size:11px;">{html.escape(str(s['status']))}</td>
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
                f"<tr><td style='font-family:monospace; font-weight:600;'>{html.escape(str(tid))}</td>"
                f"<td style='font-weight:600;'>{html.escape(str(tname))}</td>"
                f"<td>{html.escape(str(tdesc))}</td></tr>"
            )

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>entropystrip - {html.escape(telemetry['filename'])}</title>
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
        padding: 1px 6px;
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
            <div class="target-path">{html.escape(telemetry['path'])}</div>
        </div>
        <div style="color: #5c6370; font-size: 11px;">v1.2.1</div>
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
            <div class="meta-val">{'Managed (.NET)' if telemetry['is_dotnet'] else 'Native PE'} | {'Signed' if telemetry['is_signed'] else 'Unsigned'}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Imports</div>
            <div class="meta-val">{telemetry['total_imports']} Functions</div>
        </div>
    </div>

    <div class="score-card">
        <div style="display: flex; align-items: baseline;">
            <span class="score-num">{telemetry['threat_score']}</span>
            <span style="color: #5c6370; font-size: 14px; margin-left: 4px;">/ 100</span>
            <span class="verdict-tag">{html.escape(telemetry['verdict'])}</span>
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
        <pre>{html.escape(telemetry["ep_disasm"])}</pre>
    </div>
    ''' if telemetry.get("ep_disasm") else ''}

</div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_html)
