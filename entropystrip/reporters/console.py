"""
Rich terminal UI rendering: section architecture tables, heatmaps, and diagnostic panels.
"""

from typing import List, Dict, Any, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape

console = Console()


def render_console_report(
    target_path: str,
    sections_table: Table,
    threat_score: int,
    verdict_text: str,
    verdict_color: str,
    is_dotnet: bool,
    is_signed: bool,
    anomalies: List[str],
    indicators: List[str],
    mitre_techniques: Optional[List[Tuple[str, str, str]]] = None,
    ep_disasm: Optional[str] = None,
    hashes: Optional[Dict[str, str]] = None,
    imphash_val: Optional[str] = None,
    deep: bool = False,
    tls_callbacks: Optional[List[Dict[str, Any]]] = None,
    fuzzy_hash: Optional[str] = None,
    bazaar_intel: Optional[Dict[str, Any]] = None,
    yara_matches: Optional[List[Dict[str, Any]]] = None,
    resources_info: Optional[List[Dict[str, Any]]] = None,
    exports_info: Optional[Dict[str, Any]] = None,
) -> None:
    """Renders comprehensive CLI triage dashboard."""
    console.print(f"\n[bold]Target:[/bold] {escape(target_path)}")
    if deep and hashes:
        console.print(f"[dim]SHA256: {escape(str(hashes.get('sha256', '-')))}[/dim]")
        if imphash_val:
            console.print(f"[dim]Imphash: {escape(str(imphash_val))}[/dim]")
        if fuzzy_hash:
            console.print(f"[dim]SSDEEP:  {escape(str(fuzzy_hash))}[/dim]")

    console.print(sections_table)

    score_panel_text = (
        f"[bold {verdict_color}]Score: {threat_score}/100[/bold {verdict_color}]\n"
        f"[bold]Verdict:[/bold] [{verdict_color}]{escape(verdict_text)}[/{verdict_color}]\n"
        f"[bold]Format:[/bold] {'Managed (.NET)' if is_dotnet else 'Native PE'} | "
        f"[bold]Signature:[/bold] {'Signed' if is_signed else 'Unsigned'}\n\n"
        f"[underline]Findings:[/underline]\n"
        + ("\n".join([f"• [{verdict_color}]{escape(a)}[/{verdict_color}]" for a in anomalies]) if anomalies else "• Clean structure.")
    )
    if indicators:
        score_panel_text += "\n\n[underline]Extracted Indicators:[/underline]\n" + "\n".join(
            [f"• [cyan]{escape(ind)}[/cyan]" for ind in indicators]
        )

    console.print("\n", Panel(score_panel_text, title="Triage Diagnostic", border_style=verdict_color))

    # MalwareBazaar Threat Intel Panel
    if bazaar_intel:
        if bazaar_intel.get("status") == "malicious":
            bazaar_text = (
                f"[bold red]Malware Signature:[/bold red] {escape(str(bazaar_intel.get('signature', 'Unknown Threat')))}\n"
                f"[bold]Tags:[/bold] {escape(', '.join(bazaar_intel.get('tags', [])))}\n"
                f"[bold]First Seen:[/bold] {escape(str(bazaar_intel.get('first_seen', '-')))} | "
                f"[bold]Reporter:[/bold] @{escape(str(bazaar_intel.get('reporter', '-')))}"
            )
            vt = bazaar_intel.get("virustotal")
            if vt and vt.get("percent") is not None:
                bazaar_text += f"\n[bold]VirusTotal Detection:[/bold] [bold red]{vt['percent']:.1f}%[/bold red] ({vt.get('positives')}/{vt.get('total')})"
            console.print(Panel(bazaar_text, title="MalwareBazaar Threat Intelligence (abuse.ch)", border_style="bold red"))
        elif bazaar_intel.get("status") == "not_found":
            console.print(Panel("[dim]Hash not found in MalwareBazaar dataset (0 community reports).[/dim]", title="MalwareBazaar Threat Intelligence", border_style="dim"))

    # YARA Rules Matches Table
    if yara_matches:
        yara_table = Table(title="YARA Rule Detections", show_header=True, header_style="bold red")
        yara_table.add_column("Rule", style="bold red")
        yara_table.add_column("Severity", justify="center")
        yara_table.add_column("Description", style="dim")
        yara_table.add_column("MITRE", style="cyan", justify="center")
        for y in yara_matches:
            yara_table.add_row(
                escape(str(y.get("rule", ""))),
                escape(str(y.get("severity", "medium")).upper()),
                escape(str(y.get("description", ""))),
                escape(str(y.get("mitre") or "-")),
            )
        console.print(yara_table)
    elif deep and yara_matches is not None:
        console.print("[dim]YARA Signature Engine: Active - 0 rule matches (Threats: CobaltStrike, Ransomware, ReflectiveLoader, EggHunter).[/dim]")

    # Resource Tree Breakdown (.rsrc)
    if resources_info:
        rsrc_rows = [res for res in resources_info if deep or res.get("is_suspicious") or res.get("entropy", 0) > 6.5]
        if rsrc_rows:
            rsrc_table = Table(title="PE Resource Tree (.rsrc Diagnostics)", show_header=True, header_style="bold cyan")
            rsrc_table.add_column("Type", style="bold")
            rsrc_table.add_column("Resource ID", style="dim")
            rsrc_table.add_column("Size", justify="right")
            rsrc_table.add_column("Entropy", justify="right")
            rsrc_table.add_column("Status", justify="center")
            for res in rsrc_rows:
                st_style = "bold red" if res.get("is_suspicious") else ("yellow" if res.get("status") == "SUSPICIOUS" else "green")
                rsrc_table.add_row(
                    escape(str(res.get("type", ""))),
                    escape(str(res.get("id", ""))),
                    escape(str(res.get("size_hex", ""))),
                    f"{res.get('entropy', 0.0):.2f}",
                    f"[{st_style}]{escape(str(res.get('status', 'OK')))}[/{st_style}]",
                )
            console.print(rsrc_table)

    # Export Address Table & Side-Loading
    if exports_info:
        fwd = exports_info.get("forwarded_count", 0)
        tot = exports_info.get("total_exports", 0)
        sys_match = exports_info.get("is_system_dll_name", False)
        exp_border = "bold red" if (fwd > 0 or sys_match) else "dim"
        exp_text = (
            f"[bold]DLL Internal Name:[/bold] {escape(str(exports_info.get('internal_name') or 'None'))}\n"
            f"[bold]Total Exports:[/bold] {tot} | [bold]Forwarded Proxy Exports:[/bold] [{'bold red' if fwd else 'dim'}]{fwd}[/{'bold red' if fwd else 'dim'}]\n"
            f"[bold]Side-Loading Risk:[/bold] [{'bold red' if sys_match else 'green'}]{'HIGH (System DLL Name Match)' if sys_match else 'Low / Standard'}[/{'bold red' if sys_match else 'green'}]"
        )
        if exports_info.get("sample_exports"):
            exp_text += f"\n[dim]Exported APIs: {escape(', '.join(exports_info['sample_exports'][:10]))}[/dim]"
        console.print(Panel(exp_text, title="Export Address Table (EAT) & DLL Hijacking Triage", border_style=exp_border))

    if deep:
        if tls_callbacks:
            tls_table = Table(
                title="TLS Callbacks (Pre-Entrypoint Execution)",
                show_header=True,
                header_style="bold yellow",
            )
            tls_table.add_column("Index", style="dim", justify="right")
            tls_table.add_column("Virtual Address (VA)", style="bold cyan")
            tls_table.add_column("RVA", justify="center")
            tls_table.add_column("File Offset", justify="center")
            for cb in tls_callbacks:
                tls_table.add_row(
                    str(cb.get("index", "-")),
                    escape(str(cb.get("va", "-"))),
                    escape(str(cb.get("rva", "-"))),
                    escape(str(cb.get("offset", "-"))),
                )
            console.print(tls_table)

        if mitre_techniques:
            mitre_table = Table(
                title="MITRE ATT&CK Adversary Techniques",
                show_header=True,
                header_style="bold magenta",
            )
            mitre_table.add_column("Technique ID", style="bold cyan", justify="center")
            mitre_table.add_column("Technique Name", style="bold")
            mitre_table.add_column("Triggered By", style="dim")
            for tid, tname, tdesc in mitre_techniques:
                mitre_table.add_row(escape(tid), escape(tname), escape(tdesc))
            console.print(mitre_table)

        if ep_disasm:
            console.print("\n", Panel(escape(ep_disasm), title="Entry Point Disassembly Stub", border_style="dim"))


def render_triage_leaderboard(
    results: List[Dict[str, Any]],
    clusters: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    yara_enabled: bool = False,
    bazaar_enabled: bool = False,
) -> None:
    """Renders directory triage leaderboard ranked by threat score with campaign clusters."""
    triage_table = Table(
        title="Incident Triage Leaderboard (Ranked by Threat Score)",
        show_header=True,
        header_style="bold magenta",
    )
    triage_table.add_column("Rank", style="dim", justify="right")
    triage_table.add_column("Binary", style="bold cyan")
    triage_table.add_column("Score", justify="center")
    triage_table.add_column("W+X", justify="center")
    triage_table.add_column(".NET", justify="center")
    triage_table.add_column("Overlay", justify="center")
    triage_table.add_column("Verdict", justify="center")
    triage_table.add_column("Primary Flag", style="dim")

    for idx, r in enumerate(results, 1):
        score_str = f"[{r['color']}]{r['threat_score']}[/{r['color']}]"
        verdict_str = f"[{r['color']}]{escape(r['verdict'])}[/{r['color']}]"
        wx_str = "[bold red]YES[/bold red]" if r.get("wx") else "[dim]NO[/dim]"
        dotnet_str = "[cyan]YES[/cyan]" if r.get("is_dotnet") else "[dim]NO[/dim]"
        overlay_str = "[bold red]YES[/bold red]" if r.get("has_overlay") else "[dim]NO[/dim]"
        top_anomaly = escape(r["anomalies"][0]) if r.get("anomalies") else "None"

        triage_table.add_row(
            str(idx),
            escape(r["filename"]),
            score_str,
            wx_str,
            dotnet_str,
            overlay_str,
            verdict_str,
            top_anomaly,
        )

    console.print(triage_table)

    if clusters:
        console.print("\n[bold cyan]Automated Campaign Clusters (Fuzzy Hash Similarity >= 70%):[/bold cyan]")
        for c_name, members in clusters.items():
            names = ", ".join([escape(m["filename"]) for m in members])
            console.print(f"  • [bold magenta]{escape(str(c_name))}[/bold magenta] ({len(members)} binaries): [dim]{names}[/dim]")

    console.print(f"\n[green][+] Completed:[/green] Triaged {len(results)} binaries.")

    if yara_enabled:
        yara_matches_count = sum(len(r.get("yara_matches", [])) for r in results)
        if yara_matches_count > 0:
            console.print(f"  • [bold red]YARA Threat Detections:[/bold red] {yara_matches_count} matching rule(s) flagged.")
        else:
            console.print("  • [dim]YARA Signature Scan: Active (0 detections across triaged binaries).[/dim]")

    if bazaar_enabled:
        bazaar_hits = sum(1 for r in results if r.get("bazaar_intel") and r["bazaar_intel"].get("status") == "malicious")
        if bazaar_hits > 0:
            console.print(f"  • [bold red]MalwareBazaar Hits:[/bold red] {bazaar_hits} confirmed malicious sample(s).")
        else:
            console.print("  • [dim]MalwareBazaar Threat Intel: Active (0 matches in abuse.ch dataset).[/dim]")
