"""
Rich terminal UI rendering: section architecture tables, heatmaps, and diagnostic panels.
"""

from typing import List, Dict, Any, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

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
) -> None:
    """Renders comprehensive CLI triage dashboard."""
    console.print(f"\n[bold]Target:[/bold] {target_path}")
    if deep and hashes:
        console.print(f"[dim]SHA256: {hashes.get('sha256', '-')}[/dim]")
        if imphash_val:
            console.print(f"[dim]Imphash: {imphash_val}[/dim]")

    console.print(sections_table)

    score_panel_text = (
        f"[bold {verdict_color}]Score: {threat_score}/100[/bold {verdict_color}]\n"
        f"[bold]Verdict:[/bold] [{verdict_color}]{verdict_text}[/{verdict_color}]\n"
        f"[bold]Format:[/bold] {'Managed (.NET)' if is_dotnet else 'Native PE'} | "
        f"[bold]Signature:[/bold] {'Signed' if is_signed else 'Unsigned'}\n\n"
        f"[underline]Findings:[/underline]\n"
        + ("\n".join([f"• [{verdict_color}]{a}[/{verdict_color}]" for a in anomalies]) if anomalies else "• Clean structure.")
    )
    if indicators:
        score_panel_text += "\n\n[underline]Extracted Indicators:[/underline]\n" + "\n".join(
            [f"• [cyan]{ind}[/cyan]" for ind in indicators]
        )

    console.print("\n", Panel(score_panel_text, title="Triage Diagnostic", border_style=verdict_color))

    if deep:
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
                mitre_table.add_row(tid, tname, tdesc)
            console.print(mitre_table)

        if ep_disasm:
            console.print("\n", Panel(ep_disasm, title="Entry Point Disassembly Stub", border_style="dim"))


def render_triage_leaderboard(results: List[Dict[str, Any]]) -> None:
    """Renders directory triage leaderboard ranked by threat score."""
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
        verdict_str = f"[{r['color']}]{r['verdict']}[/{r['color']}]"
        wx_str = "[bold red]YES[/bold red]" if r["wx"] else "[dim]NO[/dim]"
        dotnet_str = "[cyan]YES[/cyan]" if r["is_dotnet"] else "[dim]NO[/dim]"
        overlay_str = "[bold red]YES[/bold red]" if r["has_overlay"] else "[dim]NO[/dim]"
        top_anomaly = r["anomalies"][0] if r["anomalies"] else "None"

        triage_table.add_row(
            str(idx),
            r["filename"],
            score_str,
            wx_str,
            dotnet_str,
            overlay_str,
            verdict_str,
            top_anomaly,
        )

    console.print(triage_table)
    console.print(f"\n[green][+] Completed:[/green] Triaged {len(results)} binaries.")
