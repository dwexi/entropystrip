"""
CLI argument parser and entry point for EntropyStrip.
"""

import sys
import os
import argparse
import ctypes

try:
    from .reporters.console import console
    from .core import analyze_single_file, scan_directory
    from .installer import is_installed_globally, install_globally, uninstall_globally, check_existing_install
    from . import __version__
except (ImportError, ValueError):
    from entropystrip.reporters.console import console
    from entropystrip.core import analyze_single_file, scan_directory
    from entropystrip.installer import is_installed_globally, install_globally, uninstall_globally, check_existing_install
    from entropystrip import __version__

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BANNER = r"""
___________       __                               _________ __         .__        
\_   _____/ _____/  |________  ____ ______ ___.__./   _____//  |________|__|_____  
 |    __)_ /    \   __\_  __ \/  _ \\____ <   |  |\_____  \\   __\_  __ \  \____ \ 
 |        \   |  \  |  |  | \(  <_> )  |_> >___  |/        \|  |  |  | \/  |  |_> >
/_______  /___|  /__|  |__|   \____/|   __// ____/_______  /|__|  |__|  |__|   __/ 
        \/     \/                   |__|   \/            \/                |__|    
"""


def is_explorer_launched() -> bool:
    """
    Returns True if the process was launched directly from Windows Explorer
    (e.g. double-click or drag-and-drop onto the .exe) in a dedicated console window.
    Returns False if launched inside an existing interactive terminal (PowerShell, CMD, bash).
    """
    if sys.platform != "win32":
        return False

    try:
        import psutil
        p = psutil.Process(os.getpid())
        # Walk up process ancestry (self -> pyinstaller bootloader -> parent)
        for _ in range(4):
            p = p.parent()
            if not p:
                break
            name = p.name().lower()
            if any(sh in name for sh in ("cmd", "powershell", "pwsh", "bash", "zsh", "wt", "windowsterminal")):
                return False
            if "explorer" in name:
                return True
    except Exception:
        pass

    try:
        if sys.stdin and sys.stdin.isatty():
            p_list = (ctypes.c_uint * 4)()
            count = ctypes.windll.kernel32.GetConsoleProcessList(p_list, 4)
            # PyInstaller onefile has 2 processes in dedicated console (bootloader + child)
            is_frozen = getattr(sys, "frozen", False)
            return count <= (2 if is_frozen else 1)
    except Exception:
        pass

    return False


def pause_for_user(prompt: str = "\nPress Enter to exit...") -> None:
    """Pauses execution until the user presses Enter."""
    try:
        input(prompt)
    except (KeyboardInterrupt, EOFError):
        pass


class StandaloneArgumentParser(argparse.ArgumentParser):
    """Custom parser that pauses before exit if running in an explorer-allocated console."""

    def exit(self, status: int = 0, message: str = None) -> None:
        if message:
            self._print_message(message, sys.stderr)
        if is_explorer_launched():
            pause_for_user("\nPress Enter to exit...")
        sys.exit(status)


def run_interactive_menu() -> None:
    """
    Interactive triage mode for Windows Explorer double-clicks.
    Offers global PATH registration, then provides the interactive forensic scanner.
    """
    if sys.platform == "win32":
        is_installed, install_type, exe_p = check_existing_install()
        if is_installed:
            if install_type == "python":
                console.print("[bold green][✓] EntropyStrip is already available globally in your PATH (via Python / pip).[/bold green]\n")
            else:
                console.print(f"[bold green][✓] EntropyStrip v{__version__} is installed globally in your Windows PATH.[/bold green]\n")
        else:
            console.print("[bold yellow]EntropyStrip is not registered in your Windows PATH.[/bold yellow]")
            try:
                choice = input("Do you want to install EntropyStrip to your Windows PATH? [Y/n]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                choice = "n"

            if choice in ("", "y", "yes"):
                install_globally()
            else:
                console.print("[dim]Installation skipped.[/dim]\n")

    console.print("[bold cyan]Interactive PE Forensic Triage Engine[/bold cyan]")
    console.print("  * Drag and drop an executable (.exe / .dll) or directory into this window, or paste path.\n")

    try:
        target_input = input("Target path to scan (or press Enter to exit): ").strip().strip('"\'')
    except (KeyboardInterrupt, EOFError):
        return

    if not target_input:
        return

    clean_target = os.path.abspath(os.path.normpath(target_input))
    if not os.path.exists(clean_target):
        console.print(f"[red]Error: Target not found -> {target_input}[/red]")
        pause_for_user("\nPress Enter to exit...")
        return

    is_dir = os.path.isdir(clean_target)

    # Prompt user for scan options
    recursive = False
    if is_dir:
        try:
            r_ans = input("Scan subdirectories recursively (-r)? [Y/n]: ").strip().lower()
            recursive = r_ans not in ("n", "no")
        except (KeyboardInterrupt, EOFError):
            pass

    deep = False
    try:
        d_ans = input("Enable deep forensic triage (--deep: MITRE mapping & disassembly)? [Y/n]: ").strip().lower()
        deep = d_ans not in ("n", "no")
    except (KeyboardInterrupt, EOFError):
        pass

    dump = False
    try:
        dump_ans = input("Carve high-entropy payloads (--dump)? [y/N]: ").strip().lower()
        dump = dump_ans in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        pass

    html_out = None
    try:
        html_ans = input("Generate standalone HTML report? [y/N]: ").strip().lower()
        if html_ans in ("y", "yes"):
            base_name = os.path.basename(clean_target) or "triage"
            html_out = f"{base_name}_report.html"
            console.print(f"[dim]HTML report will be saved to: {html_out}[/dim]")
    except (KeyboardInterrupt, EOFError):
        pass

    console.print()
    if is_dir:
        scan_directory(
            clean_target,
            recursive=recursive,
            dump_payloads=dump,
            html_out=html_out,
            deep=deep,
        )
    else:
        analyze_single_file(
            clean_target,
            dump_payloads=dump,
            quiet=False,
            html_out=html_out,
            deep=deep,
        )

    pause_for_user("\nScan complete. Press Enter to exit...")


def main() -> None:
    console.print(BANNER, style="cyan")

    # If double-clicked in Windows Explorer with no arguments, launch interactive mode
    if len(sys.argv) == 1 and is_explorer_launched():
        run_interactive_menu()
        return

    parser = StandaloneArgumentParser(
        prog="entropystrip",
        description="EntropyStrip: PE De-obfuscator, Shannon Entropy Radar, and Incident Triage Engine",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show program's version number and exit",
    )
    parser.add_argument("target", nargs="?", default=None, help="Path to Windows executable (.exe / .dll) or directory")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan subdirectories")
    parser.add_argument("--dump", action="store_true", help="Carve high-entropy payloads to extracted_payloads/")
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Deep forensic triage: MITRE ATT&CK mapping, entry point disassembly, and hashes",
    )
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive triage wizard")
    parser.add_argument("--install", action="store_true", help="Install EntropyStrip globally to Windows PATH")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall EntropyStrip from Windows PATH")
    parser.add_argument("--html", help="Path to write HTML report")
    parser.add_argument("--json", help="Path to write JSON telemetry")
    args = parser.parse_args()

    if args.install:
        install_globally()
        if is_explorer_launched():
            pause_for_user()
        return

    if args.uninstall:
        uninstall_globally()
        if is_explorer_launched():
            pause_for_user()
        return

    if args.interactive:
        run_interactive_menu()
        return

    if not args.target:
        parser.print_help()
        if is_explorer_launched():
            pause_for_user()
        sys.exit(0)

    clean_target = os.path.abspath(os.path.normpath(args.target.strip().strip('"\'')))

    if os.path.isdir(clean_target):
        scan_directory(
            clean_target,
            recursive=args.recursive,
            dump_payloads=args.dump,
            html_out=args.html,
            json_out=args.json,
            deep=args.deep,
        )
    else:
        analyze_single_file(
            clean_target,
            dump_payloads=args.dump,
            quiet=False,
            html_out=args.html,
            json_out=args.json,
            deep=args.deep,
        )

    if is_explorer_launched():
        pause_for_user("\nScan complete. Press Enter to exit...")


if __name__ == "__main__":
    main()

