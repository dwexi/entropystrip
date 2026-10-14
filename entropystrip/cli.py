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
    from .installer import is_installed_globally, install_globally, uninstall_globally
    from . import __version__
except (ImportError, ValueError):
    from entropystrip.reporters.console import console
    from entropystrip.core import analyze_single_file, scan_directory
    from entropystrip.installer import is_installed_globally, install_globally, uninstall_globally
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
    """Returns True if the console window was allocated directly by Windows Explorer."""
    try:
        if sys.platform == "win32" and sys.stdin and sys.stdin.isatty():
            process_list = (ctypes.c_uint * 4)()
            count = ctypes.windll.kernel32.GetConsoleProcessList(process_list, 4)
            # PyInstaller onefile bootloader + unpacked child = 2 processes in dedicated console
            threshold = 2 if getattr(sys, "frozen", False) else 1
            return count <= threshold
    except Exception:
        pass
    return False


def pause_for_user(prompt: str = "\nPress Enter to exit...") -> None:
    """Pauses execution until the user presses Enter."""
    try:
        input(prompt)
    except Exception:
        pass


class StandaloneArgumentParser(argparse.ArgumentParser):
    """Argument parser that avoids closing the window immediately when run from Explorer."""

    def exit(self, status: int = 0, message: str = None) -> None:
        if message:
            self._print_message(message, sys.stderr)
        if is_explorer_launched():
            pause_for_user("\nPress Enter to exit...")
        sys.exit(status)


def main() -> None:
    # If launched with no arguments (e.g. double-clicked from File Explorer)
    if len(sys.argv) == 1:
        console.print(BANNER, style="cyan")
        if sys.platform == "win32":
            if not is_installed_globally():
                console.print("[bold yellow]EntropyStrip is not yet registered in your Windows PATH.[/bold yellow]\n")
                try:
                    choice = input("Do you want to install EntropyStrip to your Windows PATH? [Y/n]: ").strip().lower()
                except (KeyboardInterrupt, EOFError):
                    choice = "n"

                if choice in ("", "y", "yes"):
                    install_globally()
                else:
                    console.print("[dim]Installation skipped.[/dim]\n")
            else:
                console.print(
                    f"[bold green][✓] EntropyStrip v{__version__} is installed globally in your Windows PATH.[/bold green]\n"
                )
        else:
            console.print(
                f"[bold green][✓] EntropyStrip v{__version__} is ready.[/bold green]\n"
            )

        console.print("[bold cyan]How to use EntropyStrip:[/bold cyan]")
        console.print("Open [bold]Command Prompt[/bold] or [bold]PowerShell[/bold] and run:")
        console.print("  • Single file triage:      [yellow]entropystrip file.exe --deep[/yellow]")
        console.print("  • Scan whole directory:    [yellow]entropystrip C:\\folder -r --deep[/yellow]")
        console.print("  • Carve embedded payloads: [yellow]entropystrip malware.exe --dump[/yellow]")
        console.print("  • Generate HTML report:    [yellow]entropystrip malware.exe --html report.html[/yellow]")
        console.print("  • View full help:          [yellow]entropystrip --help[/yellow]")

        pause_for_user()
        return

    console.print(BANNER, style="cyan")
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
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install EntropyStrip globally to %%LOCALAPPDATA%%\\Programs\\EntropyStrip and add to User PATH",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Uninstall EntropyStrip from global PATH and remove installed files",
    )
    parser.add_argument("target", nargs="?", default=None, help="Path to Windows executable (.exe / .dll) or directory")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan subdirectories")
    parser.add_argument("--dump", action="store_true", help="Carve high-entropy payloads to extracted_payloads/")
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Deep forensic triage: MITRE ATT&CK mapping, entry point disassembly, and hashes",
    )
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

    if not args.target:
        parser.print_help()
        if is_explorer_launched():
            pause_for_user()
        return

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

