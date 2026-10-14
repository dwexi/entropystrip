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
    from . import __version__
except (ImportError, ValueError):
    from entropystrip.reporters.console import console
    from entropystrip.core import analyze_single_file, scan_directory
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


def should_pause_on_exit() -> bool:
    """Returns True if running in a console window allocated directly by Windows Explorer."""
    try:
        if sys.platform == "win32" and sys.stdin and sys.stdin.isatty():
            process_list = (ctypes.c_uint * 2)()
            count = ctypes.windll.kernel32.GetConsoleProcessList(process_list, 2)
            return count <= 1
    except Exception:
        pass
    return False


def pause_if_needed(prompt: str = "\nPress Enter to exit...") -> None:
    """Pauses execution if the console window would otherwise close immediately."""
    if should_pause_on_exit():
        try:
            input(prompt)
        except Exception:
            pass


class StandaloneArgumentParser(argparse.ArgumentParser):
    """Argument parser that avoids closing the window immediately when run from Explorer."""

    def exit(self, status: int = 0, message: str = None) -> None:
        if message:
            self._print_message(message, sys.stderr)
        pause_if_needed("\nPress Enter to exit...")
        sys.exit(status)


def main() -> None:
    # If launched with no arguments (e.g. double-clicked from File Explorer)
    if len(sys.argv) == 1:
        console.print(BANNER, style="cyan")
        console.print(
            f"[bold green][✓] EntropyStrip v{__version__} is successfully installed and ready.[/bold green]\n"
        )
        console.print("[bold cyan]Interactive PE Triage Engine[/bold cyan]")
        console.print("  • Drag and drop an executable (.exe / .dll) or directory into this window and press Enter.")
        console.print("  • Or run from PowerShell / Command Prompt: [yellow]entropystrip <target-path>[/yellow]")
        console.print("  • Type [yellow]--help[/yellow] to view all flags (--deep, --dump, --html, --json).\n")

        try:
            user_input = input("Target path to scan (or press Enter to exit): ").strip().strip('"\'')
        except (KeyboardInterrupt, EOFError):
            return

        if not user_input:
            pause_if_needed()
            return

        if user_input.lower() in ("-h", "--help", "help"):
            sys.argv.append("--help")
            # fall through to argparse below
        else:
            clean_target = os.path.abspath(os.path.normpath(user_input))
            if os.path.isdir(clean_target):
                scan_directory(clean_target)
            elif os.path.isfile(clean_target):
                analyze_single_file(clean_target, quiet=False)
            else:
                console.print(f"[red]Error: Target not found -> {user_input}[/red]")

            pause_if_needed("\nScan complete. Press Enter to exit...")
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
    parser.add_argument("target", help="Path to Windows executable (.exe / .dll) or directory")
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

    pause_if_needed("\nScan complete. Press Enter to exit...")


if __name__ == "__main__":
    main()

