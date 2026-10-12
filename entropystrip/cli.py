"""
CLI argument parser and entry point for EntropyStrip.
"""

import sys
import os
import argparse
try:
    from .reporters.console import console
    from .core import analyze_single_file, scan_directory
except (ImportError, ValueError):
    from entropystrip.reporters.console import console
    from entropystrip.core import analyze_single_file, scan_directory

try:
    sys.stdout.reconfigure(encoding="utf-8")
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


def main() -> None:
    console.print(BANNER, style="cyan")
    parser = argparse.ArgumentParser(
        prog="entropystrip",
        description="EntropyStrip: PE De-obfuscator, Shannon Entropy Radar, and Incident Triage Engine",
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
        scan_directory(clean_target, recursive=args.recursive, dump_payloads=args.dump)
    else:
        analyze_single_file(
            clean_target,
            dump_payloads=args.dump,
            quiet=False,
            html_out=args.html,
            json_out=args.json,
            deep=args.deep,
        )


if __name__ == "__main__":
    main()
