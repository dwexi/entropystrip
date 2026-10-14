"""
EntropyStrip: Algorithmic PE De-obfuscator, Shannon Entropy Radar, and Incident Triage Engine.
"""

__version__ = "1.2.3"
__author__ = "dwexi"

from .core import (
    calculate_entropy,
    calculate_dilution_metrics,
    detect_encoded_payload,
    scan_sliding_window_entropy,
    calculate_chi_square,
    detect_string_staging,
    detect_installer,
    check_authenticode_signature,
    analyze_single_file,
    scan_directory,
    generate_html_report,
    generate_directory_html_report,
    main,
)

__all__ = [
    "calculate_entropy",
    "calculate_dilution_metrics",
    "detect_encoded_payload",
    "scan_sliding_window_entropy",
    "calculate_chi_square",
    "detect_string_staging",
    "detect_installer",
    "check_authenticode_signature",
    "analyze_single_file",
    "scan_directory",
    "generate_html_report",
    "generate_directory_html_report",
    "main",
    "__version__",
]
