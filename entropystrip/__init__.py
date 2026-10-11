"""
EntropyStrip: Algorithmic PE De-obfuscator, Shannon Entropy Radar, and Incident Triage Engine.
"""

__version__ = "1.1.0"
__author__ = "dwexi"

from .core import (
    calculate_entropy,
    calculate_dilution_metrics,
    scan_sliding_window_entropy,
    calculate_chi_square,
    detect_string_staging,
    detect_installer,
    analyze_single_file,
    scan_directory,
    main,
)

__all__ = [
    "calculate_entropy",
    "calculate_dilution_metrics",
    "scan_sliding_window_entropy",
    "calculate_chi_square",
    "detect_string_staging",
    "detect_installer",
    "analyze_single_file",
    "scan_directory",
    "main",
    "__version__",
]
