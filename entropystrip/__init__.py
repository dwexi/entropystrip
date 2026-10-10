"""
EntropyStrip: Algorithmic PE De-obfuscator, Shannon Entropy Radar, and Incident Triage Engine.
"""

__version__ = "1.0.0"
__author__ = "dwexi"

from .core import (
    calculate_entropy,
    calculate_dilution_metrics,
    analyze_single_file,
    scan_directory,
    main,
)

__all__ = [
    "calculate_entropy",
    "calculate_dilution_metrics",
    "analyze_single_file",
    "scan_directory",
    "main",
    "__version__",
]
