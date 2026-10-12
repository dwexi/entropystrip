"""
Mathematical and heuristic detection radar modules.
"""

from .entropy import (
    calculate_entropy,
    scan_sliding_window_entropy,
    get_entropy_heatmap_string,
)
from .dilution import (
    calculate_dilution_metrics,
    calculate_chi_square,
)
from .staging import (
    detect_encoded_payload,
    detect_string_staging,
    STRING_STAGING_APIS,
)
from .signatures import (
    detect_installer,
    check_authenticode_signature,
)

__all__ = [
    "calculate_entropy",
    "scan_sliding_window_entropy",
    "get_entropy_heatmap_string",
    "calculate_dilution_metrics",
    "calculate_chi_square",
    "detect_encoded_payload",
    "detect_string_staging",
    "STRING_STAGING_APIS",
    "detect_installer",
    "check_authenticode_signature",
]
