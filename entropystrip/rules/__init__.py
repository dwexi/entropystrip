"""
YARA rules scanning engine and curated threat signatures for EntropyStrip.
"""

from .yara_engine import (
    is_yara_available,
    compile_yara_rules,
    scan_yara,
    get_default_rule_paths,
)

__all__ = [
    "is_yara_available",
    "compile_yara_rules",
    "scan_yara",
    "get_default_rule_paths",
]
