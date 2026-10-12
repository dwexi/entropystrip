"""
String-based obfuscation, Base64 buffers, and dynamic memory staging primitive detectors.
"""

import re
from typing import Tuple, List, Set
from .entropy import calculate_entropy

STRING_STAGING_APIS: Set[str] = {
    "UuidFromStringA",
    "UuidFromStringW",
    "RtlIpv4StringToAddressA",
    "RtlIpv4StringToAddressW",
    "RtlIpv6StringToAddressA",
    "RtlIpv6StringToAddressW",
    "RtlEthernetStringToAddressA",
    "CLSIDFromString",
}

BASE64_CHARSET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n")
UUID_REGEX = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
IP_REGEX = re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def detect_encoded_payload(data: bytes) -> Tuple[bool, float, str]:
    """
    Detects dense Base64 encoded payload buffers.
    Base64 encoding yields entropy strictly between ~5.60 and 6.05 with >= 96% charset purity.
    """
    if not data or len(data) < 512:
        return False, 0.0, ""

    sample = data[:4096]
    b64_matches = sum(1 for b in sample if b in BASE64_CHARSET)
    ratio = b64_matches / len(sample)
    if ratio >= 0.96:
        ent = calculate_entropy(sample)
        if 5.6 <= ent <= 6.05:
            return True, ent, f"Base64-encoded payload detected (H={ent:.2f}, {ratio*100:.0f}% charset uniformity)"
    return False, 0.0, ""


def detect_string_staging(
    data: bytes, flagged_apis: List[str]
) -> Tuple[List[str], int, bool, int, bool]:
    """
    Detects memory-staging patterns where shellcode is formatted as string tables
    (UUIDs, IPv4/IPv6, MAC addresses) to evade static disk entropy checks before runtime assembly.
    """
    staging_hits = [api for api in flagged_apis if api in STRING_STAGING_APIS]

    # Bound regex inspection on large files to prevent regex DoS
    scan_buf = (data[:1_000_000] + data[-500_000:]) if data and len(data) > 1_500_000 else data
    uuid_matches = UUID_REGEX.findall(scan_buf) if scan_buf else []
    ip_matches = IP_REGEX.findall(scan_buf) if scan_buf else []

    # Correlate matches against resolved staging APIs to prevent false positives on legitimate COM GUIDs
    has_uuid_cluster = len(uuid_matches) >= (4 if staging_hits else 12)
    has_ip_cluster = len(ip_matches) >= (6 if staging_hits else 16)

    return staging_hits, len(uuid_matches), has_uuid_cluster, len(ip_matches), has_ip_cluster
