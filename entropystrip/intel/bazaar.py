"""
MalwareBazaar (abuse.ch) Threat Intelligence API client.
Queries sample hash reputation, malware family signatures, tags, and community telemetry.
"""

import json
import urllib.parse
from typing import Optional, Dict, Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from .config import get_bazaar_api_key

MALWAREBAZAAR_ENDPOINT = "https://mb-api.abuse.ch/api/v1/"
_BAZAAR_CACHE: Dict[str, Optional[Dict[str, Any]]] = {}
_CONSECUTIVE_FAILURES = 0
_CIRCUIT_OPEN = False


def reset_circuit_breaker() -> None:
    """Resets the circuit breaker state (useful for tests and new scan runs)."""
    global _CONSECUTIVE_FAILURES, _CIRCUIT_OPEN
    _CONSECUTIVE_FAILURES = 0
    _CIRCUIT_OPEN = False


def query_malware_bazaar(
    sha256_hash: str,
    api_key: Optional[str] = None,
    timeout: int = 6,
) -> Optional[Dict[str, Any]]:
    """
    Queries MalwareBazaar API for hash classification, signature, and community tags.
    Results are cached in-memory to prevent redundant queries during batch scans.
    Employs circuit breaker and negative caching for resilience in offline / throttled networks.
    
    Returns:
        Structured intel dictionary if known, or None if network fails / unknown.
    """
    global _CONSECUTIVE_FAILURES, _CIRCUIT_OPEN

    clean_hash = sha256_hash.strip().lower()
    if not clean_hash or len(clean_hash) != 64:
        return None

    if _CIRCUIT_OPEN:
        return None

    if clean_hash in _BAZAAR_CACHE:
        return _BAZAAR_CACHE[clean_hash]

    resolved_key = get_bazaar_api_key(api_key)

    headers = {
        "User-Agent": "EntropyStrip-Forensic-Radar/1.3.0",
    }
    if resolved_key:
        headers["Auth-Key"] = resolved_key

    payload = {
        "query": "get_info",
        "hash": clean_hash,
    }

    try:
        data_encoded = urllib.parse.urlencode(payload).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        req = Request(
            url=MALWAREBAZAAR_ENDPOINT,
            data=data_encoded,
            headers=headers,
            method="POST",
        )

        with urlopen(req, timeout=timeout) as response:
            resp_bytes = response.read()
            resp_data = json.loads(resp_bytes.decode("utf-8", errors="ignore"))

            query_status = resp_data.get("query_status")
            if query_status == "ok" and resp_data.get("data"):
                sample_info = resp_data["data"][0]
                
                vt_data = None
                intel = sample_info.get("intelligence", {})
                if intel and "virustotal" in intel and isinstance(intel["virustotal"], dict):
                    vt = intel["virustotal"]
                    raw_pct = vt.get("percent")
                    pct_val = float(raw_pct) if raw_pct is not None else 0.0
                    vt_data = {
                        "percent": pct_val,
                        "positives": int(vt.get("positives") or 0),
                        "total": int(vt.get("total") or 0),
                    }

                raw_tags = sample_info.get("tags") or []
                clean_tags = [str(t) for t in raw_tags if t is not None]

                intel_result = {
                    "status": "malicious",
                    "source": "MalwareBazaar (abuse.ch)",
                    "sha256": sample_info.get("sha256_hash"),
                    "signature": sample_info.get("signature") or "Unknown Malware Family",
                    "file_type": sample_info.get("file_type"),
                    "mime_type": sample_info.get("file_type_mime"),
                    "tags": clean_tags,
                    "reporter": sample_info.get("reporter"),
                    "first_seen": sample_info.get("first_seen"),
                    "last_seen": sample_info.get("last_seen"),
                    "delivery_method": sample_info.get("delivery_method"),
                    "virustotal": vt_data,
                }
                _BAZAAR_CACHE[clean_hash] = intel_result
                _CONSECUTIVE_FAILURES = 0
                return intel_result

            elif query_status == "hash_not_found":
                intel_result = {
                    "status": "not_found",
                    "source": "MalwareBazaar (abuse.ch)",
                    "sha256": clean_hash,
                    "signature": None,
                    "message": "Hash not found in MalwareBazaar dataset (0 community reports)",
                }
                _BAZAAR_CACHE[clean_hash] = intel_result
                _CONSECUTIVE_FAILURES = 0
                return intel_result

            else:
                _BAZAAR_CACHE[clean_hash] = None
                return None

    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError, Exception):
        _BAZAAR_CACHE[clean_hash] = None
        _CONSECUTIVE_FAILURES += 1
        if _CONSECUTIVE_FAILURES >= 3:
            _CIRCUIT_OPEN = True
        return None
