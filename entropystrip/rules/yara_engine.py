"""
YARA rule compilation and scanning engine for EntropyStrip.
Supports bundled threat rules and custom user-provided .yar files/directories.
"""

import os
from typing import List, Dict, Any, Optional

try:
    import yara
    HAS_YARA = True
except ImportError:
    yara = None
    HAS_YARA = False

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), "defaults")
_COMPILED_RULES_CACHE: Dict[str, Any] = {}


def is_yara_available() -> bool:
    """Returns True if yara-python is installed and usable."""
    return HAS_YARA


def get_default_rule_paths() -> List[str]:
    """Returns paths to all bundled .yar rule files in defaults/."""
    paths = []
    if os.path.isdir(DEFAULT_RULES_DIR):
        for fname in os.listdir(DEFAULT_RULES_DIR):
            if fname.lower().endswith((".yar", ".yara")):
                paths.append(os.path.join(DEFAULT_RULES_DIR, fname))
    return paths


def compile_yara_rules(custom_path: Optional[str] = None) -> Optional[Any]:
    """
    Compiles bundled and optional custom YARA rules.
    Caches compiled rules in-memory for high-speed triage.
    """
    if not HAS_YARA:
        return None

    cache_key = custom_path or "__default__"
    if cache_key in _COMPILED_RULES_CACHE:
        return _COMPILED_RULES_CACHE[cache_key]

    filepaths: Dict[str, str] = {}
    
    # 1. Register bundled default rules
    for p in get_default_rule_paths():
        base = os.path.basename(p)
        filepaths[f"default_{base}"] = p

    # 2. Register custom rules if supplied
    if custom_path:
        clean_p = os.path.abspath(custom_path)
        if os.path.isfile(clean_p):
            filepaths["custom_file"] = clean_p
        elif os.path.isdir(clean_p):
            idx = 0
            for root, _, files in os.walk(clean_p):
                for f in files:
                    if f.lower().endswith((".yar", ".yara")):
                        filepaths[f"custom_{idx}_{f}"] = os.path.join(root, f)
                        idx += 1

    if not filepaths:
        return None

    try:
        compiled = yara.compile(filepaths=filepaths)
        _COMPILED_RULES_CACHE[cache_key] = compiled
        return compiled
    except Exception:
        # If compilation of combined rules fails (e.g. duplicate identifier or syntax error in custom file),
        # fall back to default rules alone
        if custom_path:
            default_fps = {f"default_{os.path.basename(p)}": p for p in get_default_rule_paths()}
            if default_fps:
                try:
                    compiled = yara.compile(filepaths=default_fps)
                    _COMPILED_RULES_CACHE[cache_key] = compiled
                    return compiled
                except Exception:
                    pass
        return None


FALLBACK_RULES = [
    {
        "rule": "CobaltStrike_Beacon_Indicators",
        "description": "Cobalt Strike beacon staging strings and default named pipes",
        "severity": "critical",
        "threat_score": 50,
        "mitre": "T1071.001",
        "patterns": [
            b"\\\\.\\pipe\\msagent_",
            b"\\\\.\\pipe\\status_",
            b"\\\\.\\pipe\\postex_",
            b"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1;",
            b"%C2_SERVER%",
        ],
    },
    {
        "rule": "Ransomware_ShadowCopy_Tampering",
        "description": "Commands executed by ransomware to inhibit system recovery",
        "severity": "high",
        "threat_score": 45,
        "mitre": "T1490",
        "patterns": [
            b"delete shadows",
            b"shadowcopy delete",
            b"bootstatuspolicy ignoreallfailures",
            b"recoveryenabled no",
            b"wbadmin delete catalog",
        ],
    },
    {
        "rule": "Suspicious_Process_Spawning_Primitives",
        "description": "Obfuscated process spawning and download cradle commands",
        "severity": "medium",
        "threat_score": 35,
        "mitre": "T1059.001",
        "patterns": [
            b"powershell -enc",
            b"powershell -encodedcommand",
            b"certutil -urlcache -split -f",
            b"bitsadmin /transfer",
            b"mshta vbscript:Execute",
            b"mshta javascript:",
        ],
    },
    {
        "rule": "Reflective_DLL_Injection_Signature",
        "description": "Reflective DLL injection export and loader signature",
        "severity": "high",
        "threat_score": 40,
        "mitre": "T1055.001",
        "patterns": [
            b"ReflectiveLoader",
            b"?ReflectiveLoader@@",
            b"reflective_dll",
        ],
    },
    {
        "rule": "Shellcode_EggHunter_Signature",
        "description": "Egg hunter shellcode search stub",
        "severity": "high",
        "threat_score": 45,
        "mitre": "T1055",
        "patterns": [
            b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e",
            b"w00tw00t",
            b"c0d3c0d3",
        ],
    },
]


def scan_fallback_rules(data: bytes) -> List[Dict[str, Any]]:
    """Pure-Python signature scanner executing when native yara-python is not installed."""
    if not data:
        return []
    
    matches = []
    lower_data = data.lower()
    for rule in FALLBACK_RULES:
        matched_patterns = []
        for pat in rule["patterns"]:
            if pat.lower() in lower_data:
                matched_patterns.append(pat.decode("latin-1", errors="replace"))
        
        if matched_patterns:
            matches.append(
                {
                    "rule": rule["rule"],
                    "tags": ["curated", "fallback"],
                    "meta": {"description": rule["description"], "score": rule["threat_score"]},
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "mitre": rule["mitre"],
                    "threat_score": rule["threat_score"],
                    "matched_strings": matched_patterns,
                }
            )
    return matches


def scan_yara(
    data: bytes = b"",
    custom_path: Optional[str] = None,
    file_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Scans binary bytes or file with compiled YARA rules.
    Falls back to pure-Python signature engine if yara-python is not compiled.
    """
    if not data and file_path and os.path.isfile(file_path):
        try:
            with open(file_path, "rb") as f:
                data = f.read(16 * 1024 * 1024)
        except Exception:
            data = b""

    if not data and not file_path:
        return []

    if not HAS_YARA:
        return scan_fallback_rules(data)

    rules = compile_yara_rules(custom_path)
    if not rules:
        return scan_fallback_rules(data)

    matches = []
    try:
        if file_path and os.path.isfile(file_path):
            raw_matches = rules.match(filepath=file_path)
        else:
            raw_matches = rules.match(data=data)
        for m in raw_matches:
            meta = getattr(m, "meta", {}) or {}
            score = int(meta.get("score", 35))
            desc = meta.get("description", m.rule)
            mitre_id = meta.get("mitre")
            severity = meta.get("severity", "medium")

            # Extract string identifiers without dumping massive binary blocks
            matched_identifiers = []
            if hasattr(m, "strings"):
                for s in m.strings[:5]:
                    ident = getattr(s, "identifier", str(s))
                    if ident not in matched_identifiers:
                        matched_identifiers.append(ident)

            matches.append(
                {
                    "rule": m.rule,
                    "tags": list(getattr(m, "tags", [])),
                    "meta": meta,
                    "description": desc,
                    "severity": severity,
                    "mitre": mitre_id,
                    "threat_score": score,
                    "matched_strings": matched_identifiers,
                }
            )
    except Exception:
        matches = scan_fallback_rules(data)

    return matches
