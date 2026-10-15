"""
Configuration management for EntropyStrip user settings and threat intel credentials.
Persists settings in ~/.entropystrip/config.json.
"""

import os
import json
from typing import Optional, Dict, Any


def get_config_dir() -> str:
    """Returns ~/.entropystrip path, creating it if necessary."""
    home = os.path.expanduser("~")
    cfg_dir = os.path.join(home, ".entropystrip")
    try:
        os.makedirs(cfg_dir, exist_ok=True)
    except Exception:
        pass
    return cfg_dir


def get_config_path() -> str:
    return os.path.join(get_config_dir(), "config.json")


def load_config() -> Dict[str, Any]:
    """Loads configuration dictionary from ~/.entropystrip/config.json."""
    cfg_path = get_config_path()
    if os.path.isfile(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
                return {}
        except Exception:
            return {}
    return {}


def save_config(cfg: Dict[str, Any]) -> bool:
    """Saves configuration dictionary to ~/.entropystrip/config.json atomically with restricted permissions."""
    if not isinstance(cfg, dict):
        return False
    cfg_dir = get_config_dir()
    cfg_path = get_config_path()
    tmp_path = os.path.join(cfg_dir, f"config.tmp.{os.getpid()}")
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600
        fd = os.open(tmp_path, flags, mode)
        with open(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp_path, cfg_path)
        return True
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return False


def get_bazaar_api_key(explicit_key: Optional[str] = None) -> Optional[str]:
    """
    Resolves MalwareBazaar API key using 3-tier precedence:
    1. Explicit key passed via CLI argument (--bazaar-key)
    2. MALWAREBAZAAR_API_KEY environment variable
    3. Stored key in ~/.entropystrip/config.json
    """
    if explicit_key and explicit_key.strip():
        return explicit_key.strip()

    env_key = os.environ.get("MALWAREBAZAAR_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()

    cfg = load_config()
    cfg_key = cfg.get("malwarebazaar_api_key")
    if cfg_key and isinstance(cfg_key, str) and cfg_key.strip():
        return cfg_key.strip()

    return None


def set_bazaar_api_key(key: str) -> bool:
    """Saves MalwareBazaar API key into ~/.entropystrip/config.json."""
    cfg = load_config()
    cfg["malwarebazaar_api_key"] = key.strip()
    return save_config(cfg)
