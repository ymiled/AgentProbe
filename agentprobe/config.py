import os
import yaml
from typing import Any

from dotenv import load_dotenv


DEFAULT_CONFIG: dict[str, Any] = {
    "llm": {
        "provider": "groq",
        "model": "llama-3.3-70b-versatile",
        "api_key_env": "GROQ_API_KEY",
        "max_tokens": 4096,
        "temperature": 0.7,
    },
    "scan": {
        "mode": "sequential",           # "sequential" or "swarm"
        "attacks": "all",               # or list: ["prompt_injection", "tool_manipulation"]
        "recon_messages": 4,
        "payloads_per_attack": 3,
        "defense_enabled": False,
        "defense_threshold": 0.7,
    },
    "target": {
        "type": "builtin",              # "builtin" or "custom"
        "module": None,
        "reset_between_attacks": True,
    },
    "output": {
        "directory": "output/",
        "format": "both",               # "json", "html", or "both"
        "save_training_data": True,
        "save_raw_logs": True,
    },
}

load_dotenv(override=False)


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load configuration, merging YAML file over defaults if provided.

    Search order:
    1. Explicit path argument
    2. AGENTPROBE_CONFIG env var
    3. agentprobe.yaml in the current working directory
    4. Defaults only
    """
    # Re-load to ensure current working directory changes are reflected.
    load_dotenv(override=False)

    config = _deep_copy(DEFAULT_CONFIG)

    yaml_path = path or os.environ.get("AGENTPROBE_CONFIG") or _find_default_yaml()
    if yaml_path and os.path.isfile(yaml_path):
        with open(yaml_path, "r") as f:
            overrides = yaml.safe_load(f) or {}
        config = _deep_merge(config, overrides) 

    return config


def get_api_key(config: dict[str, Any]) -> str:
    """Resolve the LLM API key from the environment."""
    load_dotenv(override=False)

    env_var = config["llm"]["api_key_env"]
    key = os.environ.get(env_var, "")
    if not key:
        raise EnvironmentError(
            f"API key not found. Set the {env_var!r} environment variable."
        )
    return key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_default_yaml() -> str | None:
    candidate = os.path.join(os.getcwd(), "agentprobe.yaml")
    return candidate if os.path.isfile(candidate) else None


def _deep_copy(d: dict) -> dict:
    import copy
    return copy.deepcopy(d)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
