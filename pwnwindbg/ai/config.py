"""Persistent configuration for the pwnWinDbg AI agent.

The config lives under ``%LOCALAPPDATA%\\pwnWinDbg\\ai_config.json`` (falling
back to the user home directory if LOCALAPPDATA is unset). It is created with
sane defaults on first use and deep-merged against those defaults on every load
so that new keys added in later versions appear automatically for existing
users.

Pure standard library (os, json) — this module must be importable in isolation
and must not import any other ``pwnwindbg.ai`` modules.
"""

import os
import json

# Default configuration. This is the source of truth for both the shape of the
# config and the type coercion done by set_value().
DEFAULT_CONFIG = {
    "provider": "claude_code",
    "max_steps": 30,
    "max_obs_chars": 6000,
    "python_timeout": 120,
    "continue_timeout": 15,
    "temperature": 0.2,
    "code_exec": True,
    "spawn_with_pipes": True,
    "blocked_commands": ["quit", "q", "exit", "ai"],
    # Native AI decompiler (see core/decompiler.py, commands/decompile_cmds.py).
    "decompile_auto": True,       # show the pseudo-C pane in the live context
    "decompile_max_insns": 400,   # cap on instructions decompiled per function
    "openai": {
        "base_url": "https://api.moonshot.ai/v1",
        "model": "kimi-k2-0711-preview",
        "api_key": "",
        "api_key_env": "MOONSHOT_API_KEY",
        "max_tokens": 4096,
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "model": "claude-opus-4-8",
        "api_key": "",
        "api_key_env": "ANTHROPIC_API_KEY",
        "max_tokens": 4096,
        "version": "2023-06-01",
    },
    "claude_code": {
        "binary": "claude",
        "model": "",
        "extra_args": [],
    },
}

# Generic environment variables honored as a fallback for well-known providers.
_GENERIC_KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}


def config_path():
    """Return the absolute path to the AI config JSON file."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "pwnWinDbg", "ai_config.json")


def _deep_copy(obj):
    """Return a deep copy of a JSON-shaped object (dicts/lists/scalars)."""
    if isinstance(obj, dict):
        return {k: _deep_copy(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_copy(v) for v in obj]
    return obj


def _deep_merge(defaults, override):
    """Deep-merge ``override`` onto a copy of ``defaults``.

    Values present in ``override`` win; keys missing from ``override`` are
    filled in from ``defaults`` (recursively for nested dicts). This is how
    upgrades pick up newly added default keys without discarding user values.
    """
    result = _deep_copy(defaults)
    if not isinstance(override, dict):
        return result
    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = _deep_copy(value)
    return result


def load():
    """Load the config, creating it with defaults if it does not exist.

    Missing keys are deep-merged over the defaults so that config upgrades add
    new keys automatically. A corrupt/unreadable file falls back to defaults.
    """
    path = config_path()
    if not os.path.exists(path):
        cfg = _deep_copy(DEFAULT_CONFIG)
        try:
            save(cfg)
        except OSError:
            # Best effort: still return usable defaults even if we can't write.
            pass
        return cfg

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        # Unreadable or malformed JSON — fall back to defaults.
        return _deep_copy(DEFAULT_CONFIG)

    if not isinstance(data, dict):
        return _deep_copy(DEFAULT_CONFIG)

    return _deep_merge(DEFAULT_CONFIG, data)


def save(cfg):
    """Persist the config to disk as pretty JSON, creating its dir if needed."""
    path = config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2, sort_keys=False)
        fh.write("\n")


def get_effective_key(cfg, provider):
    """Resolve the effective API key for ``provider``.

    Resolution order:
      1. The env var named by ``<provider>.api_key_env`` (if set & non-empty).
      2. The stored ``<provider>.api_key`` value (if non-empty).
      3. A generic well-known env var (OPENAI_API_KEY / ANTHROPIC_API_KEY).

    Returns an empty string when nothing is configured.
    """
    section = cfg.get(provider)
    if isinstance(section, dict):
        env_name = section.get("api_key_env")
        if env_name:
            env_val = os.environ.get(env_name)
            if env_val:
                return env_val
        stored = section.get("api_key")
        if stored:
            return stored

    generic_name = _GENERIC_KEY_ENV.get(provider)
    if generic_name:
        generic_val = os.environ.get(generic_name)
        if generic_val:
            return generic_val

    return ""


def _coerce_like(current, value):
    """Coerce string ``value`` to match the type of ``current`` (int/bool).

    Only applies when ``current`` is a bool or int (bool checked first, since
    bool is a subclass of int). Everything else is passed through unchanged.
    """
    if isinstance(value, str):
        if isinstance(current, bool):
            lowered = value.strip().lower()
            if lowered in ("true", "1", "yes", "on"):
                return True
            if lowered in ("false", "0", "no", "off"):
                return False
            return current
        if isinstance(current, int):
            try:
                return int(value.strip(), 0)
            except ValueError:
                return current
    return value


def set_value(cfg, dotted_key, value):
    """Set a config value addressed by a dotted key, coercing int/bool.

    Examples: ``set_value(cfg, "openai.model", "kimi-k2")`` or
    ``set_value(cfg, "provider", "anthropic")``. When the existing default at
    that location is an int or bool, a string ``value`` is coerced to match.
    Intermediate dict levels are created as needed.
    """
    parts = dotted_key.split(".")
    node = cfg
    # Walk/create intermediate dicts.
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child

    leaf = parts[-1]
    if leaf in node:
        value = _coerce_like(node[leaf], value)
    else:
        # Fall back to the default's type at this location, if known.
        default_current = _default_at(parts)
        if default_current is not None:
            value = _coerce_like(default_current, value)

    node[leaf] = value


def _default_at(parts):
    """Return the DEFAULT_CONFIG value at a dotted path, or None if absent."""
    node = DEFAULT_CONFIG
    for part in parts:
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node
