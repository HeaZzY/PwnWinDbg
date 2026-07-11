"""`ai` command: drive the autonomous in-debugger AI agent and manage its config.

Usage:
    ai "<task>"                     run the agent on a one-shot task
    ai status                       show provider / model / key / config path
    ai config                       print effective config + path
    ai config path                  print the config file path
    ai config set <dotted> <value>  set a config value (e.g. openai.model foo)
    ai use <provider>               switch provider (claude_code|openai|anthropic)
    ai model <name>                 set the current provider's model
    ai key <provider> <value>       store an API key for a provider
"""

import json

from ..display.formatters import console, info, error, success, warn
from ..ai import config as ai_config


_SUBCOMMANDS = {"config", "use", "model", "key", "status"}
_USAGE = (
    'ai "<task>"  —  run the AI agent on a task\n'
    "  ai status                       provider / model / key / config path\n"
    "  ai config [path]                show effective config (or its path)\n"
    "  ai config set <dotted> <value>  set a config value\n"
    "  ai use <provider>               claude_code | openai | anthropic\n"
    "  ai model <name>                 set the current provider's model\n"
    "  ai key <provider> <value>       store an API key"
)


def _print_usage():
    info("AI agent")
    console.print(_USAGE)


def _current_provider(cfg):
    return cfg.get("provider", "claude_code")


def _provider_model(cfg, provider):
    """Return the configured model for a provider, or '' if none/unknown."""
    section = cfg.get(provider)
    if isinstance(section, dict):
        return section.get("model", "") or ""
    return ""


def _cmd_status(cfg):
    provider = _current_provider(cfg)
    model = _provider_model(cfg, provider)
    try:
        key = ai_config.get_effective_key(cfg, provider)
    except Exception:
        key = ""
    key_present = "yes" if key else "no"
    info("AI status")
    console.print(f"  provider    : {provider}")
    console.print(f"  model       : {model or '(default)'}")
    console.print(f"  key present : {key_present}")
    console.print(f"  config path : {ai_config.config_path()}")


def _cmd_config(cfg, args):
    parts = args.split() if args else []
    # `ai config path`
    if parts and parts[0].lower() == "path":
        console.print(ai_config.config_path())
        return
    # `ai config set <dotted> <value>`
    if parts and parts[0].lower() == "set":
        if len(parts) < 3:
            error("Usage: ai config set <dotted.key> <value>")
            return
        dotted = parts[1]
        # Preserve the remainder verbatim (values may contain spaces).
        value = args.split(None, 2)[2]
        try:
            ai_config.set_value(cfg, dotted, value)
            ai_config.save(cfg)
        except Exception as exc:
            error(f"ai config set: {exc}")
            return
        success(f"set {dotted} = {value}")
        return
    # `ai config` — dump effective config + path
    info(f"AI config ({ai_config.config_path()})")
    try:
        console.print(json.dumps(cfg, indent=2))
    except Exception as exc:
        error(f"could not render config: {exc}")


def _cmd_use(cfg, args):
    provider = args.strip()
    if not provider:
        error("Usage: ai use <claude_code|openai|anthropic>")
        return
    try:
        ai_config.set_value(cfg, "provider", provider)
        ai_config.save(cfg)
    except Exception as exc:
        error(f"ai use: {exc}")
        return
    success(f"provider = {provider}")


def _cmd_model(cfg, args):
    name = args.strip()
    if not name:
        error("Usage: ai model <name>")
        return
    provider = _current_provider(cfg)
    try:
        ai_config.set_value(cfg, f"{provider}.model", name)
        ai_config.save(cfg)
    except Exception as exc:
        error(f"ai model: {exc}")
        return
    success(f"{provider}.model = {name}")


def _cmd_key(cfg, args):
    parts = args.split(None, 1)
    if len(parts) < 2 or not parts[1].strip():
        error("Usage: ai key <provider> <value>")
        return
    provider = parts[0].strip()
    value = parts[1].strip()
    if provider not in cfg or not isinstance(cfg.get(provider), dict):
        error(f"unknown provider: {provider}")
        return
    try:
        ai_config.set_value(cfg, f"{provider}.api_key", value)
        ai_config.save(cfg)
    except Exception as exc:
        error(f"ai key: {exc}")
        return
    success(f"stored api_key for {provider}")


def cmd_ai(debugger, args):
    """Dispatch the `ai` command. Always returns None."""
    text = (args or "").strip()
    if not text:
        _print_usage()
        return None

    first = text.split(None, 1)[0].lower()
    rest = text.split(None, 1)[1] if len(text.split(None, 1)) > 1 else ""

    if first in _SUBCOMMANDS:
        try:
            cfg = ai_config.load()
        except Exception as exc:
            error(f"ai: could not load config: {exc}")
            return None

        if first == "status":
            _cmd_status(cfg)
        elif first == "config":
            _cmd_config(cfg, rest)
        elif first == "use":
            _cmd_use(cfg, rest)
        elif first == "model":
            _cmd_model(cfg, rest)
        elif first == "key":
            _cmd_key(cfg, rest)
        return None

    # Otherwise: the whole args string is the task.
    try:
        from ..ai.agent import run_agent
        run_agent(debugger, text)
    except Exception as exc:
        error(f"ai: {exc}")
    return None
