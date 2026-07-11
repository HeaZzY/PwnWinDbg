"""Provider-agnostic session interface and factory for the AI agent.

An :class:`AgentSession` owns a conversation: a system prompt plus a rolling
``messages`` list of ``{"role", "content"}`` dicts.  ``send(user_text)`` appends
the user turn, streams the assistant reply as text deltas, then records the full
assistant reply in history so the next ``send()`` includes it.

Providers must raise :class:`RuntimeError` (with a helpful message) on any
network / transport / parse failure so the agent loop can surface it cleanly.
"""

from abc import ABC, abstractmethod
from typing import Iterator, List, Dict


class AgentSession(ABC):
    """A stateful LLM conversation that streams assistant text deltas.

    Subclasses keep ``self.system_prompt`` and ``self.messages`` (a list of
    ``{"role": "user"|"assistant", "content": str}`` dicts) and implement
    :meth:`send`.
    """

    def __init__(self, cfg: dict, system_prompt: str):
        self.cfg = cfg or {}
        self.system_prompt = system_prompt or ""
        self.messages: List[Dict[str, str]] = []

    @abstractmethod
    def send(self, user_text: str) -> Iterator[str]:
        """Send ``user_text`` and yield assistant text deltas.

        Implementations must append the user message and the full assistant
        reply to ``self.messages`` so history is preserved across calls.
        """
        raise NotImplementedError


def create_session(cfg: dict, system_prompt: str) -> AgentSession:
    """Build an :class:`AgentSession` for the provider named by ``cfg['provider']``.

    ``cfg`` is the loaded AI config dict (see ``pwnwindbg.ai.config``); this
    module does not import the config module so it stays decoupled.
    """
    cfg = cfg or {}
    provider = (cfg.get("provider") or "claude_code").strip().lower()

    if provider == "openai":
        from .openai_provider import OpenAISession
        return OpenAISession(cfg, system_prompt)
    if provider == "anthropic":
        from .anthropic_provider import AnthropicSession
        return AnthropicSession(cfg, system_prompt)
    if provider == "claude_code":
        from .claude_code_provider import ClaudeCodeSession
        return ClaudeCodeSession(cfg, system_prompt)

    raise RuntimeError(
        f"unknown AI provider {provider!r}: expected one of "
        "'openai', 'anthropic', 'claude_code'"
    )


def _effective_key(cfg: dict, provider: str) -> str:
    """Best-effort resolution of an API key without importing the config module.

    Mirrors ``config.get_effective_key``: an env var named by
    ``<provider>.api_key_env`` wins if set & non-empty, then the stored
    ``api_key``, then the generic ``OPENAI_API_KEY`` / ``ANTHROPIC_API_KEY``.
    """
    import os

    section = (cfg or {}).get(provider) or {}
    env_name = section.get("api_key_env")
    if env_name:
        val = os.environ.get(env_name)
        if val:
            return val
    key = section.get("api_key")
    if key:
        return key
    generic = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}.get(provider)
    if generic:
        val = os.environ.get(generic)
        if val:
            return val
    return ""
