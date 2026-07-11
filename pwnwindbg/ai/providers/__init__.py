"""LLM provider sessions for the in-debugger AI agent.

Each provider implements a stateful :class:`AgentSession` that keeps its own
conversation history and streams assistant text deltas from ``send()``.

Public API:
    from pwnwindbg.ai.providers import create_session, AgentSession
"""

from .base import AgentSession, create_session

__all__ = ["AgentSession", "create_session"]
