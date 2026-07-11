"""Anthropic native Messages API provider (streaming SSE).

POSTs to ``{base_url}/v1/messages`` with a top-level ``system`` field and a
``messages`` list of user/assistant turns.  HTTP via the standard library.
"""

import json
import urllib.request
import urllib.error
from typing import Iterator

from .base import AgentSession, _effective_key


class AnthropicSession(AgentSession):
    """Chat session against the native Anthropic Messages API."""

    def __init__(self, cfg: dict, system_prompt: str):
        super().__init__(cfg, system_prompt)
        self._section = (cfg or {}).get("anthropic") or {}

    def _endpoint(self) -> str:
        base = (self._section.get("base_url") or "https://api.anthropic.com").rstrip("/")
        return base + "/v1/messages"

    def send(self, user_text: str) -> Iterator[str]:
        self.messages.append({"role": "user", "content": user_text})

        key = _effective_key(self.cfg, "anthropic")
        if not key:
            raise RuntimeError(
                "anthropic error: no API key. Set it with 'ai key anthropic <value>' "
                "or export ANTHROPIC_API_KEY."
            )

        model = self._section.get("model") or "claude-opus-4-8"
        version = self._section.get("version") or "2023-06-01"
        body = {
            "model": model,
            "messages": list(self.messages),
            "max_tokens": self._section.get("max_tokens", 4096),
            "temperature": self.cfg.get("temperature", 0.2),
            "stream": True,
        }
        if self.system_prompt:
            body["system"] = self.system_prompt
        data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(
            self._endpoint(),
            data=data,
            method="POST",
            headers={
                "content-type": "application/json",
                "x-api-key": key,
                "anthropic-version": version,
                "accept": "text/event-stream",
            },
        )

        assistant_parts = []
        try:
            resp = urllib.request.urlopen(req, timeout=600)
        except urllib.error.HTTPError as e:
            detail = _read_error_body(e)
            raise RuntimeError(f"anthropic error: HTTP {e.code} {e.reason}: {detail}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"anthropic error: connection failed: {e.reason}") from e
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"anthropic error: {e}") from e

        try:
            for delta in _iter_sse_deltas(resp):
                assistant_parts.append(delta)
                yield delta
        except RuntimeError:
            raise
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"anthropic error: stream read failed: {e}") from e
        finally:
            try:
                resp.close()
            except Exception:
                pass

        self.messages.append({"role": "assistant", "content": "".join(assistant_parts)})


def _iter_sse_deltas(resp) -> Iterator[str]:
    """Yield text deltas from Anthropic's ``content_block_delta`` events.

    The SSE stream carries ``event:`` and ``data:`` lines; we only need the
    JSON in ``data:``.  We emit text on ``content_block_delta`` events whose
    ``delta.type == "text_delta"`` and stop on ``message_stop``.
    """
    for raw in resp:
        line = raw.decode("utf-8", "replace").strip()
        if not line or not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if not payload:
            continue
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            continue
        etype = obj.get("type")
        if etype == "content_block_delta":
            delta = obj.get("delta") or {}
            if delta.get("type") == "text_delta":
                text = delta.get("text")
                if text:
                    yield text
        elif etype == "message_stop":
            break
        elif etype == "error":
            err = obj.get("error") or {}
            msg = err.get("message") or str(err)
            raise RuntimeError(f"anthropic error: {msg}")


def _read_error_body(err) -> str:
    """Extract a short human-readable message from an HTTPError body."""
    try:
        raw = err.read().decode("utf-8", "replace")
    except Exception:
        return ""
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            e = obj.get("error")
            if isinstance(e, dict) and e.get("message"):
                return str(e["message"])
            if obj.get("message"):
                return str(obj["message"])
    except json.JSONDecodeError:
        pass
    return raw[:500]
