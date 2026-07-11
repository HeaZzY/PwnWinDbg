"""OpenAI-compatible ``/chat/completions`` provider (streaming SSE).

Works with any OpenAI-compatible endpoint: Kimi/Moonshot, DeepSeek, OpenRouter,
local servers, etc.  HTTP is done with the standard library (:mod:`urllib`); no
``requests``/``httpx`` dependency.
"""

import json
import urllib.request
import urllib.error
from typing import Iterator

from .base import AgentSession, _effective_key


class OpenAISession(AgentSession):
    """Chat session against an OpenAI-compatible ``/chat/completions`` endpoint."""

    def __init__(self, cfg: dict, system_prompt: str):
        super().__init__(cfg, system_prompt)
        self._section = (cfg or {}).get("openai") or {}

    def _endpoint(self) -> str:
        base = (self._section.get("base_url") or "https://api.openai.com/v1").rstrip("/")
        return base + "/chat/completions"

    def _build_messages(self):
        msgs = []
        if self.system_prompt:
            msgs.append({"role": "system", "content": self.system_prompt})
        msgs.extend(self.messages)
        return msgs

    def send(self, user_text: str) -> Iterator[str]:
        self.messages.append({"role": "user", "content": user_text})

        key = _effective_key(self.cfg, "openai")
        if not key:
            raise RuntimeError(
                "openai error: no API key. Set it with 'ai key openai <value>' "
                "or export the configured api_key_env."
            )

        model = self._section.get("model") or "gpt-4o-mini"
        body = {
            "model": model,
            "messages": self._build_messages(),
            "temperature": self.cfg.get("temperature", 0.2),
            "max_tokens": self._section.get("max_tokens", 4096),
            "stream": True,
        }
        data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(
            self._endpoint(),
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + key,
                "Accept": "text/event-stream",
            },
        )

        assistant_parts = []
        try:
            resp = urllib.request.urlopen(req, timeout=600)
        except urllib.error.HTTPError as e:
            detail = _read_error_body(e)
            raise RuntimeError(f"openai error: HTTP {e.code} {e.reason}: {detail}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"openai error: connection failed: {e.reason}") from e
        except Exception as e:  # noqa: BLE001 - surface anything as RuntimeError
            raise RuntimeError(f"openai error: {e}") from e

        try:
            for delta in _iter_sse_deltas(resp):
                assistant_parts.append(delta)
                yield delta
        except RuntimeError:
            raise
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"openai error: stream read failed: {e}") from e
        finally:
            try:
                resp.close()
            except Exception:
                pass

        self.messages.append({"role": "assistant", "content": "".join(assistant_parts)})


def _iter_sse_deltas(resp) -> Iterator[str]:
    """Yield ``choices[0].delta.content`` text deltas from an SSE stream.

    Iterating the response yields raw bytes lines; we decode, strip the
    ``data: `` prefix, stop on ``[DONE]`` and json-decode the rest.
    """
    for raw in resp:
        line = raw.decode("utf-8", "replace").strip()
        if not line or not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if payload == "[DONE]":
            break
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            continue
        choices = obj.get("choices") or []
        if not choices:
            continue
        delta = choices[0].get("delta") or {}
        content = delta.get("content")
        if content:
            yield content


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
            if isinstance(e, str):
                return e
            if obj.get("message"):
                return str(obj["message"])
    except json.JSONDecodeError:
        pass
    return raw[:500]
