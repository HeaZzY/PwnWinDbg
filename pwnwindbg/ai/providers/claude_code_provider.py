"""Claude Code CLI provider (the CLI is used purely as the reasoning brain).

We do NOT rely on the CLI's own agentic tool use or MCP.  Instead we run in a
**stateless-transcript** mode that is robust across CLI versions:

  * every ``send()`` serializes the whole conversation (system prompt + prior
    turns + the new user text) into one prompt string;
  * we invoke ``<binary> -p --output-format stream-json --verbose --max-turns 1
    [--model <model>] [extra_args]`` and write that prompt to the process
    **stdin** (``claude -p`` with no inline prompt reads stdin);
  * we parse the stream-json output line by line, extracting assistant text and
    yielding it as it appears;
  * history is kept in the session so the next prompt includes it.

``--max-turns 1`` keeps the CLI to a single reasoning turn (no autonomous tool
use); the debugger driving happens in *our* agent loop, not the CLI's.
"""

import json
import os
import shutil
import subprocess
import time
from typing import Iterator, List

from .base import AgentSession


def _candidate_paths(binary):
    """Common install locations to probe when PATH lookup misses ``binary``."""
    home = os.path.expanduser("~")
    if os.name == "nt" and not binary.lower().endswith((".exe", ".cmd", ".bat")):
        names = [binary + ".exe", binary + ".cmd", binary]
    else:
        names = [binary]
    dirs = [
        os.path.join(home, ".local", "bin"),
        os.path.join(os.environ.get("APPDATA", ""), "npm"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", binary),
        "/usr/local/bin",
        "/usr/bin",
    ]
    out = []
    for d in dirs:
        if not d:
            continue
        out.extend(os.path.join(d, n) for n in names)
    return out


def _resolve_launcher(binary):
    """Return an argv prefix that can actually launch ``binary``.

    On Windows the ``claude`` command installed by npm is a ``.cmd``/``.ps1``
    shim, and ``CreateProcess`` (what ``subprocess`` uses) cannot execute those
    directly — only ``.exe``. We resolve the real path via :func:`shutil.which`
    (honouring PATHEXT), fall back to common install dirs when PATH misses it
    (the dir may not be on the PATH this Python process inherited), and wrap
    ``.cmd``/``.bat`` with ``cmd /c`` and ``.ps1`` with PowerShell so
    stdin/stdout piping still works.
    """
    resolved = shutil.which(binary)
    is_bare = (os.sep not in binary) and ("/" not in binary)
    if not resolved and is_bare:
        for cand in _candidate_paths(binary):
            if os.path.exists(cand):
                resolved = cand
                break
    resolved = resolved or binary
    if os.name == "nt":
        low = resolved.lower()
        if low.endswith((".cmd", ".bat")):
            return ["cmd", "/c", resolved]
        if low.endswith(".ps1"):
            return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", resolved]
    return [resolved]


class ClaudeCodeSession(AgentSession):
    """Session that shells out to the Claude Code CLI per turn."""

    def __init__(self, cfg: dict, system_prompt: str):
        super().__init__(cfg, system_prompt)
        self._section = (cfg or {}).get("claude_code") or {}

    def _build_argv(self) -> List[str]:
        binary = self._section.get("binary") or "claude"
        argv = _resolve_launcher(binary) + [
            "-p",
            "--output-format", "stream-json",
            "--verbose",
            "--max-turns", "1",
            # Disable ALL of Claude Code's built-in tools (Bash/Read/Write/...).
            # We use the CLI purely as a text reasoner that emits our fenced
            # ```dbg / ```python blocks. If it could call its own tools it would
            # trip --max-turns 1 and die with error_max_turns instead of
            # answering. "" means "disable all tools" per `claude --help`.
            "--tools", "",
        ]
        model = self._section.get("model")
        if model:
            argv += ["--model", str(model)]
        extra = self._section.get("extra_args") or []
        if isinstance(extra, (list, tuple)):
            argv += [str(a) for a in extra]
        return argv

    def _serialize_prompt(self, user_text: str) -> str:
        """Flatten system prompt + history + new user turn into one string.

        The debugger system prompt goes at the very TOP so behaviour does not
        depend on ``--append-system-prompt`` support.
        """
        parts = []
        if self.system_prompt:
            parts.append("[SYSTEM]\n" + self.system_prompt)
        for msg in self.messages:
            role = (msg.get("role") or "user").upper()
            parts.append(f"[{role}]\n{msg.get('content', '')}")
        parts.append("[USER]\n" + user_text)
        parts.append("[ASSISTANT]\n")
        return "\n\n".join(parts)

    def send(self, user_text: str) -> Iterator[str]:
        # NOTE: do NOT append the user turn to history until we succeed —
        # _serialize_prompt iterates self.messages (prior turns) and appends
        # this user_text as the trailing [USER] block; appending first would
        # duplicate it, and a failed attempt should not pollute history.
        argv = self._build_argv()
        prompt = self._serialize_prompt(user_text)

        try:
            attempts = max(1, int(self._section.get("retries", 2)) + 1)
        except (TypeError, ValueError):
            attempts = 3

        last_error = None
        for attempt in range(1, attempts + 1):
            produced = []
            try:
                for text in self._run_once(argv, prompt):
                    produced.append(text)
                    yield text
            except RuntimeError as e:
                if produced:
                    # Already streamed part of a reply — can't retry cleanly.
                    raise
                last_error = e
                if attempt < attempts:
                    # The whole call produced nothing — treat as a transient
                    # CLI/API hiccup, back off, and retry the identical request.
                    time.sleep(min(2.0 * attempt, 6.0))
                    continue
                raise RuntimeError(f"{e} [after {attempts} attempts]")
            # Success: commit the turn to history.
            self.messages.append({"role": "user", "content": user_text})
            self.messages.append({"role": "assistant", "content": "".join(produced)})
            return

    def _run_once(self, argv, prompt) -> Iterator[str]:
        """One CLI invocation: stream assistant text, or raise on empty/failure."""
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except FileNotFoundError as e:
            raise RuntimeError(
                f"claude_code error: CLI binary {argv[0]!r} not found on PATH. "
                "Install the Claude Code CLI or set claude_code.binary in the config."
            ) from e
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"claude_code error: failed to launch CLI: {e}") from e

        # Feed the prompt on stdin then close it so the CLI starts producing.
        try:
            proc.stdin.write(prompt)
            proc.stdin.close()
        except Exception as e:  # noqa: BLE001
            _kill(proc)
            raise RuntimeError(f"claude_code error: failed to send prompt: {e}") from e

        assistant_parts: List[str] = []
        result_fallback = [None]
        saw_delta = [False]
        meta = {}

        try:
            for text in _iter_stream_json(proc.stdout, result_fallback, meta):
                saw_delta[0] = True
                assistant_parts.append(text)
                yield text
        except Exception as e:  # noqa: BLE001
            _kill(proc)
            raise RuntimeError(f"claude_code error: failed to parse CLI output: {e}") from e

        stderr_text = ""
        try:
            if proc.stderr is not None:
                stderr_text = proc.stderr.read() or ""
        except Exception:
            stderr_text = ""

        rc = proc.wait()

        # If streaming yielded nothing, fall back to the final result object.
        if not saw_delta[0]:
            final = result_fallback[0]
            if final:
                assistant_parts.append(final)
                yield final

        if not "".join(assistant_parts):
            raise RuntimeError(_empty_output_error(meta, stderr_text, rc))


def _iter_stream_json(stdout, result_fallback, meta=None) -> Iterator[str]:
    """Yield assistant text from a Claude Code ``stream-json`` stdout stream.

    Each stdout line is a standalone JSON object.  We handle:
      * ``type == "assistant"`` -> ``message.content[]`` items with
        ``type == "text"`` (full assistant message blocks);
      * streaming ``content_block_delta`` objects carrying ``delta.text``;
      * ``type == "result"`` -> stash ``result`` as a fallback for the case
        where no text deltas were seen (and record error results in ``meta``);
      * ``type == "rate_limit_event"`` -> record limit/credit status in ``meta``
        so an empty response yields an actionable error.
    """
    if stdout is None:
        return
    if meta is None:
        meta = {}
    for line in stdout:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue

        otype = obj.get("type")

        if otype == "assistant":
            message = obj.get("message") or {}
            for block in message.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text")
                    if text:
                        yield text
        elif otype == "content_block_delta":
            delta = obj.get("delta") or {}
            text = delta.get("text")
            if text:
                yield text
        elif otype == "rate_limit_event":
            meta["rate_limit"] = obj.get("rate_limit_info") or {}
        elif otype == "result":
            res = obj.get("result")
            if isinstance(res, str) and res:
                result_fallback[0] = res
            if obj.get("is_error") or (obj.get("subtype") not in (None, "success")):
                meta["result_error"] = obj.get("result") or obj.get("subtype")


def _empty_output_error(meta, stderr_text, rc) -> str:
    """Build an actionable message when the CLI returned no assistant text."""
    parts = []
    rl = (meta or {}).get("rate_limit") or {}
    status = rl.get("status")
    # NB: overage being "rejected"/out_of_credits while status=="allowed" is the
    # NORMAL subscription state (pay-as-you-go off) — do NOT report it as an
    # error. Only a status other than "allowed" is a real usage-limit block.
    if status and status != "allowed":
        parts.append(
            f"Claude usage limit hit (status={status}, "
            f"overage={rl.get('overageStatus')}, "
            f"reason={rl.get('overageDisabledReason')})"
        )
    result_error = (meta or {}).get("result_error")
    if result_error:
        if str(result_error) == "error_max_turns":
            parts.append("CLI stopped with error_max_turns (it tried to use a "
                         "built-in tool). Tools are disabled via --tools \"\"; "
                         "if this persists, update the Claude CLI.")
        else:
            parts.append(str(result_error))
    if stderr_text and stderr_text.strip():
        parts.append(stderr_text.strip()[:300])
    if not parts:
        parts.append(f"CLI exited with code {rc}, no output")
    return (
        "claude_code error: " + " | ".join(parts)
        + ". Tips: pick a cheaper model (ai config set claude_code.model "
        "claude-sonnet-4-6), wait for the limit to reset, or switch provider "
        "(ai use openai / ai use anthropic + ai key ...)."
    )


def _kill(proc):
    """Best-effort terminate a subprocess without raising."""
    try:
        proc.kill()
    except Exception:
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        pass
