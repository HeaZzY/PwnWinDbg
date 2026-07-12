"""Autonomous agent loop for the in-debugger AI.

`run_agent` orchestrates a single one-shot task: it starts the loopback RPC
server, builds the system prompt + initial context, and then drives the LLM in a
read-eval loop. Each assistant turn may contain fenced ```dbg / ```python
blocks; those are executed (dbg commands via the dispatcher, python via an
isolated child process talking back over RPC) and their output is fed back to
the model as the next observation. Ctrl+C pauses the loop for steering (or
interrupts a running debuggee). Every failure surfaces via ``error`` but must
never crash the REPL.
"""

import os
import re
import signal
import subprocess
import sys
import tempfile

from ..display.common import console, error, info, warn
from ..display import ai_view
from . import config
from .tools import DebugTools, snapshot_context, run_dbg_block
from .rpc_server import RpcServer
from .providers.base import create_session
from .system_prompt import build_system_prompt, CMD_CHEATSHEET


# Repo root (the directory that CONTAINS the ``pwnwindbg`` package) so a
# code-exec child launched with ``-m pwnwindbg.ai.child_runner`` can import the
# package no matter what the user's current working directory is. agent.py lives
# at ``<root>/pwnwindbg/ai/agent.py`` → three dirnames up is ``<root>``.
_PKG_PARENT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


# Matches a fenced ```dbg / ```python block. The language tag is followed by a
# newline; DOTALL lets the body span lines; non-greedy so blocks don't merge.
_BLOCK_RE = re.compile(
    r"```(dbg|python)[ \t]*\r?\n(.*?)```",
    re.DOTALL | re.IGNORECASE,
)

# Set by the SIGINT handler when the debuggee is not running (steer request).
_pause = False


def _parse_blocks(text):
    """Return a list of (kind, body) fenced blocks in document order.

    ``kind`` is lowercased ("dbg" or "python"); ``body`` is the block contents.
    """
    blocks = []
    for m in _BLOCK_RE.finditer(text or ""):
        kind = m.group(1).lower()
        body = m.group(2)
        blocks.append((kind, body))
    return blocks


def _truncate_obs(text, limit):
    """Truncate an observation to ``limit`` chars, keeping head + tail."""
    if limit <= 0 or len(text) <= limit:
        return text
    half = max(limit // 2, 1)
    head = text[:half]
    tail = text[-half:]
    omitted = len(text) - len(head) - len(tail)
    return f"{head}\n... [truncated {omitted} chars] ...\n{tail}"


def run_python_child(script, host, port, token, cfg):
    """Run a ```python block in an isolated child process, streaming output.

    The script is written to a temp file and executed via the child_runner
    module. The child's stdout/stderr (combined) is the observation; it is
    streamed live to the console while collected. Honors ``cfg["python_timeout"]``
    and kills the child on timeout or Ctrl+C.

    Returns the collected stdout, with a "[killed: ...]" note on abnormal exit.
    """
    tmp_path = None
    proc = None
    collected = []
    killed_note = ""
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="pwndbg_ai_", suffix=".py")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(script)

        child_env = dict(os.environ)
        child_env["PWNWINDBG_RPC_HOST"] = str(host)
        child_env["PWNWINDBG_RPC_PORT"] = str(port)
        child_env["PWNWINDBG_RPC_TOKEN"] = str(token)
        # Ensure the child can import the pwnwindbg package regardless of cwd.
        _existing_pp = child_env.get("PYTHONPATH", "")
        child_env["PYTHONPATH"] = (
            _PKG_PARENT + (os.pathsep + _existing_pp if _existing_pp else "")
        )

        proc = subprocess.Popen(
            [sys.executable, "-m", "pwnwindbg.ai.child_runner", tmp_path],
            env=child_env,
            cwd=os.getcwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        timeout = cfg.get("python_timeout", 120)
        import threading

        def _pump():
            try:
                for line in iter(proc.stdout.readline, ""):
                    collected.append(line)
                    ai_view.stream_tool_output(line)
            except Exception:
                pass

        pump = threading.Thread(target=_pump, daemon=True)
        pump.start()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_proc(proc)
            killed_note = "\n[killed: timeout]"
        except KeyboardInterrupt:
            _kill_proc(proc)
            killed_note = "\n[killed: interrupted]"
        pump.join(timeout=2.0)
    except Exception as exc:
        killed_note = f"\n[child error: {exc}]"
    finally:
        if proc is not None and proc.poll() is None:
            _kill_proc(proc)
        try:
            if proc is not None and proc.stdout is not None:
                proc.stdout.close()
        except Exception:
            pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    return ("".join(collected).rstrip() + killed_note).strip()


def _kill_proc(proc):
    """Best-effort terminate then kill a child process."""
    try:
        proc.terminate()
    except Exception:
        pass
    try:
        proc.wait(timeout=2.0)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_agent(debugger, task):
    """Run one autonomous AI task against the debugger. Returns None.

    Never raises out to the REPL; failures are reported via ``error``.
    """
    global _pause
    _pause = False

    if not task or not task.strip():
        error('ai: empty task. Usage: ai "<task>"')
        return None

    try:
        cfg = config.load()
    except Exception as exc:
        error(f"ai: could not load config: {exc}")
        return None

    tools = DebugTools(debugger)
    server = None
    cockpit = None
    prev_record = getattr(console, "record", False)
    prev_run_timeout = getattr(debugger, "run_timeout", None)
    prev_sigint = None
    installed_sigint = False

    # Bound every agent-driven `continue`/step so a debuggee blocked on stdin
    # returns control (as a "timeout" stop) instead of hanging the loop.
    try:
        debugger.run_timeout = float(cfg.get("continue_timeout", 15) or 15)
    except Exception:
        debugger.run_timeout = 15

    try:
        server = RpcServer(tools)
        host, port, token = server.start()
    except Exception as exc:
        error(f"ai: failed to start RPC server: {exc}")
        return None

    console.record = True

    def _sigint_handler(signum, frame):
        global _pause
        try:
            from ..core.debugger import DebuggerState
            if getattr(debugger, "state", None) == DebuggerState.RUNNING:
                debugger.interrupt()
                return
        except Exception:
            pass
        _pause = True

    try:
        prev_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, _sigint_handler)
        installed_sigint = True
    except Exception:
        installed_sigint = False

    # Bring up the live cockpit (left: reasoning + issued commands, right:
    # registers/stack/backtrace) unless disabled or there's no real terminal.
    if bool(cfg.get("live_view", True)) and getattr(console, "is_terminal", False):
        try:
            from ..display.ai_cockpit import AgentCockpit
            cockpit = AgentCockpit(debugger, task)
            if cockpit.start():
                ai_view.set_active(cockpit)
            else:
                cockpit = None
        except Exception:
            cockpit = None

    try:
        ai_view.agent_header(task)

        # Seed context: a plain-text snapshot of the current debugger state.
        try:
            state_summary = snapshot_context(debugger)
        except Exception as exc:
            state_summary = f"(context unavailable: {exc})"

        code_exec = bool(cfg.get("code_exec", True))
        system = build_system_prompt(state_summary, code_exec, CMD_CHEATSHEET)

        try:
            session = create_session(cfg, system)
        except Exception as exc:
            error(f"ai: could not start provider session: {exc}")
            return None

        max_steps = int(cfg.get("max_steps", 30) or 30)
        max_obs = int(cfg.get("max_obs_chars", 6000) or 6000)

        user_text = (
            f"TASK:\n{task}\n\n"
            f"Initial debugger context:\n{state_summary}\n\n"
            "Begin. Inspect state as needed and act."
        )

        no_block_streak = 0
        for step in range(1, max_steps + 1):
            ai_view.step_header(step, max_steps)

            # Stream the assistant turn, printing reasoning live and
            # accumulating the full text for block parsing.
            full = []
            try:
                for delta in session.send(user_text):
                    full.append(delta)
                    ai_view.stream_reasoning(delta)
            except KeyboardInterrupt:
                warn("ai: interrupted during model response")
                break
            except Exception as exc:
                error(f"ai: provider error: {exc}")
                break
            full_text = "".join(full)

            blocks = _parse_blocks(full_text)
            if not blocks:
                # No actionable block. This is EITHER a genuine final answer OR
                # the model just narrated its intent ("I'll start by...") without
                # acting. Don't stop on a short, non-conclusive first no-block
                # turn — nudge it to act or truly finalize. Accept as final when
                # it's a substantial conclusion, or on a second consecutive
                # no-block turn (so we can't loop forever).
                if no_block_streak >= 1 or len(full_text.strip()) > 400:
                    ai_view.final_answer(full_text)
                    break
                no_block_streak += 1
                info("ai: no action block — nudging the agent to act or finalize")
                user_text = (
                    "Your last message contained no ```dbg or ```python block, "
                    "so NOTHING was executed and you received no new observation. "
                    "Do not merely describe what you will do. If the task is "
                    "FULLY solved, give your final answer now. Otherwise emit a "
                    "```dbg or ```python block RIGHT NOW to take the next "
                    "concrete step."
                )
                continue
            no_block_streak = 0

            observations = []
            for kind, body in blocks:
                if kind == "dbg":
                    lines = [ln for ln in body.splitlines() if ln.strip()]
                    ai_view.tool_call("dbg", "\n".join(lines))
                    try:
                        out = run_dbg_block(debugger, lines)
                    except Exception as exc:
                        out = f"[dbg error: {exc}]"
                    ai_view.command_result(out)  # feeds the cockpit state panel
                    observations.append("[dbg output]\n" + out)
                elif kind == "python":
                    if not code_exec:
                        observations.append(
                            "[python output]\n[disabled: code_exec is off]"
                        )
                        continue
                    ai_view.tool_call("python", body)
                    try:
                        out = run_python_child(body, host, port, token, cfg)
                    except Exception as exc:
                        out = f"[python error: {exc}]"
                    ai_view.command_result(out)  # main-thread cockpit update
                    observations.append("[python output]\n" + out)

            obs_text = "\n\n".join(observations).strip()
            obs_text = _truncate_obs(obs_text, max_obs)

            # Ctrl+C steering: if a pause was requested (debuggee not running),
            # let the user resume, stop, or inject guidance.
            if _pause:
                _pause = False
                try:
                    steer = ai_view.steer_prompt()
                except Exception:
                    steer = "stop"
                steer = (steer or "").strip()
                if steer.lower() == "stop":
                    info("ai: stopped by user")
                    break
                if steer:
                    obs_text = (
                        f"{obs_text}\n\n[user steering]\n{steer}"
                        if obs_text else f"[user steering]\n{steer}"
                    )

            user_text = obs_text if obs_text else "(no output; continue)"
        else:
            warn(f"ai: reached max steps ({max_steps}); stopping")

    except KeyboardInterrupt:
        warn("ai: run cancelled")
    except Exception as exc:
        error(f"ai: unexpected error: {exc}")
    finally:
        if cockpit is not None:
            try:
                cockpit.stop()
            except Exception:
                pass
            ai_view.set_active(None)
        if server is not None:
            try:
                server.stop()
            except Exception:
                pass
        if installed_sigint and prev_sigint is not None:
            try:
                signal.signal(signal.SIGINT, prev_sigint)
            except Exception:
                pass
        try:
            console.record = prev_record
        except Exception:
            pass
        try:
            debugger.run_timeout = prev_run_timeout
        except Exception:
            pass

    return None
