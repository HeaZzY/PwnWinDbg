"""Parent-side tool executor: the concrete implementations behind every RPC
method the code-exec child may call.

Each public method of :class:`DebugTools` maps 1:1 (same name, same signature,
plain Python types with ``bytes`` as ``bytes``) to an RPC method in the frozen
contract. The child stub in ``agent_runtime.build_namespace`` calls these by
name through ``RpcServer``; the two ends MUST stay identical.

``dbg`` drives the real debugger via ``commands.dispatcher.dispatch`` while
capturing the Rich console output as plain text (the console is put into
``record`` mode by the agent loop). Resuming commands additionally render the
new context through ``handle_stop`` (imported lazily to dodge a circular
import). A small command blocklist prevents the AI from quitting the REPL.
"""

from ..commands.dispatcher import dispatch
from ..core.memory import read_memory, write_memory
from ..display import ai_view
from ..display.common import console, info
from ..utils.addr_expr import eval_expr


# Fallback blocklist used only if config can't be loaded for some reason.
_DEFAULT_BLOCKED = ("quit", "q", "exit", "ai")


def _blocked_commands():
    """Load the blocklist from ai.config lazily (avoid import cycles)."""
    try:
        from . import config
        blocked = config.load().get("blocked_commands") or []
        return {str(x).lower() for x in blocked}
    except Exception:
        return set(_DEFAULT_BLOCKED)


class DebugTools:
    """Bound set of debugger operations exposed to the AI over RPC."""

    def __init__(self, debugger):
        self.debugger = debugger

    # -- debugger command execution ------------------------------------

    def dbg(self, cmd):
        """Run a debugger command via dispatch; return its captured text.

        The command's output is printed live on the parent console AND
        captured (console is in ``record`` mode during an agent run). If the
        command resumes execution, the resulting context (via ``handle_stop``)
        is included in the returned text. Blocked commands are not executed.
        """
        cmd = (cmd or "").strip()
        if not cmd:
            return ""

        first = cmd.split(None, 1)[0].lower()
        if first in _blocked_commands() or first.startswith("ai"):
            return f"[blocked] {cmd}"

        # Flush anything the console recorded before we ran.
        try:
            console.export_text(clear=True)
        except Exception:
            pass

        stop_info = dispatch(self.debugger, cmd)

        if stop_info and stop_info.get("reason") != "quit":
            # Lazy import to avoid the __main__ <-> commands circular import.
            try:
                from ..__main__ import handle_stop
                handle_stop(self.debugger, stop_info)
            except Exception:
                pass

        try:
            text = console.export_text(clear=True)
        except Exception:
            text = ""
        return text.rstrip()

    # -- memory --------------------------------------------------------

    def read_mem(self, addr, size):
        """Read ``size`` bytes at ``addr`` from the debuggee. Returns bytes."""
        data = read_memory(self.debugger.process_handle, int(addr), int(size))
        try:
            ai_view.tool_activity(
                "read",
                f"{int(size)} B @ {int(addr):#x} -> {ai_view.hex_preview(data)}",
            )
        except Exception:
            pass
        return data

    def write_mem(self, addr, data):
        """Write ``data`` bytes at ``addr``. Returns bytes written."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("write_mem expects bytes")
        data = bytes(data)
        try:
            ai_view.tool_activity(
                "write",
                f"{len(data)} B @ {int(addr):#x}: {ai_view.hex_preview(data)}",
            )
        except Exception:
            pass
        return write_memory(self.debugger.process_handle, int(addr), data)

    # -- registers -----------------------------------------------------

    def regs(self):
        """Return the current register dict (name -> int)."""
        result = self.debugger.get_registers()
        # get_registers() returns (regs_dict, changed_set)
        if isinstance(result, tuple):
            result = result[0]
        return dict(result or {})

    def getreg(self, name):
        """Return one register value by name (case-insensitive)."""
        regs = self.regs()
        want = str(name).lower()
        for k, v in regs.items():
            if k.lower() == want:
                return int(v)
        raise RuntimeError(f"unknown register: {name}")

    def setreg(self, name, value):
        """Set a register via the ``set`` debugger command."""
        self.dbg(f"set {name} {int(value):#x}")
        try:
            ai_view.tool_activity("reg", f"set {name} = {int(value):#x}")
        except Exception:
            pass
        return None

    # -- debuggee tube (stdin/stdout) ----------------------------------

    def _tube(self):
        tube = getattr(self.debugger, "tube", None)
        if tube is None:
            raise RuntimeError(
                "no interactive tube: spawn the target with 'run -i <exe>'"
            )
        return tube

    def send(self, data):
        """Write ``data`` to the debuggee's stdin. Returns bytes written."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("send expects bytes")
        data = bytes(data)
        try:
            ai_view.tool_activity(
                "send", f"{len(data)} B: {ai_view.hex_preview(data)}"
            )
        except Exception:
            pass
        return self._tube().write(data)

    def sendline(self, data):
        """Like :meth:`send` but appends a newline."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("sendline expects bytes")
        data = bytes(data)
        try:
            ai_view.tool_activity(
                "send",
                f"{len(data) + 1} B (+\\n): {ai_view.hex_preview(data)}",
            )
        except Exception:
            pass
        return self._tube().write(data + b"\n")

    def recv(self, size=4096, timeout=1.0):
        """Receive up to ``size`` bytes from the debuggee's stdout."""
        data = self._tube().recv(int(size), float(timeout))
        try:
            ai_view.tool_activity(
                "recv", f"{len(data)} B: {ai_view.hex_preview(data)}"
            )
        except Exception:
            pass
        return data

    def recvuntil(self, delim, timeout=5.0):
        """Receive until ``delim`` (bytes) appears or ``timeout`` elapses."""
        if not isinstance(delim, (bytes, bytearray)):
            raise TypeError("recvuntil expects bytes delim")
        delim = bytes(delim)
        data = self._tube().recvuntil(delim, float(timeout))
        try:
            ai_view.tool_activity(
                "recv",
                f"{len(data)} B until {ai_view.hex_preview(delim)}: "
                f"{ai_view.hex_preview(data)}",
            )
        except Exception:
            pass
        return data

    def recvline(self, timeout=5.0):
        """Receive a single newline-terminated line."""
        data = self._tube().recvline(float(timeout))
        try:
            ai_view.tool_activity(
                "recv", f"{len(data)} B line: {ai_view.hex_preview(data)}"
            )
        except Exception:
            pass
        return data

    def shutdown_stdin(self):
        """Close the debuggee's stdin (send EOF) so a blocked read returns."""
        self._tube().shutdown_stdin()
        try:
            ai_view.tool_activity("info", "shutdown stdin (EOF sent to debuggee)")
        except Exception:
            pass
        return None

    # -- misc ----------------------------------------------------------

    def eval_addr(self, expr):
        """Evaluate an address expression to an int (raise if unresolved)."""
        val = eval_expr(self.debugger, str(expr))
        if val is None:
            raise RuntimeError(f"cannot evaluate address expression: {expr!r}")
        val = int(val)
        try:
            ai_view.tool_activity("eval", f"{expr} = {val:#x}")
        except Exception:
            pass
        return val

    def state(self):
        """Return a compact snapshot of debugger state as a dict."""
        dbg = self.debugger
        arch = "x86" if getattr(dbg, "is_wow64", False) else "x64"
        rip = None
        try:
            if getattr(dbg, "state", None) == "stopped":
                regs = self.regs()
                for key in ("Rip", "Eip"):
                    if key in regs:
                        rip = int(regs[key])
                        break
        except Exception:
            rip = None
        return {
            "state": getattr(dbg, "state", None),
            "pid": getattr(dbg, "process_id", None),
            "arch": arch,
            "rip": rip,
            "has_tube": getattr(dbg, "tube", None) is not None,
        }

    def log(self, msg):
        """Print an informational message on the parent console."""
        info(str(msg))
        return None

    def trace(self, kind, summary, detail=None):
        """Emit a one-line activity trace on the parent console.

        Public so the RPC server auto-dispatches it: the code-exec child uses
        it to surface its local-only actions (shell, file I/O) live.
        """
        ai_view.tool_activity(
            str(kind), str(summary), detail if detail is None else str(detail)
        )
        return None


# ---------------------------------------------------------------------------
# Helpers used by the agent loop (parent side, not over RPC)
# ---------------------------------------------------------------------------

def snapshot_context(debugger):
    """Capture the full context display as plain text to seed the agent.

    Uses the console ``record`` mechanism so the render is captured without
    disrupting the live display. Returns a short note if no process is live.
    """
    state = getattr(debugger, "state", None)
    if getattr(debugger, "process_handle", None) is None or state in (
        None, "idle", "terminated",
    ):
        return "(no live process — spawn one with 'run <exe>' or 'run -i <exe>')"

    prev_record = console.record
    console.record = True
    try:
        try:
            console.export_text(clear=True)
        except Exception:
            pass
        try:
            from ..commands.display_cmds import display_context
            display_context(debugger)
        except Exception as exc:
            return f"(context render failed: {exc})"
        try:
            text = console.export_text(clear=True)
        except Exception:
            text = ""
    finally:
        console.record = prev_record
    return text.rstrip() or "(empty context)"


def run_dbg_block(debugger, lines):
    """Run several debugger commands; return their concatenated output.

    Each section is ``"<cmd>\\n<output>"``; sections are separated by blank
    lines. Blank/comment lines in ``lines`` are skipped.
    """
    tools = DebugTools(debugger)
    sections = []
    for raw in lines:
        cmd = (raw or "").strip()
        if not cmd or cmd.startswith("#"):
            continue
        out = tools.dbg(cmd)
        sections.append(f"{cmd}\n{out}" if out else cmd)
    return "\n\n".join(sections)
