"""Live "cockpit" view for the in-debugger AI agent.

Renders a two-column Rich layout while the agent works: the LEFT column is a
rolling log of the agent's reasoning and the debugger commands it issues (so you
watch it drive the debugger — ``ni``, ``bp`` … — in your place), and the RIGHT
column is a live panel of registers + stack + backtrace that refreshes after
each command so you see the state evolve.

Everything is exception-safe: if there is no real terminal or Rich Live fails,
the caller falls back to the plain linear :mod:`ai_view` output. Register/stack
reads are done read-only (no ``prev_regs`` mutation) so the agent's cockpit
never disturbs the debugger's own change-highlighting.
"""

from collections import deque

from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from .common import (
    console, ADDR_COLOR, SYMBOL_COLOR, BANNER_COLOR, STRING_COLOR,
    CHAIN_ARROW_COLOR,
)


def _sym(debugger, addr):
    try:
        return debugger.symbols.resolve_address(addr) or ""
    except Exception:
        return ""


class AgentCockpit:
    """A live left(activity)/right(debugger-state) layout for an agent run."""

    def __init__(self, debugger, task, max_log=400):
        self.debugger = debugger
        self.task = task
        self.log = deque(maxlen=max_log)     # Text lines for the left column
        self._reasoning = ""                 # in-progress streamed line
        self._state = None                   # cached right-column renderable
        self._step = (0, 0)
        self.live = None
        self.layout = Layout()
        self.layout.split_row(
            Layout(name="activity", ratio=3),
            Layout(name="state", ratio=2, minimum_size=40),
        )

    # ---- lifecycle -------------------------------------------------------
    def start(self):
        self.log.append(Text.assemble(
            ("task: ", "bold " + SYMBOL_COLOR), (str(self.task), STRING_COLOR)))
        self._rebuild_state()
        try:
            self.live = Live(
                self._render(), console=console, screen=False,
                auto_refresh=True, refresh_per_second=8, transient=False,
            )
            self.live.start()
            return True
        except Exception:
            self.live = None
            return False

    def stop(self):
        self._flush_reasoning()
        if self.live is not None:
            try:
                self.live.update(self._render(), refresh=True)
            except Exception:
                pass
            try:
                self.live.stop()
            except Exception:
                pass
            self.live = None

    # ---- event sink (mirrors ai_view) ------------------------------------
    def step(self, n, total):
        self._flush_reasoning()
        self._step = (n, total)
        self.log.append(Text.assemble(
            ("▶ step ", "bold " + BANNER_COLOR),
            (f"{n}", "bold " + ADDR_COLOR), ("/", BANNER_COLOR),
            (f"{total}", ADDR_COLOR)))
        self._paint()

    def reasoning(self, delta):
        if not delta:
            return
        self._reasoning += delta
        while "\n" in self._reasoning:
            line, self._reasoning = self._reasoning.split("\n", 1)
            self.log.append(Text("  " + line, style="dim cyan", overflow="fold"))
        self._paint(refresh=False)

    def command(self, kind, snippet):
        """Highlight the command(s) the agent is issuing on our behalf."""
        self._flush_reasoning()
        tag = "dbg" if kind == "dbg" else "py"
        for line in str(snippet).splitlines():
            if line.strip():
                self.log.append(Text.assemble(
                    (f"  {tag}❯ ", "bold " + STRING_COLOR),
                    (line, "bold white")))
        self._paint()

    def output(self, text):
        """Append (a tail of) a command's output, then refresh debugger state."""
        lines = [ln for ln in str(text).splitlines() if ln.strip()]
        for ln in lines[-6:]:
            self.log.append(Text("    " + ln, style="bright_black",
                                 overflow="ellipsis", no_wrap=True))
        self._rebuild_state()
        self._paint()

    def note(self, text):
        self.log.append(Text("  " + str(text), style="dim yellow"))
        self._paint()

    # ---- rendering -------------------------------------------------------
    def _flush_reasoning(self):
        if self._reasoning.strip():
            self.log.append(Text("  " + self._reasoning.rstrip(),
                                 style="dim cyan", overflow="fold"))
        self._reasoning = ""

    def _paint(self, refresh=True):
        if self.live is None:
            return
        try:
            self.live.update(self._render(), refresh=refresh)
        except Exception:
            pass

    def _render(self):
        # Left: tail of the activity log sized to the terminal height.
        try:
            height = console.size.height or 30
        except Exception:
            height = 30
        tail = list(self.log)[-(max(6, height - 4)):]
        if self._reasoning.strip():
            tail = tail + [Text("  " + self._reasoning, style="dim cyan",
                                overflow="fold")]
        body = Group(*tail) if tail else Text("")
        n, total = self._step
        title = f"AI agent — step {n}/{total}" if total else "AI agent"
        self.layout["activity"].update(
            Panel(body, title=title, border_style=BANNER_COLOR, padding=(0, 1)))
        self.layout["state"].update(self._state or Text(""))
        return self.layout

    def _rebuild_state(self):
        """Recompute the right-hand register/stack/backtrace panel (read-only)."""
        d = self.debugger
        try:
            if not getattr(d, "process_handle", None):
                self._state = Panel(Text("(no running process)",
                                         style="bright_black"),
                                    title="debugger", border_style=BANNER_COLOR)
                return
            parts = []
            parts.extend(self._regs_lines())
            parts.append(Text("stack", style="bold " + BANNER_COLOR))
            parts.extend(self._stack_lines())
            parts.append(Text("backtrace", style="bold " + BANNER_COLOR))
            parts.extend(self._bt_lines())
            self._state = Panel(Group(*parts), title="debugger state",
                                border_style=BANNER_COLOR, padding=(0, 1))
        except Exception:
            self._state = Panel(Text("(state unavailable)", style="bright_black"),
                                title="debugger state", border_style=BANNER_COLOR)

    def _regs_lines(self):
        """A compact register summary read WITHOUT mutating the debugger."""
        d = self.debugger
        out = []
        try:
            from ..core.registers import get_context, context_to_dict
            th = d.get_active_thread_handle()
            if not th:
                return out
            regs = context_to_dict(get_context(th, d.is_wow64), d.is_wow64)
        except Exception:
            return out
        wow = d.is_wow64
        ipk, spk, bpk = (("Eip", "Esp", "Ebp") if wow else ("Rip", "Rsp", "Rbp"))
        ip = regs.get(ipk, 0)
        sym = _sym(d, ip)
        ipline = Text.assemble(("● ", "bold red"),
                               (self._fmt(ip), ADDR_COLOR))
        if sym:
            ipline.append("  " + sym, style=SYMBOL_COLOR)
        out.append(ipline)
        gp = (["Eax", "Ebx", "Ecx", "Edx", "Esi", "Edi", spk, bpk] if wow
              else ["Rax", "Rbx", "Rcx", "Rdx", "Rsi", "Rdi", spk, bpk])
        row = Text()
        for i, k in enumerate(gp):
            if k not in regs:
                continue
            row.append(f"{k.lower():>3} ", style="yellow")
            row.append(self._fmt(regs[k]) + " ", style="white")
            if i % 2 == 1:
                out.append(row)
                row = Text()
        if str(row):
            out.append(row)
        return out

    def _stack_lines(self):
        d = self.debugger
        out = []
        try:
            entries, sp = d.get_stack_entries(count=6)
        except Exception:
            return out
        for addr, val in entries:
            off = addr - sp
            line = Text()
            line.append(f"{off:+04x} ", style="bright_black")
            line.append("│ ", style="bright_black")
            if val is None:
                line.append("????", style="bright_red")
            else:
                line.append(self._fmt(val), style="white")
                s = _sym(d, val)
                if s:
                    line.append(" " + s, style=SYMBOL_COLOR)
            line.no_wrap = True
            line.overflow = "ellipsis"
            out.append(line)
        return out

    def _bt_lines(self):
        d = self.debugger
        out = []
        try:
            frames = d.get_backtrace(6)
        except Exception:
            return out
        for idx, addr in frames:
            s = _sym(d, addr) or self._fmt(addr)
            line = Text.assemble((f"#{idx} ", "bright_black"),
                                 (self._fmt(addr) + " ", ADDR_COLOR),
                                 (s, SYMBOL_COLOR))
            line.no_wrap = True
            line.overflow = "ellipsis"
            out.append(line)
        return out

    def _fmt(self, v):
        try:
            return ("0x%08x" if self.debugger.ptr_size == 4 else "0x%016x") % (
                v & (0xFFFFFFFF if self.debugger.ptr_size == 4 else 0xFFFFFFFFFFFFFFFF))
        except Exception:
            return hex(v) if isinstance(v, int) else str(v)
