"""Live decompile pane rendering.

Renders the cached pseudo-C for a function with the current source line
highlighted. Prefers Rich ``Syntax`` (C lexer + line numbers + highlight_lines);
falls back to a styled ``Text`` and ultimately a plain print. Never raises.
"""

try:
    from .common import console, banner
except Exception:  # pragma: no cover - importable in isolation
    console = None

    def banner(*_a, **_k):
        pass

import re

from ..core.decompiler import line_for_addr


# Show the whole function up to this many lines; beyond it, window around cur.
_WHOLE_FUNC_MAX = 60
_WINDOW_BEFORE = 25
_WINDOW_AFTER = 25

# Trailing `// ... 0xADDR ...` mapping annotation — stripped for display (the
# address->line map is kept separately in the result). One comment per line,
# so stripping never changes the line count and highlight indices stay aligned.
_DISP_ANNOT = re.compile(r"\s*//[^\n]*0x[0-9A-Fa-f]+[^\n]*$")


def _clean_code(code):
    """Strip trailing address-mapping comments for a clean on-screen render."""
    return "\n".join(_DISP_ANNOT.sub("", ln) for ln in (code or "").split("\n"))


def _render_syntax(code, cur, win_start, win_end):
    """Return a Rich Syntax renderable for the window, or None if unavailable.

    ``code`` is the full function text; ``cur`` is a 0-based line index (or None);
    ``win_start``/``win_end`` are 0-based, end-exclusive line bounds. Line
    numbering / highlighting are given as absolute 1-based numbers into ``code``
    and the visible slice is selected via ``line_range``.
    """
    try:
        from rich.syntax import Syntax
    except Exception:
        return None
    kwargs = dict(
        theme="ansi_dark",
        line_numbers=True,
        word_wrap=False,
        line_range=(win_start + 1, win_end),
    )
    if cur is not None:
        kwargs["highlight_lines"] = {cur + 1}
    try:
        return Syntax(code, "c", **kwargs)
    except Exception:
        return None


def _render_text(lines, cur, win_start, win_end):
    """Fallback renderer: styled Rich Text, or plain print as last resort."""
    if console is None:
        for idx in range(win_start, win_end):
            prefix = ">> " if idx == cur else "   "
            try:
                print(prefix + lines[idx])
            except Exception:
                pass
        return
    try:
        from rich.text import Text
        out = Text()
        for idx in range(win_start, win_end):
            line = lines[idx]
            if idx == cur:
                out.append(f"{idx + 1:>4} ▶ {line}\n", style="reverse bold")
            else:
                out.append(f"{idx + 1:>4}   {line}\n", style="dim")
        console.print(out)
    except Exception:
        for idx in range(win_start, win_end):
            prefix = ">> " if idx == cur else "   "
            try:
                console.print(prefix + lines[idx])
            except Exception:
                pass


def _window(result, current_addr):
    """Return (lines, cur, win_start, win_end) for the current view window."""
    code = result.get("code", "") or ""
    lines = result.get("lines")
    if not isinstance(lines, list):
        lines = code.split("\n")
    total = len(lines)
    try:
        cur = line_for_addr(result, current_addr)
    except Exception:
        cur = None
    win_start, win_end = 0, total
    if total > _WHOLE_FUNC_MAX and cur is not None:
        win_start = max(0, cur - _WINDOW_BEFORE)
        win_end = min(total, cur + _WINDOW_AFTER + 1)
    return lines, cur, win_start, win_end


def _ansi_to_text(ansi):
    """ANSI text -> Rich Text, dropping a leading banner/separator line."""
    from rich.text import Text
    lines = (ansi or "").rstrip("\n").split("\n")
    # Drop a leading "────[ DISASM ]────" banner (the panel supplies its own title).
    while lines and "─" in lines[0] and "DISASM" in lines[0].upper():
        lines.pop(0)
    while lines and (not lines[0].strip() or set(lines[0].strip()) <= {"─"}):
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return Text.from_ansi("\n".join(lines))


def render_beside(disasm_ansi, result, current_addr):
    """Print the disasm (left) and the decompiled pseudo-C (right) side by side.

    ``disasm_ansi`` is the already-rendered disasm pane captured as ANSI text.
    Falls back to a stacked render on any error. Never raises.
    """
    if console is None or not result:
        try:
            display_decompile(result, current_addr)
        except Exception:
            pass
        return
    try:
        from rich.panel import Panel
        from rich.table import Table

        left_body = _ansi_to_text(disasm_ansi)

        code = _clean_code(result.get("code", "") or "")
        _lines, cur, win_start, win_end = _window(result, current_addr)
        lines = code.split("\n")
        right_body = _render_syntax(code, cur, win_start, win_end)
        if right_body is None:
            from rich.text import Text
            right_body = Text()
            for idx in range(win_start, win_end):
                ln = lines[idx] if idx < len(lines) else ""
                style = "reverse bold" if idx == cur else "cyan"
                right_body.append(f"{idx + 1:>4} {'>' if idx == cur else ' '} {ln}\n",
                                  style=style)

        start = result.get("start", 0) or 0
        left = Panel(left_body, title="[bold blue]disasm[/]",
                     border_style="blue", padding=(0, 1))
        right = Panel(right_body, title=f"[bold green]decompile {start:#x}[/]",
                      border_style="green", padding=(0, 1))
        # Two equal columns that fill the width so the panels sit flush together
        # (Columns leaves a big gap; a grid with ratio columns expands cleanly).
        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_row(left, right)
        console.print(grid)
    except Exception:
        try:
            display_decompile(result, current_addr)
        except Exception:
            pass


def display_decompile(result, current_addr, context_lines=None):
    """Render `result` (from decompile_function) with the current line highlighted.

    Shows the whole function when short; otherwise a window of ~25 lines around
    the current line. Never raises.
    """
    try:
        if not result:
            return
        start = result.get("start", 0) or 0
        code = _clean_code(result.get("code", "") or "")
        lines = code.split("\n")
        total = len(lines)
        if total == 0:
            return

        try:
            cur = line_for_addr(result, current_addr)
        except Exception:
            cur = None

        win_start, win_end = 0, total
        if total > _WHOLE_FUNC_MAX and cur is not None:
            win_start = max(0, cur - _WINDOW_BEFORE)
            win_end = min(total, cur + _WINDOW_AFTER + 1)

        try:
            banner(f"DECOMPILE  {start:#x}")
        except Exception:
            pass

        obj = _render_syntax(code, cur, win_start, win_end)
        if obj is not None and console is not None:
            try:
                console.print(obj)
                return
            except Exception:
                pass
        _render_text(lines, cur, win_start, win_end)
    except Exception:
        try:
            if console is not None:
                console.print(result.get("code", ""))
        except Exception:
            pass
