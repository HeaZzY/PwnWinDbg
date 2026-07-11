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

from ..core.decompiler import line_for_addr


# Show the whole function up to this many lines; beyond it, window around cur.
_WHOLE_FUNC_MAX = 60
_WINDOW_BEFORE = 25
_WINDOW_AFTER = 25


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


def display_decompile(result, current_addr, context_lines=None):
    """Render `result` (from decompile_function) with the current line highlighted.

    Shows the whole function when short; otherwise a window of ~25 lines around
    the current line. Never raises.
    """
    try:
        if not result:
            return
        start = result.get("start", 0) or 0
        code = result.get("code", "") or ""
        lines = result.get("lines")
        if not isinstance(lines, list):
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
