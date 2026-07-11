"""Live terminal display for the in-debugger AI agent.

Renders the agent's reasoning, tool calls, tool output and final answer with a
distinct visual style so the user can clearly tell the AI's "thinking" apart
from ordinary debugger output. Reuses the shared Rich console and colour scheme.
"""

from rich.panel import Panel
from rich.text import Text

from .common import (
    console, banner,
    ADDR_COLOR, SYMBOL_COLOR, BANNER_COLOR, STRING_COLOR,
)


# Map an activity ``kind`` to a compact (label, style) pair. Reuses the shared
# colour palette so the trace lines sit visually alongside ordinary output.
_ACTIVITY_KINDS = {
    "read":  ("  [read]  ", "cyan"),
    "write": ("  [write] ", "bold red"),
    "reg":   ("  [reg]   ", "yellow"),
    "send":  ("  [-> in] ", "magenta"),
    "recv":  ("  [<- out]", "green"),
    "eval":  ("  [eval]  ", "bright_black"),
    "sh":    ("  [shell] ", "blue"),
    "file":  ("  [file]  ", "bright_magenta"),
    "info":  ("  [note]  ", "dim"),
}
_ACTIVITY_FALLBACK = ("  [tool]  ", "dim")


def hex_preview(data, n=24):
    """Return a short hex preview of ``data`` (bytes/bytearray/str/None).

    ``str`` is encoded as utf-8. Only the first ``n`` bytes are rendered; if the
    data is longer a `` ...(<total> B)`` marker is appended. Empty/None yields
    ``"(0 B)"``. Never raises.
    """
    try:
        if data is None:
            return "(0 B)"
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        elif isinstance(data, bytearray):
            data = bytes(data)
        elif not isinstance(data, bytes):
            data = str(data).encode("utf-8", "replace")
        total = len(data)
        if total == 0:
            return "(0 B)"
        head = data[:n].hex()
        if total > n:
            return f"{head} ...({total} B)"
        return head
    except Exception:
        return ""


def tool_activity(kind, summary, detail=None):
    """Print ONE concise styled line describing an agent tool action.

    ``kind`` selects a small labelled icon + colour (see ``_ACTIVITY_KINDS``);
    unknown kinds fall back to a generic dim label. ``summary`` is the main text;
    an optional ``detail`` is printed on the next line, indented, dim and
    truncated to ~200 chars. The whole function is exception-safe and never
    raises so tracing can never break a tool.
    """
    try:
        label, style = _ACTIVITY_KINDS.get(str(kind), _ACTIVITY_FALLBACK)
        console.print(
            Text.assemble((label + " ", style), (str(summary), "dim white")),
            highlight=False,
            markup=False,
        )
        if detail is not None:
            text = str(detail)
            if len(text) > 200:
                text = text[:200] + "..."
            console.print(
                Text("      " + text, style="dim"),
                highlight=False,
                markup=False,
            )
    except Exception:
        pass


# Style used for streamed reasoning text so it reads as the AI "thinking".
_REASONING_STYLE = "dim cyan"
# Whether the last reasoning delta left the cursor mid-line (so we know when to
# emit a trailing newline before the next section).
_reasoning_open = False


def agent_header(task):
    """Print the banner announcing the start of an agent run."""
    banner("AI AGENT")
    console.print(
        Text.assemble(("task: ", "bold " + SYMBOL_COLOR), (str(task), STRING_COLOR))
    )


def step_header(n, total):
    """Print a lightweight header marking the start of step ``n`` of ``total``."""
    _end_reasoning()
    console.print(
        Text.assemble(
            ("▶ step ", "bold " + BANNER_COLOR),
            (f"{n}", "bold " + ADDR_COLOR),
            ("/", BANNER_COLOR),
            (f"{total}", ADDR_COLOR),
        )
    )


def stream_reasoning(delta):
    """Stream a chunk of assistant reasoning text, no newline spam.

    Deltas are printed inline (in a dim/cyan style) so the reasoning flows like
    live typing. Call :func:`final_answer` / :func:`tool_call` afterwards; those
    close the open reasoning line first.
    """
    global _reasoning_open
    if not delta:
        return
    console.print(delta, style=_REASONING_STYLE, end="", highlight=False, markup=False)
    _reasoning_open = True


def _end_reasoning():
    """Terminate an open streamed-reasoning line with a newline, once."""
    global _reasoning_open
    if _reasoning_open:
        console.print("")
        _reasoning_open = False


def tool_call(kind, snippet):
    """Announce a tool invocation (``kind`` is "dbg" or "python") and show code.

    Args:
        kind: The block kind, "dbg" or "python".
        snippet: The block's source text.
    """
    _end_reasoning()
    label = "dbg" if kind == "dbg" else "python"
    console.print(
        Text.assemble(("▶ ", "bold " + BANNER_COLOR), (label, "bold " + BANNER_COLOR))
    )
    lang = "python" if kind == "python" else "text"
    try:
        from rich.syntax import Syntax
        console.print(
            Syntax(str(snippet).rstrip("\n"), lang, theme="ansi_dark",
                   background_color="default", word_wrap=True)
        )
    except Exception:
        # Fall back to plain text if syntax highlighting is unavailable.
        console.print(Text(str(snippet).rstrip("\n"), style="white"), markup=False)


def stream_tool_output(delta):
    """Stream a chunk of tool (child-process) output live to the console."""
    if not delta:
        return
    console.print(delta, end="", highlight=False, markup=False)


def final_answer(text):
    """Render the agent's final answer inside a green panel."""
    _end_reasoning()
    console.print(
        Panel(
            Text(str(text).strip() or "(no answer)", style="white"),
            title="AI answer",
            border_style=STRING_COLOR,
            expand=False,
        )
    )


def steer_prompt():
    """Prompt the user for steering input after a Ctrl+C pause.

    Returns the raw string the user typed (empty string = resume).
    """
    _end_reasoning()
    console.print(
        Text.assemble(
            ("[paused] ", "bold yellow"),
            ("Enter to resume, 'stop' to end, or type guidance to steer:",
             "yellow"),
        )
    )
    try:
        return console.input("[bold yellow]steer> [/]")
    except (EOFError, KeyboardInterrupt):
        return "stop"
