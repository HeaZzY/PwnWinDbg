"""A tiny pixel-art mascot for the in-debugger AI agent.

Rendered with Unicode half-blocks (``▀``) so each character cell shows two
vertically-stacked "pixels" (fg = top, bg = bottom) — giving square-ish pixels.
The mascot is a little cyber-bot whose visor expression changes with the agent's
mood (idle / think / work / win / err), a bit like Claude Code's companion.

Pure Rich; exception-safe helpers so it can never break the cockpit.
"""

from rich.text import Text
from rich.console import Group
from rich.panel import Panel


# palette: key -> hex colour (None = transparent)
_PAL = {
    " ": None,
    "o": "#12313d",   # dark outline
    "c": "#39bae6",   # body cyan
    "b": "#2a7f9e",   # body shade
    "f": "#0a1820",   # visor inner (dark)
    "W": "#e8f6ff",   # visor frame / white
    "a": "#ffd166",   # antenna
    "g": "#8b9bb4",   # legs / metal
    # eye colours (overwritten per mood via the 'e' key)
    "e": "#7fffd4",
}

# Mood -> (eye colour, the two 4-wide visor eye rows, a status glyph).
_MOODS = {
    "idle":  ("#7fffd4", ["e  e", "    "], "•"),
    "think": ("#c792ea", [" ee ", "    "], "?"),
    "work":  ("#5cf0c8", ["eeee", "eeee"], "»"),
    "win":   ("#ffd166", ["e  e", " ee "], "★"),
    "err":   ("#ff5c57", ["e  e", "e  e"], "×"),
}

# Base sprite, 16 wide x 16 tall. Visor interior (rows 8-11, cols 6-9) is 'f'
# and gets the mood eyes painted over it. Antenna 'a' at the very top.
_BASE = [
    "       aa       ",
    "       aa       ",
    "     oooooo     ",
    "    occccccco   ",
    "   occccccccco  ",
    "   ocWWWWWWco   ",
    "   ocWffffWco   ",
    "   ocWffffWco   ",
    "   ocWffffWco   ",
    "   ocWffffWco   ",
    "   ocWWWWWWco   ",
    "   obccccccbo   ",
    "    occccco     ",
    "     ooooo      ",
    "     g   g      ",
    "    gg   gg     ",
]


def _sprite_grid(mood):
    """Return the 16x16 pixel grid for ``mood`` (eyes painted into the visor)."""
    eye_color, eye_rows, _ = _MOODS.get(mood, _MOODS["idle"])
    grid = [list(row) for row in _BASE]
    # visor interior is rows 6-9, cols 6-9 (4x4). Paint the 2 eye rows into the
    # middle of it (rows 7-8) so the eyes sit centred.
    for i, er in enumerate(eye_rows):
        r = 7 + i
        for j, ch in enumerate(er):
            if ch == "e":
                grid[r][6 + j] = "E"     # 'E' = mood eye (dynamic colour)
    return grid, eye_color


def render(mood="idle"):
    """Return a list of Rich Text lines drawing the mascot for ``mood``."""
    try:
        grid, eye_color = _sprite_grid(mood)
        pal = dict(_PAL)
        pal["E"] = eye_color
        lines = []
        for r in range(0, len(grid), 2):
            top = grid[r]
            bot = grid[r + 1] if r + 1 < len(grid) else [" "] * len(top)
            t = Text(no_wrap=True)
            for c in range(len(top)):
                tc = pal.get(top[c])
                bc = pal.get(bot[c]) if c < len(bot) else None
                if tc is None and bc is None:
                    t.append(" ")
                elif tc is not None and bc is not None:
                    t.append("▀", style=f"{tc} on {bc}")
                elif tc is not None:
                    t.append("▀", style=tc)
                else:
                    t.append("▄", style=bc)
            lines.append(t)
        return lines
    except Exception:
        return [Text("[o_o]", style="cyan")]


def panel(mood="idle", status=""):
    """Return a compact Rich renderable: the mascot above a status line."""
    try:
        body = list(render(mood))
        if status:
            body.append(Text(status, style="bold #39bae6", justify="center"))
        return Group(*body)
    except Exception:
        return Text("[o_o] " + status, style="cyan")


def glyph(mood="idle"):
    """The mood's status glyph (for compact one-line contexts)."""
    return _MOODS.get(mood, _MOODS["idle"])[2]
