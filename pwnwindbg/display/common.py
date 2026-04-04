"""Shared display utilities: console, colors, banners, messages."""

import sys
import os

# Force UTF-8 output on Windows
if sys.platform == "win32":
    os.system("")  # Enable ANSI escape processing on Windows 10+
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

from rich.console import Console
from rich.text import Text

# Singleton console
console = Console(highlight=False, force_terminal=True)

# ---------------------------------------------------------------------------
# Color scheme
# ---------------------------------------------------------------------------

PERM_COLORS = {
    "rwx": "bold bright_red on red",
    "rw-": "yellow",
    "rw-c": "yellow",
    "r-x": "green",
    "r--": "blue",
    "---": "bright_black",
    "--x": "green",
}

REG_COLOR_IP = "bold red"
REG_COLOR_SP = "bold yellow"
REG_COLOR_BP = "bold yellow"
REG_COLOR_FLAGS = "bold magenta"
REG_COLOR_GENERAL = "bold white"
REG_COLOR_CHANGED = "bold bright_red"
REG_COLOR_SEG = "bright_black"

BANNER_COLOR = "bold bright_blue"
ARROW_COLOR = "bold bright_green"
ADDR_COLOR = "bright_cyan"
SYMBOL_COLOR = "bright_magenta"
STRING_COLOR = "bright_green"
CHAIN_ARROW_COLOR = "bold bright_yellow"


# ---------------------------------------------------------------------------
# Banner helpers
# ---------------------------------------------------------------------------

def _get_width():
    """Get terminal width, clamped."""
    try:
        w = console.width
    except Exception:
        w = 80
    return min(max(w, 60), 160)


def banner(title, width=None):
    """Print a pwndbg-style section banner."""
    if width is None:
        width = _get_width()
    title_str = f"[ {title} ]"
    pad = max(width - len(title_str), 0)
    left = pad // 2
    right = pad - left
    line = "\u2500" * left + title_str + "\u2500" * right
    console.print(line, style=BANNER_COLOR)


def separator(width=None):
    """Print a separator line."""
    if width is None:
        width = _get_width()
    console.print("\u2500" * width, style="bright_black")


# ---------------------------------------------------------------------------
# Permission color helper
# ---------------------------------------------------------------------------

def prot_color(prot_str):
    """Get color for a protection string."""
    if "rwx" in prot_str:
        return "bold bright_red"
    if "rw" in prot_str:
        return "yellow"
    if "r-x" in prot_str or "rx" in prot_str:
        return "green"
    if "r--" in prot_str or prot_str.startswith("r"):
        return "blue"
    return "bright_black"


# ---------------------------------------------------------------------------
# Message helpers
# ---------------------------------------------------------------------------

def error(msg):
    console.print(f"[bright_red][-] {msg}[/]")


def info(msg):
    console.print(f"[bright_blue][*] {msg}[/]")


def success(msg):
    console.print(f"[bright_green][+] {msg}[/]")


def warn(msg):
    console.print(f"[bright_yellow][!] {msg}[/]")
