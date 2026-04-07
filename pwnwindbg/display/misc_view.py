"""Miscellaneous display: process info, breakpoints, backtrace."""

from rich.text import Text

from .common import console, banner, ADDR_COLOR, SYMBOL_COLOR


def display_process_info(info_dict):
    """Display process information."""
    banner("PROCESS INFO")
    for key, val in info_dict.items():
        text = Text()
        text.append(f"  {key:20s}", style="bold white")
        text.append(str(val), style="white")
        console.print(text)


def display_breakpoints(bps):
    """Display breakpoint list."""
    banner("BREAKPOINTS")
    if not bps:
        console.print("  No breakpoints set.", style="bright_black")
        return

    for bp in bps:
        text = Text()
        state_color = "bright_green" if bp.enabled else "bright_red"
        state_str = "E" if bp.enabled else "D"
        text.append(f"  #{bp.id:<4d}", style="bold white")
        text.append(f"[{state_str}]", style=state_color)
        text.append(f"  {bp.address:#x}", style=ADDR_COLOR)
        text.append(f"  hits={bp.hit_count}", style="bright_black")
        if bp.temporary:
            text.append("  [temp]", style="bright_yellow")
        if getattr(bp, "condition", None):
            text.append(f"  if {bp.condition}", style="bright_cyan")
        console.print(text)


def display_backtrace(frames, symbol_resolver=None):
    """Display backtrace.
    frames: list of (frame_number, return_address) tuples
    """
    banner("BACKTRACE")

    for idx, ret_addr in frames:
        text = Text()
        text.append(f" #{idx:<3d}", style="bright_white")
        text.append(f" {ret_addr:#x}", style=ADDR_COLOR)

        if symbol_resolver:
            sym = symbol_resolver(ret_addr)
            if sym:
                text.append(f"  ({sym})", style=SYMBOL_COLOR)

        console.print(text)
