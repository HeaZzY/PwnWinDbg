"""Stack display rendering."""

from rich.text import Text

from .common import console, banner, ADDR_COLOR, CHAIN_ARROW_COLOR, SYMBOL_COLOR


def display_stack(entries, sp, ptr_size, symbol_resolver=None):
    """Display stack in pwndbg style.
    entries: list of (address, value) tuples
    """
    banner("STACK")

    ptr_fmt = "0x{:016x}" if ptr_size == 8 else "0x{:08x}"

    for i, (addr, val) in enumerate(entries):
        text = Text()
        offset = (addr - sp)

        text.append(f" {offset:+04x}", style="bright_black")
        text.append(" \u2502 ", style="bright_black")

        text.append(ptr_fmt.format(addr), style=ADDR_COLOR)
        text.append(" \u2192 ", style=CHAIN_ARROW_COLOR)

        if val is not None:
            text.append(ptr_fmt.format(val), style="white")

            if symbol_resolver and val > 0x1000:
                sym = symbol_resolver(val)
                if sym:
                    text.append(f"  ({sym})", style=SYMBOL_COLOR)
        else:
            text.append("??", style="bright_red")

        console.print(text)
