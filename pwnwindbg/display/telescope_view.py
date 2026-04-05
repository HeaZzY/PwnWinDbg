"""Telescope (pointer chain) display rendering."""

from rich.text import Text

from .common import console, banner, CHAIN_ARROW_COLOR, SYMBOL_COLOR, STRING_COLOR, prot_color


def _val_color(perm_str):
    """Color a pointer value based on the memory permissions it points to.
    r-x / code  → bold red
    rwx         → bold red underline
    rw-         → bold blue
    r--         → bright_cyan
    other       → white
    """
    if not perm_str:
        return "white"
    p = perm_str.lower()
    if "rwx" in p:
        return "bold bright_red underline"
    if "x" in p:
        return "bold red"
    if "rw" in p:
        return "bold blue"
    if p.startswith("r"):
        return "bright_cyan"
    return "white"


def display_telescope(chains, start_addr, ptr_size, base_addr=None, title="TELESCOPE"):
    """Display telescope/pointer chain dereferencing.
    chains: list of (offset, chain_entries) where chain_entries is
            list of (value, label, perm_str, is_string, string_val, asm_str)
    base_addr: original address for offset display (defaults to start_addr)
    title: banner title (default "TELESCOPE", use "STACK" for context display)
    """
    banner(title)

    if base_addr is None:
        base_addr = start_addr
    addr_fmt = "0x{:016x}" if ptr_size == 8 else "0x{:08x}"
    ptr_fmt = addr_fmt

    for offset, chain in chains:
        text = Text()

        # Show offset relative to original base + actual address
        mem_addr = start_addr + offset
        display_offset = mem_addr - base_addr
        text.append(f" {display_offset:+04x}", style="bright_black")
        text.append(" \u2502 ", style="bright_black")
        text.append(addr_fmt.format(mem_addr), style="bright_cyan")
        text.append(" \u2192 ", style="bright_black")

        for i, entry in enumerate(chain):
            # Support both old 5-tuple and new 6-tuple format
            if len(entry) == 6:
                val, label, perm_str, is_string, string_val, asm_str = entry
            else:
                val, label, perm_str, is_string, string_val = entry
                asm_str = ""

            if i > 0:
                text.append(" \u2014\u2014\u25b8 ", style=CHAIN_ARROW_COLOR)

            if is_string and string_val:
                text.append(f'"{string_val}"', style=STRING_COLOR)
            elif val is not None:
                text.append(ptr_fmt.format(val), style=_val_color(perm_str))
            else:
                text.append("??", style="bright_red")

            if label:
                pcolor = prot_color(perm_str) if perm_str else "bright_black"
                text.append(f" ({label}", style=SYMBOL_COLOR)
                if perm_str:
                    text.append(f" {perm_str}", style=pcolor)
                text.append(")", style=SYMBOL_COLOR)

            # Show asm instruction for executable pointers
            if asm_str and not is_string:
                text.append(f" \u25c0 {asm_str}", style="bright_yellow")

        console.print(text)
