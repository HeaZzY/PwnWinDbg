"""Memory map (vmmap) display rendering."""

from rich.text import Text

from .common import console, banner, ADDR_COLOR, SYMBOL_COLOR, prot_color
from ..utils.constants import prot_to_str, mem_type_to_str, MEM_COMMIT


def display_vmmap(regions, symbol_resolver=None, ptr_size=4):
    """Display memory map in pwndbg style.
    regions: list of (base, size, protect, state, type, label) tuples
    """
    banner("VMMAP")

    # Detect if any address needs 64-bit display
    needs_64 = any(base + size > 0xFFFFFFFF for base, size, _, _, _, _ in regions)
    addr_fmt = "0x{:016x}" if needs_64 else "0x{:08x}"
    addr_w = 18 if needs_64 else 10

    # Header
    text = Text()
    text.append(f" {'Start':>{addr_w}s}  {'End':>{addr_w}s}  {'Size':>10s}  {'Perm':6s}  {'Type':8s}  Mapping", style="bold white")
    console.print(text)

    for base, size, protect, state, mtype, label in regions:
        end = base + size
        prot_str = prot_to_str(protect)
        color = prot_color(prot_str)

        text = Text()
        text.append(f" {addr_fmt.format(base)}", style=ADDR_COLOR)
        text.append(f"  {addr_fmt.format(end)}", style=ADDR_COLOR)
        text.append(f"  {size:#010x}", style="white")
        text.append(f"  {prot_str:6s}", style=color)

        type_str = mem_type_to_str(mtype) if state == MEM_COMMIT else "Reserve"
        text.append(f"  {type_str:8s}", style="bright_black")

        if label:
            text.append(f"  {label}", style=SYMBOL_COLOR)

        console.print(text)
