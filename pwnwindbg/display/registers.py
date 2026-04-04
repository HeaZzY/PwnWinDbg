"""Register display rendering."""

from rich.text import Text

from .common import (
    console, banner,
    REG_COLOR_IP, REG_COLOR_SP, REG_COLOR_BP, REG_COLOR_FLAGS,
    REG_COLOR_GENERAL, REG_COLOR_CHANGED, REG_COLOR_SEG,
    SYMBOL_COLOR,
)
from ..core.registers import (
    REGS_64_GENERAL, REGS_64_FRAME, REGS_32_GENERAL, REGS_32_FRAME,
)


def _get_reg_color(name, is_changed):
    if is_changed:
        return REG_COLOR_CHANGED
    lower = name.lower()
    if lower in ("rip", "eip"):
        return REG_COLOR_IP
    if lower in ("rsp", "esp"):
        return REG_COLOR_SP
    if lower in ("rbp", "ebp"):
        return REG_COLOR_BP
    if lower == "eflags":
        return REG_COLOR_FLAGS
    if lower.startswith("seg"):
        return REG_COLOR_SEG
    return REG_COLOR_GENERAL


def _format_eflags(eflags):
    flags = []
    flag_defs = [
        (0, "CF"), (2, "PF"), (4, "AF"), (6, "ZF"), (7, "SF"),
        (8, "TF"), (9, "IF"), (10, "DF"), (11, "OF"),
    ]
    for bit, name in flag_defs:
        if eflags & (1 << bit):
            flags.append(name)
    return " ".join(flags)


def display_registers(regs, changed, is_wow64, symbol_resolver=None):
    """Display registers in pwndbg style."""
    banner("REGISTERS")

    if is_wow64:
        general = REGS_32_GENERAL
        frame = REGS_32_FRAME
        ptr_fmt = "0x{:08x}"
    else:
        general = REGS_64_GENERAL
        frame = REGS_64_FRAME
        ptr_fmt = "0x{:016x}"

    for name in general + frame:
        if name not in regs:
            continue
        val = regs[name]
        color = _get_reg_color(name, name in changed)
        val_str = ptr_fmt.format(val)

        text = Text()
        text.append(f" {name:6s}", style=color)
        text.append(" ")
        text.append(val_str, style=color)

        if symbol_resolver and val > 0x1000:
            sym = symbol_resolver(val)
            if sym:
                text.append(f"  ({sym})", style=SYMBOL_COLOR)

        console.print(text)

    # EFlags
    if "EFlags" in regs:
        eflags = regs["EFlags"]
        color = _get_reg_color("EFlags", "EFlags" in changed)
        text = Text()
        text.append(f" {'EFlags':6s}", style=color)
        text.append(f" 0x{eflags:08x}", style=color)
        text.append(f"  [{_format_eflags(eflags)}]", style="bright_black")
        console.print(text)

    # Segment registers
    seg_names = ["SegCs", "SegDs", "SegEs", "SegFs", "SegGs", "SegSs"]
    seg_vals = []
    for s in seg_names:
        if s in regs:
            seg_vals.append(f"{s[3:].lower()}={regs[s]:#06x}")
    if seg_vals:
        text = Text()
        text.append("  ", style="")
        text.append("  ".join(seg_vals), style=REG_COLOR_SEG)
        console.print(text)
