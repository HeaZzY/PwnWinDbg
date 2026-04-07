"""Resolve Win64 ABI arguments at the current call site.

Microsoft x64 calling convention:
    arg1 -> rcx     arg5 -> [rsp + 0x20]   (after the call: [rsp + 0x28])
    arg2 -> rdx     arg6 -> [rsp + 0x28]
    arg3 -> r8      arg7 -> [rsp + 0x30]
    arg4 -> r9      ...

The first 4 args live in registers, and the caller reserves 32 bytes of
"shadow space" on the stack for the callee to spill them into. We sample
the args *before* the call executes, so RSP is still the caller's value
and stack args 5+ live at [rsp + 0x20], [rsp + 0x28], etc.

x86 (cdecl/stdcall): all args on the stack at [esp+0], [esp+4], [esp+8], ...
"""

from .memory import read_ptr, read_string, read_memory_safe, virtual_query
from ..utils.constants import prot_to_str, MEM_COMMIT


# Win64 ABI: 4 register-passed args, 32-byte shadow space, then stack
WIN64_REG_ARGS = ("Rcx", "Rdx", "R8", "R9")
WIN64_SHADOW_SPACE = 0x20


def _annotate_value(debugger, val):
    """Build a one-line description of `val` for an argument display.

    Mirrors the telescope's first-step logic but flattened to a string:
    string > symbol > module+offset (+perm). Returns "" if nothing useful.
    """
    if val is None or val == 0:
        return ""

    # Cheap rejects
    if val < 0x1000 or val >> 63:
        # tiny values or kernel pointers (we're userland) — show numeric only
        return ""

    ph = debugger.process_handle
    mbi = virtual_query(ph, val)
    committed = mbi and mbi.State == MEM_COMMIT
    if not committed:
        return ""

    # 1. printable string?
    s = read_string(ph, val, 64)
    if s and len(s) >= 2 and all(c.isprintable() or c in "\t\r\n" for c in s):
        truncated = s[:60]
        if len(s) > 60:
            truncated += "..."
        return f'"{truncated}"'

    # 2. resolved symbol?
    if debugger.symbols:
        sym = debugger.symbols.resolve_address(val)
        if sym:
            return sym
        mod = debugger.symbols.get_module_at(val)
        if mod:
            perm = prot_to_str(mbi.Protect) if mbi else ""
            base = f"{mod.name}+{mod.offset_of(val):#x}"
            return f"{base} ({perm})" if perm else base

    perm = prot_to_str(mbi.Protect) if mbi else ""
    return f"({perm})" if perm else ""


def resolve_call_args(debugger, regs, num_args=4):
    """Return [(name, value, annotation)] for the first `num_args` arguments
    of the call about to be executed at the current RIP.

    Caller is expected to confirm the current instruction is a `call` before
    invoking — we don't re-check here.
    """
    if not regs:
        return []

    if debugger.is_wow64:
        # x86 cdecl/stdcall: all args on stack
        sp = regs.get("Esp", 0)
        if not sp:
            return []
        out = []
        for i in range(num_args):
            slot = sp + i * 4
            val = read_ptr(debugger.process_handle, slot, 4)
            ann = _annotate_value(debugger, val) if val else ""
            out.append((f"arg{i + 1}", val, ann))
        return out

    # Win64
    sp = regs.get("Rsp", 0)
    out = []
    for i in range(num_args):
        if i < len(WIN64_REG_ARGS):
            name = WIN64_REG_ARGS[i].lower()
            val = regs.get(WIN64_REG_ARGS[i], 0)
        else:
            name = f"arg{i + 1}"
            # arg5 sits right above the 32-byte shadow space at the
            # caller's rsp; we have not executed the call yet so no RA push.
            slot = sp + WIN64_SHADOW_SPACE + (i - len(WIN64_REG_ARGS)) * 8
            val = read_ptr(debugger.process_handle, slot, 8)
        ann = _annotate_value(debugger, val) if val else ""
        out.append((name, val or 0, ann))
    return out
