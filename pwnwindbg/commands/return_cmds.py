"""`return` — force the current function to return immediately.

Useful for short-circuiting checks (license validation, anti-debug
probes, error paths) without manually patching code.

Usage:
    return              — return with rax/eax left unchanged
    return <expr>       — return after setting rax/eax to <expr>

Mechanics:
    1. Read the return address from [rsp] (and optionally validate it
       via the .pdata unwinder when available).
    2. Set rip = return address, rsp += 8 (or +4 on wow64).
    3. If a value was supplied, set rax/eax to it.
    4. Leave the user **stopped** at the caller's instruction so they
       can decide what to do next (typically `c` to keep going).

The unwinder fallback only kicks in if `[rsp]` doesn't look like a
valid return address (e.g. RIP is mid-function with a non-default
prologue) — for the common case of being stopped at a function entry
or right after a `call`, the naive `[rsp]` read is exactly right.
"""

from ..core.memory import read_memory_safe, read_ptr
from ..core.registers import (
    get_context, get_ip, get_sp, set_context, set_ip,
)
from ..display.formatters import error, info, success
from ..utils.addr_expr import eval_expr


def cmd_return(debugger, args):
    """Force-return from the current function. Optional arg is the new rax."""
    if not debugger.process_handle:
        error("No process attached")
        return None

    th = debugger.get_active_thread_handle()
    if th is None:
        error("No active thread")
        return None

    raw = args.strip()
    new_rax = None
    if raw:
        new_rax = eval_expr(debugger, raw)
        if new_rax is None:
            error(f"Cannot resolve return value: {raw}")
            return None

    ctx = get_context(th, debugger.is_wow64)
    sp = get_sp(ctx, debugger.is_wow64)

    # Try [rsp] first — that's the natural return address slot when we're
    # stopped at function entry or just after a `call`. Validate that it
    # points into a known executable region; if not, fall back to the
    # .pdata unwinder.
    ret_addr = read_ptr(debugger.process_handle, sp, debugger.ptr_size)
    if not _looks_like_code_addr(debugger, ret_addr):
        ret_addr = _unwind_one_frame(debugger, ctx) or ret_addr

    if not ret_addr:
        error("Cannot determine return address")
        return None

    # Splat the new state. The +ptr_size in rsp simulates the `ret`
    # instruction's pop of the return address.
    if debugger.is_wow64:
        ctx.Eip = ret_addr & 0xFFFFFFFF
        ctx.Esp = (sp + 4) & 0xFFFFFFFF
        if new_rax is not None:
            ctx.Eax = new_rax & 0xFFFFFFFF
    else:
        ctx.Rip = ret_addr & 0xFFFFFFFFFFFFFFFF
        ctx.Rsp = (sp + 8) & 0xFFFFFFFFFFFFFFFF
        if new_rax is not None:
            ctx.Rax = new_rax & 0xFFFFFFFFFFFFFFFF

    set_context(th, ctx, debugger.is_wow64)

    if new_rax is not None:
        rax_word = "eax" if debugger.is_wow64 else "rax"
        success(
            f"Returned to {ret_addr:#x} ({rax_word}={new_rax:#x})"
        )
    else:
        success(f"Returned to {ret_addr:#x}")
    info("Use `c` / `context` to inspect the caller and keep going")
    return None


def _looks_like_code_addr(debugger, addr):
    """Quick sanity check on a return-address candidate. We don't want
    to launch the unwinder for every call when [rsp] is obviously fine."""
    if not addr:
        return False
    if addr < 0x10000:
        return False
    if not debugger.symbols:
        # No symbol manager — trust the read.
        return True
    # Cheap check: does the address fall inside any loaded module's
    # range? That covers the overwhelming majority of legitimate return
    # addresses (calls into JITted code on Windows are rare).
    for mod in debugger.symbols.modules:
        if mod.base_address <= addr < mod.base_address + mod.size:
            return True
    return False


def _unwind_one_frame(debugger, ctx):
    """Use the .pdata unwinder to recover the caller RIP when [rsp] is
    not the right slot (e.g. RIP is mid-function in a frame that has
    pushed callee-saved regs since the call)."""
    if debugger.is_wow64 or not debugger.symbols or not debugger.symbols.modules:
        return None
    try:
        from ..core.seh import unwind_one_frame_x64

        def _read(addr, size):
            return read_memory_safe(debugger.process_handle, addr, size)

        ip = get_ip(ctx, debugger.is_wow64)
        sp = get_sp(ctx, debugger.is_wow64)
        caller_rip, _ = unwind_one_frame_x64(
            _read, debugger.symbols.modules, ip, sp, mid_prolog=True,
        )
        if caller_rip and caller_rip > 0x10000:
            return caller_rip
    except Exception:
        return None
    return None
