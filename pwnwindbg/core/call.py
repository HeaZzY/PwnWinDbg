"""Synthetic function-call primitive for the userland debugger.

`invoke_function(debugger, func_addr, args)` runs `func_addr(*args)` inside
the debuggee on its currently active thread, then returns rax. The
mechanics, in order:

1. Allocate a tiny RWX **trampoline** page in the target process. We
   write a single NOP byte at offset 0 and immediately install a
   one-shot software BP on top of it via the normal `BreakpointManager`,
   so the BP fires when the called function returns to it. The original
   byte saved by the BP manager is the NOP we just wrote, so the
   step-over machinery will happily restore a benign instruction even
   though we never intend to actually execute it.

2. Save the active thread's full CONTEXT (deep copy via memmove). After
   the call returns we splat this back into the thread so the user's
   debugging session resumes exactly where it was — no observable side
   effect on RIP/RSP/regs aside from whatever the called function may
   have done to the heap or globals.

3. Compose a fresh CONTEXT for the call:
     - rcx, rdx, r8, r9 receive the first four args (Win64 ABI)
     - args 5+ are written to the stack at [new_rsp+0x28], [new_rsp+0x30], …
     - the trampoline address is written at [new_rsp] as the return addr
     - new_rsp is chosen 16-byte-aligned BEFORE the simulated call (so
       on entry to the callee `rsp & 0xF == 8`, which is what the ABI
       requires) and is offset 0x100 below the user's rsp so we don't
       trample anything
     - rip is set to the function entry point

4. Continue and run the standard event loop. The first stop with reason
   "breakpoint" at the trampoline address indicates the function has
   returned; rax holds the result.

5. Capture rax, restore the saved context, manually evict the temp BP
   from the manager (the user-visible side effect: zero — the trampoline
   was never an "anchored" BP and the original byte was a NOP we wrote),
   and free the trampoline page.

Limitations:
- x64 only — wow64 is rejected with a clear error.
- Only works while the debugger is **stopped** on the target thread (the
  normal state when the user is typing commands).
- The call is expected to return without hitting another breakpoint or
  faulting. If it does, the user is left in that secondary stop and must
  resolve it themselves before the original context is restored.
- A maximum of 16 arguments is enforced — generous for typical APIs and
  bounded so the stack frame stays predictable.
"""

import ctypes

from ..utils.constants import (
    kernel32,
    MEM_COMMIT, MEM_RESERVE, MEM_RELEASE,
    PAGE_EXECUTE_READWRITE,
)
from .memory import write_memory
from .registers import get_context, set_context, get_ip, get_sp


# x64 ABI register slots for the first four arguments.
_X64_REG_ARGS = ("Rcx", "Rdx", "R8", "R9")
# Headroom we leave between the user's rsp and our scratch frame so the
# called function has stack to work with without clobbering whatever the
# user had below rsp.
_STACK_HEADROOM = 0x200
# Maximum number of args we'll set up. Any more is almost certainly a
# user error and the stack frame would get unwieldy.
MAX_CALL_ARGS = 16


class CallError(Exception):
    """Raised when invoke_function cannot complete (bad state, bad args,
    target faulted before returning to the trampoline, etc.)."""


def alloc_remote(process_handle, size):
    """Allocate `size` bytes RWX in the target process. Returns the address
    or raises CallError on failure."""
    addr = kernel32.VirtualAllocEx(
        process_handle,
        None,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    if not addr:
        err = ctypes.GetLastError()
        raise CallError(f"VirtualAllocEx failed (err={err})")
    return addr


def free_remote(process_handle, addr):
    """Release a region previously allocated with `alloc_remote`. Best
    effort — failures are swallowed because they shouldn't happen on a
    page we just allocated, but we don't want a teardown hiccup to mask
    a real error from the call itself."""
    if not addr:
        return
    try:
        kernel32.VirtualFreeEx(process_handle, addr, 0, MEM_RELEASE)
    except Exception:
        pass


def _copy_context(ctx):
    """Deep-copy a CONTEXT64 / WOW64_CONTEXT structure via memmove."""
    cls = type(ctx)
    out = cls()
    ctypes.memmove(
        ctypes.addressof(out), ctypes.addressof(ctx), ctypes.sizeof(cls)
    )
    return out


def invoke_function(debugger, func_addr, args):
    """Run `func_addr(*args)` on the active thread; return rax.

    `args` is a list of integers (already laid out as raw register/stack
    values — strings, etc., must be allocated by the caller and passed in
    as pointers).
    """
    if debugger.is_wow64:
        raise CallError("`call` is x64-only for now (target is wow64)")
    if debugger.process_handle is None:
        raise CallError("No process attached")
    if len(args) > MAX_CALL_ARGS:
        raise CallError(
            f"Too many args ({len(args)}); maximum is {MAX_CALL_ARGS}"
        )

    th = debugger.get_active_thread_handle()
    if th is None:
        raise CallError("No active thread")

    # 1. Allocate the trampoline page and seed it with a NOP. The BP we
    # install on top will save the NOP as `original_byte`, so when the
    # BP fires the manager restores a benign instruction.
    trampoline = alloc_remote(debugger.process_handle, 16)
    try:
        write_memory(debugger.process_handle, trampoline, b"\x90")  # NOP

        # 2. Snapshot the current context so we can fully revert.
        orig_ctx = get_context(th, debugger.is_wow64)
        saved_ctx = _copy_context(orig_ctx)

        # 3. Compose the call context. We work on a copy so we never see
        # half-applied state if a setter raises mid-flight.
        new_ctx = _copy_context(orig_ctx)

        # First four args land in rcx/rdx/r8/r9.
        for i in range(min(4, len(args))):
            setattr(new_ctx, _X64_REG_ARGS[i], args[i] & 0xFFFFFFFFFFFFFFFF)

        # Pick a fresh stack frame below the user's current rsp, aligned
        # so the callee sees `rsp & 0xF == 8` on entry. We pre-align to
        # 16 then subtract 8 for the (simulated) return address push.
        orig_rsp = get_sp(orig_ctx, debugger.is_wow64)
        pre_call_rsp = (orig_rsp - _STACK_HEADROOM) & ~0xF
        new_rsp = pre_call_rsp - 8

        # Stack args 5+ live at [rsp+0x28], [rsp+0x30], …
        for i in range(4, len(args)):
            slot = new_rsp + 0x28 + (i - 4) * 8
            write_memory(
                debugger.process_handle,
                slot,
                (args[i] & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"),
            )

        # Return address: trampoline+0 (where the one-shot BP lives).
        write_memory(
            debugger.process_handle, new_rsp, trampoline.to_bytes(8, "little")
        )

        new_ctx.Rsp = new_rsp
        new_ctx.Rip = func_addr & 0xFFFFFFFFFFFFFFFF

        # 4. Install the temp BP and apply the new context. Order
        # matters: install the BP BEFORE setting context so the trampoline
        # is armed by the time we resume.
        bp = debugger.bp_manager.add(
            debugger.process_handle, trampoline, temporary=True
        )
        set_context(th, new_ctx, debugger.is_wow64)

        # 5. Drive the event loop. We expect the very next stop to be
        # the trampoline BP (in our active thread). Anything else
        # propagates up — the user has to deal with it themselves
        # because we cannot resume a half-finished call without losing
        # the saved context.
        debugger.state = debugger.state  # leave running/stopped untouched
        stop = debugger.do_continue()
        if stop is None:
            raise CallError("Debug loop returned no stop info")
        if stop.get("reason") != "breakpoint":
            raise CallError(
                f"call interrupted by {stop.get('reason')}; original "
                f"context NOT restored, debugger now in mid-call state"
            )
        hit_bp = stop.get("bp")
        if hit_bp is None or hit_bp.address != trampoline:
            raise CallError(
                f"call interrupted by foreign BP at "
                f"{stop.get('address'):#x}; mid-call state preserved"
            )

        # 6. Capture rax. The active thread may have changed (the BP
        # fires on the same TID we set up, so this is normally a no-op,
        # but be defensive).
        th_after = debugger.get_active_thread_handle()
        result_ctx = get_context(th_after, debugger.is_wow64)
        rax = result_ctx.Rax & 0xFFFFFFFFFFFFFFFF

        # 7. Restore the saved context onto the active thread. This
        # rewinds rip/rsp/regs to the user's pre-call state.
        set_context(th_after, saved_ctx, debugger.is_wow64)

        # 8. Tear down the temp BP. _step_over_bp was set when the BP
        # fired; clear it so do_continue doesn't try to single-step
        # through a (now freed) trampoline byte.
        debugger.bp_manager.re_enable_after_single_step(
            debugger.process_handle, hit_bp
        )
        debugger._step_over_bp = None

        return rax
    finally:
        free_remote(debugger.process_handle, trampoline)
