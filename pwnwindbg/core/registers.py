"""Register handling: get/set thread context, display, change tracking."""

import ctypes
from ..utils.constants import (
    kernel32, CONTEXT64, CONTEXT32, WOW64_CONTEXT,
    CONTEXT_ALL_AMD64, CONTEXT_ALL_i386, WOW64_CONTEXT_ALL,
    EFLAGS_TF, EFLAGS_RF,
)


# Register names for each architecture
REGS_64 = [
    "Rax", "Rbx", "Rcx", "Rdx", "Rsi", "Rdi", "Rbp", "Rsp",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
    "Rip", "EFlags",
    "SegCs", "SegDs", "SegEs", "SegFs", "SegGs", "SegSs",
]

REGS_32 = [
    "Eax", "Ebx", "Ecx", "Edx", "Esi", "Edi", "Ebp", "Esp",
    "Eip", "EFlags",
    "SegCs", "SegDs", "SegEs", "SegFs", "SegGs", "SegSs",
]

# Groupings for display
REGS_64_GENERAL = ["Rax", "Rbx", "Rcx", "Rdx", "Rsi", "Rdi", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]
REGS_64_FRAME = ["Rbp", "Rsp", "Rip"]
REGS_32_GENERAL = ["Eax", "Ebx", "Ecx", "Edx", "Esi", "Edi"]
REGS_32_FRAME = ["Ebp", "Esp", "Eip"]


def get_context_64(thread_handle):
    """Get 64-bit thread context."""
    ctx = CONTEXT64()
    ctx.ContextFlags = CONTEXT_ALL_AMD64
    if not kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx)):
        err = ctypes.GetLastError()
        raise RuntimeError(f"GetThreadContext failed (err={err})")
    return ctx


def set_context_64(thread_handle, ctx):
    """Set 64-bit thread context."""
    if not kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx)):
        err = ctypes.GetLastError()
        raise RuntimeError(f"SetThreadContext failed (err={err})")


def get_context_32(thread_handle):
    """Get 32-bit (WoW64) thread context."""
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = WOW64_CONTEXT_ALL
    if not kernel32.Wow64GetThreadContext(thread_handle, ctypes.byref(ctx)):
        err = ctypes.GetLastError()
        raise RuntimeError(f"Wow64GetThreadContext failed (err={err})")
    return ctx


def set_context_32(thread_handle, ctx):
    """Set 32-bit (WoW64) thread context."""
    if not kernel32.Wow64SetThreadContext(thread_handle, ctypes.byref(ctx)):
        err = ctypes.GetLastError()
        raise RuntimeError(f"Wow64SetThreadContext failed (err={err})")


def get_context(thread_handle, is_wow64):
    """Get thread context, auto-detecting architecture."""
    if is_wow64:
        return get_context_32(thread_handle)
    else:
        return get_context_64(thread_handle)


def set_context(thread_handle, ctx, is_wow64):
    """Set thread context, auto-detecting architecture."""
    if is_wow64:
        set_context_32(thread_handle, ctx)
    else:
        set_context_64(thread_handle, ctx)


def get_ip(ctx, is_wow64):
    """Get instruction pointer from context."""
    if is_wow64:
        return ctx.Eip
    return ctx.Rip


def set_ip(ctx, value, is_wow64):
    """Set instruction pointer in context."""
    if is_wow64:
        ctx.Eip = value
    else:
        ctx.Rip = value


def get_sp(ctx, is_wow64):
    """Get stack pointer from context."""
    if is_wow64:
        return ctx.Esp
    return ctx.Rsp


def get_bp(ctx, is_wow64):
    """Get base pointer from context."""
    if is_wow64:
        return ctx.Ebp
    return ctx.Rbp


def set_trap_flag(ctx):
    """Set the Trap Flag for single-stepping."""
    ctx.EFlags |= EFLAGS_TF


def clear_trap_flag(ctx):
    """Clear the Trap Flag."""
    ctx.EFlags &= ~EFLAGS_TF


def set_resume_flag(ctx):
    """Set the Resume Flag to avoid re-triggering hardware breakpoints."""
    ctx.EFlags |= EFLAGS_RF


def context_to_dict(ctx, is_wow64):
    """Convert context to a dict of register_name -> value."""
    regs = {}
    if is_wow64:
        for name in REGS_32:
            regs[name] = getattr(ctx, name)
    else:
        for name in REGS_64:
            regs[name] = getattr(ctx, name)
    return regs


def diff_registers(old_regs, new_regs):
    """Return set of register names that changed between old and new."""
    if old_regs is None:
        return set()
    changed = set()
    for name in new_regs:
        if name in old_regs and old_regs[name] != new_regs[name]:
            changed.add(name)
    return changed
