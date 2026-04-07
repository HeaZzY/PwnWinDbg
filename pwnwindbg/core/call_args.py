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

from .memory import (
    read_ptr, read_string, read_wstring, read_memory_safe, virtual_query,
)
from .api_protos import ArgType
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


def _annotate_typed_value(debugger, val, type_tag):
    """Type-aware annotation for a single argument value.

    Falls back to the generic `_annotate_value` for any tag we can't
    decode specially. The type tags come from `core.api_protos.ArgType`.
    """
    if val is None or val == 0:
        # NULL is meaningful for handles/pointers — render explicitly so
        # the user sees a NULL flag/buffer rather than an empty cell.
        if type_tag in (ArgType.LPVOID, ArgType.LPCSTR, ArgType.LPCWSTR,
                        ArgType.HANDLE, ArgType.HMODULE,
                        ArgType.PUNICODE_STRING, ArgType.POBJECT_ATTRIBUTES):
            return "NULL"
        return ""

    ph = debugger.process_handle

    # Pure-numeric types: render as hex, do not deref
    if type_tag in (ArgType.DWORD, ArgType.QWORD, ArgType.SIZE_T):
        # Mask DWORD to 32 bits since the upper half of rcx/rdx is junk for
        # a 4-byte argument value
        if type_tag == ArgType.DWORD:
            return f"={val & 0xFFFFFFFF:#x}"
        return ""  # the default {val:#x} render is already correct
    if type_tag == ArgType.BOOL:
        return "TRUE" if val & 0xFFFFFFFF else "FALSE"

    # Handles: just show the integer; pretty-printing pseudo-handles
    # like INVALID_HANDLE_VALUE / current process / current thread.
    if type_tag in (ArgType.HANDLE, ArgType.HMODULE):
        if val == 0xFFFFFFFFFFFFFFFF or val == 0xFFFFFFFF:
            return "INVALID_HANDLE_VALUE"
        if val == 0xFFFFFFFFFFFFFFFE or val == 0xFFFFFFFE:
            return "GetCurrentThread()"
        if val == 0xFFFFFFFFFFFFFFFF - 1:
            return "GetCurrentProcess()"
        # HMODULE: try to find a matching module base
        if type_tag == ArgType.HMODULE and debugger.symbols:
            mod = debugger.symbols.modules_by_base.get(val)
            if mod:
                return mod.name
        return ""

    # ANSI string
    if type_tag == ArgType.LPCSTR:
        s = read_string(ph, val, 256)
        if s:
            truncated = s[:120]
            if len(s) > 120:
                truncated += "..."
            return f'"{truncated}"'
        return _annotate_value(debugger, val) or "??"

    # Wide string
    if type_tag == ArgType.LPCWSTR:
        ws = read_wstring(ph, val, 256)
        if ws:
            truncated = ws[:120]
            if len(ws) > 120:
                truncated += "..."
            return f'L"{truncated}"'
        return _annotate_value(debugger, val) or "??"

    # PUNICODE_STRING: { USHORT Length; USHORT MaxLen; PWSTR Buffer; }
    # On x64 the Buffer pointer is at offset 8 due to alignment.
    if type_tag == ArgType.PUNICODE_STRING:
        from .memory import read_word, read_qword
        length = read_word(ph, val)
        if length is None:
            return _annotate_value(debugger, val) or "??"
        buf = read_qword(ph, val + 8)
        if not buf:
            return f"UNICODE_STRING(empty, len={length})"
        chars = length // 2 if length else 0
        ws = read_wstring(ph, buf, max(chars + 1, 1))
        if ws:
            truncated = ws[:120]
            if len(ws) > 120:
                truncated += "..."
            return f'UNICODE_STRING(L"{truncated}", len={length})'
        return f"UNICODE_STRING(buf={buf:#x}, len={length})"

    # POBJECT_ATTRIBUTES: layout
    #   ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ...
    # On x64 ObjectName is at offset 0x10.
    if type_tag == ArgType.POBJECT_ATTRIBUTES:
        from .memory import read_qword
        obj_name_ptr = read_qword(ph, val + 0x10)
        if obj_name_ptr:
            ann = _annotate_typed_value(
                debugger, obj_name_ptr, ArgType.PUNICODE_STRING
            )
            return f"OBJECT_ATTRIBUTES(name={ann})"
        return "OBJECT_ATTRIBUTES(name=NULL)"

    # LPVOID and unknowns: generic telescope-style annotation
    return _annotate_value(debugger, val)


def resolve_call_args(debugger, regs, num_args=4, proto=None):
    """Return [(name, value, annotation)] for the arguments of the call
    about to execute at the current RIP.

    Caller is expected to confirm the current instruction is a `call`
    before invoking — we don't re-check here.

    `proto` (optional): a list of `(arg_name, ArgType)` from
    `api_protos.lookup()`. When provided, the number of args fetched and
    their displayed names/annotations come from the prototype, not the
    default convention. Falls back to `num_args` register/stack slots when
    `proto` is None.
    """
    if not regs:
        return []

    typed = proto is not None
    if typed:
        num_args = len(proto)

    if debugger.is_wow64:
        # x86 cdecl/stdcall: all args on stack at [esp + 4*i]
        sp = regs.get("Esp", 0)
        if not sp:
            return []
        out = []
        for i in range(num_args):
            slot = sp + i * 4
            val = read_ptr(debugger.process_handle, slot, 4)
            if typed:
                arg_name, arg_type = proto[i]
                ann = _annotate_typed_value(debugger, val, arg_type)
            else:
                arg_name = f"arg{i + 1}"
                ann = _annotate_value(debugger, val) if val else ""
            out.append((arg_name, val, ann))
        return out

    # Win64
    sp = regs.get("Rsp", 0)
    out = []
    for i in range(num_args):
        if i < len(WIN64_REG_ARGS):
            default_name = WIN64_REG_ARGS[i].lower()
            val = regs.get(WIN64_REG_ARGS[i], 0)
        else:
            default_name = f"arg{i + 1}"
            # arg5 sits right above the 32-byte shadow space at the
            # caller's rsp; we have not executed the call yet so no RA push.
            slot = sp + WIN64_SHADOW_SPACE + (i - len(WIN64_REG_ARGS)) * 8
            val = read_ptr(debugger.process_handle, slot, 8)
        if typed:
            arg_name, arg_type = proto[i]
            ann = _annotate_typed_value(debugger, val, arg_type)
        else:
            arg_name = default_name
            ann = _annotate_value(debugger, val) if val else ""
        out.append((arg_name, val or 0, ann))
    return out
