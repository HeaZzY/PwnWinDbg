"""ftrace — bulk-trace arbitrary user-named functions via auto-continuing BPs.

Generalizes `syscalls` (which only knows about ntdll!Nt* exports) to any
function name the user can resolve. Each call site logs a one-line entry
to the REPL with typed arguments derived from `core.api_protos` when a
prototype is registered for that function. Functions without a registered
prototype fall back to a generic `(rcx=…, rdx=…, r8=…, r9=…)` rendering.

Builds on the same dprintf machinery as `syscalls` — every BP carries a
`bp.action` format string evaluated by `format_dprintf` against the live
register/memory namespace. The wiring is just:

    1. Resolve each user-supplied name to an address (eval_expr handles
       `WinExec`, `kernel32!WinExec`, `ntdll!NtClose`, bare hex, …).
       Glob patterns like `*alloc*` or `Reg*` are expanded against the
       PE export cache.
    2. Look up the prototype via `api_protos.lookup`.
    3. Synthesize a format string from the prototype: each argument is
       rendered with the right helper (`cstr` for LPCSTR, `wstr` for
       LPCWSTR, masked-hex for DWORD, etc.). Args 5+ on x64 are pulled
       from `qword(rsp+0x28)` etc. (the BP fires *after* the call, so
       the return address sits at [rsp+0]).
    4. Install an INT3 with `bp.action = fmt`. The standard dprintf path
       in core/debugger.py renders + auto-continues.

Usage:
    ftrace on <name> [name ...]   — install traces (each name may glob)
    ftrace off [filter]           — remove all (or matching by substring)
    ftrace list                   — show currently active traces
"""

import fnmatch

from ..core.api_protos import ArgType, lookup as proto_lookup
from ..display.formatters import banner, console, error, info, success
from ..utils.addr_expr import eval_expr


# Win64 ABI: first four args in rcx/rdx/r8/r9. The BP fires at the
# function entry (after the call), so [rsp+0] is the return address and
# the 32-byte shadow space starts at [rsp+8]. The first stack-passed arg
# (arg5) therefore lives at [rsp+0x28].
_X64_REG_ARGS = ("rcx", "rdx", "r8", "r9")
_X64_FIRST_STACK_OFFSET = 0x28
_X64_STACK_STRIDE = 8

# Wow64: every arg is on the stack at [esp+4], [esp+8], …; [esp+0] is the
# return address.
_X86_FIRST_STACK_OFFSET = 4
_X86_STACK_STRIDE = 4


def _x64_arg_loc(idx):
    """Format-string expression for the i-th x64 argument."""
    if idx < len(_X64_REG_ARGS):
        return _X64_REG_ARGS[idx]
    off = _X64_FIRST_STACK_OFFSET + (idx - len(_X64_REG_ARGS)) * _X64_STACK_STRIDE
    return f"qword(rsp+{off:#x})"


def _x86_arg_loc(idx):
    off = _X86_FIRST_STACK_OFFSET + idx * _X86_STACK_STRIDE
    return f"dword(esp+{off:#x})"


def _arg_placeholder(loc, type_tag, is_wow64):
    """Build a `{...}` format placeholder for one typed argument.

    Returns the body that goes inside the braces (without the surrounding
    `{` `}`). The format renderer in `bp_conditions.format_dprintf` will
    eval the expression and apply the optional `:spec`.
    """
    # String types — deref via cstr/wstr. The renderer prints the result
    # raw (no quoting) which is fine for one-line tracing.
    if type_tag == ArgType.LPCSTR:
        return f"cstr({loc})"
    if type_tag == ArgType.LPCWSTR:
        return f"wstr({loc})"

    # PUNICODE_STRING: { USHORT Length; USHORT MaxLen; PWSTR Buffer; }
    # On x64 the Buffer pointer is at offset 8 due to alignment. We
    # deref Buffer and read it as a wide string. On wow64 the layout is
    # the same idea but the Buffer pointer sits at offset 4.
    if type_tag == ArgType.PUNICODE_STRING:
        if is_wow64:
            return f"wstr(dword({loc}+4))"
        return f"wstr(qword({loc}+8))"

    # POBJECT_ATTRIBUTES: ObjectName at offset 0x10 -> PUNICODE_STRING.
    # Deref two levels: ObjectName -> Buffer -> wide string.
    if type_tag == ArgType.POBJECT_ATTRIBUTES:
        if is_wow64:
            return f"wstr(dword(dword({loc}+0x8)+4))"
        return f"wstr(qword(qword({loc}+0x10)+8))"

    # DWORD / BOOL: mask the upper bits (the upper half of rcx is junk
    # for a 4-byte arg).
    if type_tag in (ArgType.DWORD, ArgType.BOOL):
        return f"({loc}) & 0xffffffff:hex"

    # HANDLE / HMODULE / LPVOID / QWORD / SIZE_T — render as hex
    return f"{loc}:hex"


def _build_format(func_name, proto, is_wow64):
    """Synthesize a dprintf format string for a known prototype."""
    arg_loc_fn = _x86_arg_loc if is_wow64 else _x64_arg_loc
    parts = []
    for i, (arg_name, arg_type) in enumerate(proto):
        loc = arg_loc_fn(i)
        body = _arg_placeholder(loc, arg_type, is_wow64)
        parts.append(f"{arg_name}={{{body}}}")
    args = ", ".join(parts)
    return f"[tid={{tid:hex}}] {func_name}({args})"


def _build_generic_format(func_name, is_wow64):
    """Fallback format string for functions without a registered prototype.

    Shows the first four register/stack args as raw hex, with no type
    decoding. Same shape as the `syscalls` default.
    """
    arg_loc_fn = _x86_arg_loc if is_wow64 else _x64_arg_loc
    parts = []
    for i in range(4):
        loc = arg_loc_fn(i)
        # Use bare expression so the renderer falls back to its default hex
        # rendering for ints. Cheap and matches the syscalls trace style.
        parts.append(f"a{i + 1}={{{loc}}}")
    args = ", ".join(parts)
    return f"[tid={{tid:hex}}] {func_name}({args})"


def _expand_targets(debugger, name):
    """Resolve a single user-supplied name to a list of (label, addr).

    `name` may be:
        - a glob like `Reg*`, `*alloc*`, `kernel32!CreateFile*` → expanded
          across the PE export cache (case-insensitive). The leading
          `module!` qualifier, if present, restricts matches to that
          module.
        - a literal address / symbol → resolved via `eval_expr`, which
          consults the PE export cache first (so forwarder chains like
          kernel32!HeapAlloc → ntdll!RtlAllocateHeap are pre-chased and
          we land on the real implementation, not a thunk the loader
          IAT-rewrote away).

    Returns a list of (display_label, runtime_addr) tuples. Empty list
    if nothing resolved.
    """
    if any(ch in name for ch in "*?["):
        return _expand_glob(debugger, name)

    addr = eval_expr(debugger, name)
    if addr is None:
        return []
    label = (
        debugger.symbols.resolve_address(addr) if debugger.symbols else None
    ) or name
    return [(label, addr)]


def _expand_glob(debugger, pattern):
    """Match a glob (with optional `module!` prefix) against PE exports.

    Iterates the *qualified* (`module!func`) entries in the export cache
    so each (module, func) pair is visible. Each entry's value already
    points at the chased real implementation, so a `kernelbase!Heap*`
    glob resolves HeapAlloc/HeapFree/etc. to ntdll!Rtl* directly without
    us needing to re-walk the forwarder chain here.
    """
    if not debugger.symbols:
        return []
    debugger.symbols._ensure_exports_loaded()

    mod_filter = None
    func_pat = pattern
    if "!" in pattern:
        mod_filter, func_pat = pattern.split("!", 1)
        mod_filter = mod_filter.lower()

    func_pat_l = func_pat.lower()
    out = []
    seen_addrs = set()
    for key, (impl_mod, impl_name, impl_addr) in debugger.symbols._export_by_name.items():
        if "!" not in key:
            continue  # iterate the qualified keys, one per (orig_mod, orig_func)
        orig_mod, orig_func = key.split("!", 1)
        if mod_filter:
            stem = orig_mod.rsplit(".", 1)[0] if "." in orig_mod else orig_mod
            if orig_mod != mod_filter and stem != mod_filter:
                continue
        if not fnmatch.fnmatchcase(orig_func, func_pat_l):
            continue
        if impl_addr in seen_addrs:
            continue
        seen_addrs.add(impl_addr)
        out.append((f"{impl_mod}!{impl_name}", impl_addr))
    return out


def cmd_ftrace(debugger, args):
    """Bulk-trace arbitrary functions via auto-continuing BPs.

    Subcommands:
        ftrace on <name> [name ...]   — each name may be a literal symbol
                                        or a glob (`Reg*`, `*alloc*`,
                                        `kernel32!CreateFile*`)
        ftrace off [filter]           — remove all (or matching substring)
        ftrace list                   — show currently active traces
    """
    if not debugger.process_handle:
        error("No process attached")
        return None

    raw = args.strip()
    if not raw:
        error("Usage: ftrace on <name> [name ...] | off [filter] | list")
        return None

    parts = raw.split()
    sub = parts[0].lower()

    if not hasattr(debugger, "ftrace_bps"):
        debugger.ftrace_bps = set()

    if sub in ("list", "ls"):
        return _cmd_list(debugger)
    if sub in ("off", "stop", "clear"):
        return _cmd_off(debugger, parts[1:])
    if sub != "on":
        error(f"Unknown subcommand: {sub}")
        error("Usage: ftrace on <name> [name ...] | off [filter] | list")
        return None

    if len(parts) < 2:
        error("Usage: ftrace on <name> [name ...]")
        return None

    return _cmd_on(debugger, parts[1:])


def _cmd_list(debugger):
    rows = [
        debugger.bp_manager.get_by_id(bp_id) for bp_id in debugger.ftrace_bps
    ]
    rows = [bp for bp in rows if bp is not None]
    if not rows:
        info("No ftrace traces installed")
        return None
    banner(f"ftrace — {len(rows)} active trace(s)")
    for bp in sorted(rows, key=lambda b: b.address):
        sym = (
            debugger.symbols.resolve_address(bp.address) or f"{bp.address:#x}"
        )
        console.print(
            f"  [bright_yellow]BP#{bp.id}[/]  "
            f"[bright_blue]{bp.address:#x}[/]  "
            f"hits={bp.hit_count}  {sym}"
        )
    return None


def _cmd_off(debugger, filters):
    """Remove ftrace BPs. With no filter, removes all of them; with one or
    more substrings, removes only the BPs whose resolved symbol contains
    any of them (case-insensitive).
    """
    if not debugger.ftrace_bps:
        info("No ftrace traces are active")
        return None

    keep_filter = filters
    n_removed = 0
    for bp_id in list(debugger.ftrace_bps):
        bp = debugger.bp_manager.get_by_id(bp_id)
        if bp is None:
            debugger.ftrace_bps.discard(bp_id)
            continue
        if keep_filter:
            sym = debugger.symbols.resolve_address(bp.address) or ""
            if not any(f.lower() in sym.lower() for f in keep_filter):
                continue
        if debugger.bp_manager.remove(debugger.process_handle, bp_id):
            n_removed += 1
            debugger.ftrace_bps.discard(bp_id)

    if n_removed:
        success(f"Removed {n_removed} ftrace trace(s)")
    else:
        info("No matching ftrace traces removed")
    return None


def _cmd_on(debugger, names):
    is_wow64 = debugger.is_wow64

    # Expand every name (glob or literal) to a (label, addr) list, then
    # de-dup across names so the same address isn't BP'd twice when two
    # patterns overlap.
    seen_addrs = set()
    targets = []
    unresolved = []
    for name in names:
        expanded = _expand_targets(debugger, name)
        if not expanded:
            unresolved.append(name)
            continue
        for label, addr in expanded:
            if addr in seen_addrs:
                continue
            seen_addrs.add(addr)
            targets.append((label, addr))

    if not targets:
        if unresolved:
            error(f"Could not resolve any of: {' '.join(unresolved)}")
        else:
            error("No targets to trace")
        return None

    n_added = 0
    n_skipped = 0
    n_failed = 0
    n_typed = 0
    for label, addr in targets:
        # Don't disturb pre-existing BPs (could be a user BP at the same
        # address — overwriting bp.action would clobber their setup).
        if debugger.bp_manager.get_by_address(addr) is not None:
            n_skipped += 1
            continue
        try:
            bp = debugger.bp_manager.add(debugger.process_handle, addr)
        except Exception:
            n_failed += 1
            continue

        # Strip a `+offset` from the label when looking up the prototype:
        # DbgHelp may name a few bytes into the prologue.
        bare_name = label
        if "!" in bare_name:
            bare_name = bare_name.split("!", 1)[1]
        if "+" in bare_name:
            bare_name = bare_name.split("+", 1)[0]

        proto = proto_lookup(bare_name)
        if proto:
            bp.action = _build_format(label, proto, is_wow64)
            n_typed += 1
        else:
            bp.action = _build_generic_format(label, is_wow64)
        debugger.ftrace_bps.add(bp.id)
        n_added += 1

    if n_added == 0:
        error(
            f"Failed to install any traces "
            f"({n_skipped} skipped, {n_failed} failed)"
        )
        return None

    summary = [f"Tracing {n_added} function(s)"]
    if n_typed:
        summary.append(f"{n_typed} with typed args")
    if n_skipped:
        summary.append(f"{n_skipped} skipped (existing BP)")
    if n_failed:
        summary.append(f"{n_failed} failed")
    if unresolved:
        summary.append(f"{len(unresolved)} unresolved")
    success(", ".join(summary))
    if unresolved:
        info(f"Unresolved: {' '.join(unresolved)}")
    info("Use `ftrace off` to disable, `bl` to see all BPs")
    return None
