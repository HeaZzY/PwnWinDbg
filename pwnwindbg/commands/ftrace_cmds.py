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
        - a literal address / symbol → resolved by searching PE exports
          first (so we land on the *implementation* module, not a kernel32
          forwarder thunk that the loader bypassed via IAT redirection),
          and falling back to `eval_expr` for things like `0x401000`,
          `module+0x10`, or DbgHelp-only symbols.

    Returns a list of (display_label, runtime_addr) tuples. Empty list
    if nothing resolved.
    """
    if any(ch in name for ch in "*?["):
        return _expand_glob(debugger, name)

    # Qualified name: let eval_expr handle module!func directly. The
    # explicit prefix already disambiguates the module the user wanted.
    if "!" in name:
        addr = eval_expr(debugger, name)
        if addr is None:
            return []
        label = (
            debugger.symbols.resolve_address(addr) if debugger.symbols else None
        ) or name
        return [(label, addr)]

    # Unqualified name: search the PE export cache across every module.
    # On Win10+, kernel32 exports HeapAlloc/CloseHandle/etc. as forwarders
    # to kernelbase, and DbgHelp may resolve the bare name to a kernel32
    # thunk address that the IAT-rewritten loader never actually calls
    # (so a BP there fires zero times). The PE export cache, by contrast,
    # contains the real implementation address for each module that
    # actually carries the symbol.
    matches = _exact_export_matches(debugger, name)
    if matches:
        return matches

    # Fallback: hex literal, module+offset, or a DbgHelp-only symbol.
    addr = eval_expr(debugger, name)
    if addr is None:
        return []
    label = (
        debugger.symbols.resolve_address(addr) if debugger.symbols else None
    ) or name
    return [(label, addr)]


def _exact_export_matches(debugger, name):
    """Return [(label, addr)] for every module exporting `name` exactly,
    chasing forwarders down to the real implementation.

    On Win10+, both kernel32!HeapAlloc and kernelbase!HeapAlloc are
    forwarders that ultimately resolve to ntdll!RtlAllocateHeap. pefile's
    RVA for a forwarded export points inside the export name table — not
    a real function entry — so a BP placed there fires zero times. We
    detect this case by re-parsing the PE file for the matching module
    and following the `forwarder` chain until we find a non-forwarded
    export or hit a missing module.
    """
    if not debugger.symbols:
        return []
    debugger.symbols._ensure_exports_loaded()
    target = name.lower()

    # First pass: collect every module whose export table mentions `name`.
    candidates = []
    seen_mods = set()
    for key, (mod_name, func_name, _addr) in debugger.symbols._export_by_name.items():
        if "!" in key:
            continue
        if func_name.lower() != target:
            continue
        if mod_name in seen_mods:
            continue
        seen_mods.add(mod_name)
        candidates.append((mod_name, func_name))

    # For each candidate, follow the forwarder chain to a real address.
    # Use a *fresh* visited set per chain so the depth guard only applies
    # within a single forwarder hop sequence, not across independent
    # candidates.
    out = []
    seen_addrs = set()
    for mod_name, func_name in candidates:
        resolved = _chase_forwarder(debugger, mod_name, func_name, set())
        if resolved is None:
            continue
        impl_mod, impl_name, impl_addr = resolved
        if impl_addr in seen_addrs:
            continue
        seen_addrs.add(impl_addr)
        out.append((f"{impl_mod}!{impl_name}", impl_addr))
    return out


def _chase_forwarder(debugger, mod_name, func_name, visited):
    """Follow `mod_name!func_name` through any forwarder chain.

    Returns (real_module_name, real_func_name, real_runtime_addr) or
    None if the chain dead-ends (missing module, broken export table,
    or unbounded loop).
    """
    try:
        import pefile
    except ImportError:
        return None

    key = f"{mod_name.lower()}!{func_name.lower()}"
    if key in visited:
        return None
    visited.add(key)
    if len(visited) > 16:
        return None  # depth guard against pathological forwarder loops

    mod = None
    for m in debugger.symbols.modules:
        if m.name.lower() == mod_name.lower():
            mod = m
            break
    if mod is None or not mod.path:
        return None

    try:
        pe = pefile.PE(mod.path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
        )
    except Exception:
        return None
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        pe.close()
        return None

    target = func_name.lower()
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue
        if exp.name.decode("utf-8", errors="replace").lower() != target:
            continue
        # Forwarded export: parse "DLL.FUNC" / "DLL.#ord" and recurse.
        fwd = getattr(exp, "forwarder", None)
        if fwd:
            pe.close()
            try:
                fwd_str = fwd.decode("utf-8", errors="replace")
            except Exception:
                return None
            if "." not in fwd_str:
                return None
            next_mod, next_func = fwd_str.split(".", 1)
            # Forwarder strings are bare DLL names without extension; the
            # loaded module list uses the full filename, so try a few
            # candidates (`ntdll.dll`, `ntdll`, etc.).
            cand_names = [
                f"{next_mod}.dll",
                next_mod,
                next_mod.lower() + ".dll",
                next_mod.lower(),
            ]
            for cand in cand_names:
                resolved = _chase_forwarder(
                    debugger, cand, next_func, visited
                )
                if resolved is not None:
                    return resolved
            return None
        # Real export: compute the runtime address from base + RVA.
        addr = mod.base_address + exp.address
        pe.close()
        return (mod.name, func_name, addr)

    pe.close()
    return None


def _expand_glob(debugger, pattern):
    """Match a glob (with optional `module!` prefix) against PE exports.

    Each match is then chased through any forwarder chain so the resulting
    BP lands on the real implementation. Without this, a glob like
    `kernelbase!Heap*` resolves HeapAlloc/HeapFree/HeapReAlloc/HeapSize to
    kernelbase RVAs that are themselves forwarders to ntdll!Rtl* — placing
    a BP at those raw RVAs fires zero times because no thread ever lands
    inside the export name table.
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
    seen_pairs = set()
    for key, (mod_name, func_name, _addr) in debugger.symbols._export_by_name.items():
        if "!" in key:
            continue  # iterate the bare-name keys only
        mod_l = mod_name.lower()
        if mod_filter:
            stem = mod_l.rsplit(".", 1)[0] if "." in mod_l else mod_l
            if mod_l != mod_filter and stem != mod_filter:
                continue
        if not fnmatch.fnmatchcase(func_name.lower(), func_pat_l):
            continue
        pair_key = (mod_l, func_name.lower())
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)
        # Fresh visited set per chain — the depth guard inside
        # _chase_forwarder is meant to bound a single forwarder sequence,
        # not accumulate across all matches of a glob.
        resolved = _chase_forwarder(debugger, mod_name, func_name, set())
        if resolved is None:
            continue
        impl_mod, impl_name, impl_addr = resolved
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
