"""hooks — IAT and inline hook detector.

Two distinct checks:

1. **IAT scan** — for every loaded module, walk its import directory and
   read each IAT slot live from process memory. If a slot points outside
   the source DLL's image range, the import has been redirected (classic
   IAT hooking used by EDR / userland rootkits).

2. **Inline scan** — for a curated list of "interesting" exports (mostly
   ntdll / kernel32 / ws2_32), read the first 5 bytes of the function and
   pattern-match common detour shapes:
       jmp imm32                 (E9 ?? ?? ?? ??)
       push imm32 ; ret          (68 ?? ?? ?? ?? C3)
       mov rax, imm64 ; jmp rax  (48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0)

Cross-module destinations are flagged. The IAT path is exhaustive; the
inline path is sample-based because reading every export of every loaded
module is too slow for an interactive command.
"""

import struct

import pefile

from rich.table import Table
from rich.text import Text

from ..display.formatters import banner, console, error, info, success, warn
from ..core.memory import read_memory_safe, read_qword, read_dword


# Functions to check for inline hooks. Curated to common EDR / API monitor
# targets. Not exhaustive — extend as needed.
INLINE_TARGETS = [
    ("ntdll.dll",     "NtCreateFile"),
    ("ntdll.dll",     "NtOpenProcess"),
    ("ntdll.dll",     "NtReadFile"),
    ("ntdll.dll",     "NtWriteFile"),
    ("ntdll.dll",     "NtAllocateVirtualMemory"),
    ("ntdll.dll",     "NtProtectVirtualMemory"),
    ("ntdll.dll",     "NtWriteVirtualMemory"),
    ("ntdll.dll",     "NtCreateThreadEx"),
    ("ntdll.dll",     "NtMapViewOfSection"),
    ("ntdll.dll",     "NtQuerySystemInformation"),
    ("ntdll.dll",     "LdrLoadDll"),
    ("kernel32.dll",  "CreateFileW"),
    ("kernel32.dll",  "CreateProcessW"),
    ("kernel32.dll",  "VirtualAllocEx"),
    ("kernel32.dll",  "VirtualProtectEx"),
    ("kernel32.dll",  "WriteProcessMemory"),
    ("kernel32.dll",  "LoadLibraryW"),
    ("kernel32.dll",  "WinExec"),
    ("ws2_32.dll",    "send"),
    ("ws2_32.dll",    "recv"),
    ("ws2_32.dll",    "connect"),
]


def _classify_hook(buf, addr):
    """Pattern-match a 16-byte slice for common detour shapes.
    Returns (kind, target) or (None, None).
    """
    if not buf or len(buf) < 5:
        return None, None
    # jmp rel32
    if buf[0] == 0xE9:
        rel = struct.unpack("<i", buf[1:5])[0]
        return "jmp rel32", addr + 5 + rel
    # push imm32 ; ret
    if buf[0] == 0x68 and len(buf) >= 6 and buf[5] == 0xC3:
        target = struct.unpack("<I", buf[1:5])[0]
        return "push/ret", target
    # mov rax, imm64 ; jmp rax  (48 B8 .. 8 bytes .. FF E0)
    if (buf[0] == 0x48 and buf[1] == 0xB8 and len(buf) >= 12
            and buf[10] == 0xFF and buf[11] == 0xE0):
        target = struct.unpack("<Q", buf[2:10])[0]
        return "mov/jmp", target
    # jmp [rip+disp32]   (FF 25 disp32) — common in IAT thunks but also detours
    if buf[0] == 0xFF and buf[1] == 0x25 and len(buf) >= 6:
        disp = struct.unpack("<i", buf[2:6])[0]
        return "jmp [rip+disp]", addr + 6 + disp
    return None, None


def _scan_inline_hooks(debugger):
    """Read 16 bytes at each curated export and look for detour shapes."""
    findings = []
    syms = debugger.symbols
    if not syms:
        return findings

    if hasattr(syms, "_ensure_exports_loaded"):
        syms._ensure_exports_loaded()

    cache = getattr(syms, "_export_by_name", {})
    for dll, fname in INLINE_TARGETS:
        key = f"{dll.lower()}!{fname.lower()}"
        entry = cache.get(key)
        if not entry:
            entry = cache.get(fname.lower())
        if not entry:
            continue
        addr = entry[2]

        buf = read_memory_safe(debugger.process_handle, addr, 16)
        if not buf:
            continue
        kind, target = _classify_hook(buf, addr)
        if not kind or not target:
            continue

        # Where does the target live?
        target_mod = syms.get_module_at(target)
        source_mod = syms.get_module_at(addr)
        if target_mod and source_mod and target_mod.base_address == source_mod.base_address:
            # In-module detour (rare but legitimate, e.g. forwarder).
            continue
        findings.append({
            "function": f"{dll}!{fname}",
            "address":  addr,
            "kind":     kind,
            "target":   target,
            "target_mod": target_mod.name if target_mod else "?",
            "bytes":    buf[:6].hex(),
        })
    return findings


def _build_forwarder_map(modules):
    """For each module, parse its export table once and collect the set of
    forwarded export names with their resolved runtime targets.

    Returns: { source_mod_name_lower: { import_name_lower: forwarded_addr } }
    Forwarded entries look like "NTDLL.RtlDeleteCriticalSection" in the
    export table; we resolve the target name against the loaded modules.
    """
    out = {}
    by_name = {m.name.lower(): m for m in modules}
    # Two-letter stem (e.g. "ntdll") -> module
    by_stem = {m.name.lower().rsplit(".", 1)[0]: m for m in modules}

    for mod in modules:
        try:
            pe = pefile.PE(mod.path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
            )
        except Exception:
            continue
        try:
            ent = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            if ent is None:
                continue
            mod_map = {}
            for exp in ent.symbols:
                fwd = exp.forwarder
                if not fwd or not exp.name:
                    continue
                fwd_str = (fwd.decode("utf-8", errors="replace")
                           if isinstance(fwd, bytes) else fwd)
                # "NTDLL.RtlAllocateHeap" or "API-MS-WIN-…-l1-1-0.func"
                if "." not in fwd_str:
                    continue
                tgt_dll, tgt_func = fwd_str.split(".", 1)
                tgt_mod = (by_name.get(tgt_dll.lower() + ".dll")
                           or by_stem.get(tgt_dll.lower()))
                if tgt_mod is None:
                    continue
                # Resolve the target function in the target module
                try:
                    tgt_pe = pefile.PE(tgt_mod.path, fast_load=True)
                    tgt_pe.parse_data_directories(
                        directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
                    )
                    tgt_ent = getattr(tgt_pe, "DIRECTORY_ENTRY_EXPORT", None)
                    if tgt_ent is None:
                        tgt_pe.close()
                        continue
                    for tgt_exp in tgt_ent.symbols:
                        if tgt_exp.name and tgt_exp.name.decode("utf-8", "replace") == tgt_func:
                            mod_map[exp.name.decode("utf-8", "replace").lower()] = (
                                tgt_mod.base_address + tgt_exp.address
                            )
                            break
                    tgt_pe.close()
                except Exception:
                    pass
            if mod_map:
                out[mod.name.lower()] = mod_map
        finally:
            pe.close()
    return out


def _scan_iat(debugger, only_module=None, max_findings=200):
    """Walk every module's import table and flag IAT entries that point
    outside the *expected* source DLL's image range.

    Forwarder-aware: if the IAT entry points to *another* module that
    exports the same function name (e.g. kernel32!HeapAlloc -> ntdll!RtlAllocateHeap-style
    apiset forwards), it is treated as a legitimate redirect, not a hook.
    """
    syms = debugger.symbols
    if not syms or not syms.modules:
        return []
    if hasattr(syms, "_ensure_exports_loaded"):
        syms._ensure_exports_loaded()
    export_by_addr = getattr(syms, "_export_by_addr", {})
    # Pre-compute forwarder maps for every module so we can compare imports
    # against legitimate export redirects.
    forwarders = _build_forwarder_map(syms.modules)

    findings = []
    for mod in syms.modules:
        if only_module and only_module.lower() not in mod.name.lower():
            continue
        try:
            pe = pefile.PE(mod.path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
            )
        except Exception:
            continue

        try:
            entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None) or []
            for dll_entry in entries:
                expected_dll = dll_entry.dll.decode("utf-8", errors="replace").lower()
                # Find the loaded source module that satisfies this import
                source = None
                for m in syms.modules:
                    if m.name.lower() == expected_dll:
                        source = m
                        break

                for imp in dll_entry.imports:
                    fname = (imp.name.decode("utf-8", errors="replace")
                             if imp.name else f"ord:{imp.ordinal}")
                    iat_slot_va = mod.base_address + (imp.address - pe.OPTIONAL_HEADER.ImageBase)
                    cur = read_qword(debugger.process_handle, iat_slot_va)
                    if cur is None or cur == 0:
                        continue

                    target_mod = syms.get_module_at(cur)

                    suspicious = False
                    reason = ""
                    if source is None:
                        # Loaded module list missing the importer — note but
                        # don't flag (could be apiset alias)
                        continue
                    if not source.contains(cur):
                        # Forwarder check 1: same function name, different
                        # module (apiset alias). Cheap.
                        forwarded = export_by_addr.get(cur)
                        if forwarded and forwarded[1].lower() == fname.lower():
                            continue
                        # Forwarder check 2: source DLL has an EXPORT-table
                        # forwarder for `fname` that resolves to `cur`.
                        # Handles kernel32!DeleteCriticalSection -> ntdll!RtlDeleteCriticalSection.
                        src_fwd = forwarders.get(source.name.lower(), {})
                        if src_fwd.get(fname.lower()) == cur:
                            continue
                        suspicious = True
                        if target_mod:
                            reason = f"-> {target_mod.name} (expected {source.name})"
                        else:
                            reason = "-> unknown region"

                    if suspicious:
                        findings.append({
                            "module":   mod.name,
                            "import":   f"{expected_dll}!{fname}",
                            "slot":     iat_slot_va,
                            "current":  cur,
                            "reason":   reason,
                        })
                        if len(findings) >= max_findings:
                            return findings
        finally:
            pe.close()
    return findings


def cmd_hooks(debugger, args):
    """Scan for IAT / inline hooks in the debuggee.

    Usage:
        hooks                    — scan IAT of every module + inline targets
        hooks --inline           — only inline scan
        hooks --iat              — only IAT scan
        hooks <module>           — restrict IAT scan to one module
    """
    if not debugger.process_handle:
        error("No process attached")
        return None
    if not debugger.symbols or not debugger.symbols.modules:
        error("No modules loaded — wait for the process to settle")
        return None

    parts = args.strip().split()
    do_inline = True
    do_iat = True
    only_module = None
    for p in parts:
        if p in ("--inline", "-i"):
            do_iat = False
        elif p in ("--iat", "--imports"):
            do_inline = False
        elif p.startswith("-"):
            warn(f"Unknown flag: {p}")
        else:
            only_module = p

    if do_iat:
        info(f"Scanning IAT of {len(debugger.symbols.modules)} module(s)…")
        iat_findings = _scan_iat(debugger, only_module=only_module)
        banner(f"IAT scan — {len(iat_findings)} suspicious entries")
        if iat_findings:
            tbl = Table(show_header=True, border_style="cyan",
                        header_style="bold bright_white")
            tbl.add_column("Module",  style="bright_green")
            tbl.add_column("Import",  style="bright_white")
            tbl.add_column("Slot",    style="bright_yellow")
            tbl.add_column("Current", style="bright_red")
            tbl.add_column("Reason",  style="bright_black")
            for f in iat_findings:
                tbl.add_row(
                    f["module"], f["import"],
                    f"{f['slot']:#018x}", f"{f['current']:#018x}",
                    f["reason"],
                )
            console.print(tbl)
        else:
            success("  IAT clean — no cross-module redirections")

    if do_inline:
        info("Scanning inline detours on curated exports…")
        inline_findings = _scan_inline_hooks(debugger)
        banner(f"Inline scan — {len(inline_findings)} hook(s)")
        if inline_findings:
            tbl = Table(show_header=True, border_style="cyan",
                        header_style="bold bright_white")
            tbl.add_column("Function", style="bright_white")
            tbl.add_column("Addr",     style="bright_yellow")
            tbl.add_column("Kind",     style="bright_magenta")
            tbl.add_column("Target",   style="bright_red")
            tbl.add_column("In",       style="bright_green")
            tbl.add_column("Bytes",    style="bright_black")
            for f in inline_findings:
                tbl.add_row(
                    f["function"], f"{f['address']:#018x}",
                    f["kind"], f"{f['target']:#018x}",
                    f["target_mod"], f["bytes"],
                )
            console.print(tbl)
        else:
            success("  Inline clean — no detours on curated targets")

    return None
