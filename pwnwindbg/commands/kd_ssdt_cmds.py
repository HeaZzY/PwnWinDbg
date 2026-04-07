"""SSDT (System Service Descriptor Table) commands for kernel debug sessions.

Commands:
    kdssdt              — dump the full SSDT (KeServiceDescriptorTable)
    kdssdt <count>      — dump only the first <count> entries
    kdssdt -h           — only show entries whose handler is OUTSIDE ntoskrnl
                          (potential rootkit hooks)

------------------------------------------------------------------------------
KeServiceDescriptorTable layout (x64)
------------------------------------------------------------------------------

`nt!KeServiceDescriptorTable` is an exported symbol pointing at an array of
`_SERVICE_DESCRIPTOR_TABLE` entries. The first entry describes the native
syscall table consumed by `nt!KiSystemCall64`:

    typedef struct _SERVICE_DESCRIPTOR_TABLE {
        PULONG     ServiceTableBase;        // +0x00  packed offset array
        PULONG     ServiceCounterTableBase; // +0x08  (debug builds only)
        ULONGLONG  NumberOfServices;        // +0x10  e.g. 0x1F0 on Win10/11
        PULONG     ParamTableBase;          // +0x18
        // [3 more entries follow for the shadow / Win32K SSDT — ignored]
    } SERVICE_DESCRIPTOR_TABLE;

------------------------------------------------------------------------------
Packed offset format
------------------------------------------------------------------------------

Each ServiceTableBase[i] is a 32-bit *packed* value, NOT a raw pointer:

    entry = (signed_offset << 4) | arg_count

where:
    - the low 4 bits  = number of stack-passed args (beyond the first 4
                        register args of the x64 calling convention)
    - the upper 28 bits = signed byte offset from `ServiceTableBase` itself,
                          stored shifted-left by 4

To recover the actual handler address:

    entry_i32 = struct.unpack_from("<i", data, n * 4)[0]   # SIGNED!
    arg_count = entry_i32 & 0xF
    offset    = entry_i32 >> 4         # arithmetic shift, sign-preserving
    func_addr = service_table_base + offset

Python's `>>` on a signed int is arithmetic, so the sign bit is preserved
naturally. The base used for the offset is `ServiceTableBase` (the array
itself), NOT the address of the SDT structure.

x86 kernels use a different encoding — this command is x64-only.
"""

import struct

from ..display.formatters import (
    info, error, success, warn, console, banner,
)

from rich.table import Table


# Sanity bounds for NumberOfServices. Win10/11 native SSDT is ~0x1F0 (496)
# entries. Anything wildly outside this window means we read garbage.
_MIN_SERVICES = 100
_MAX_SERVICES = 1000

# Kernel half of the canonical x64 address space
_KERNEL_MIN = 0xFFFF800000000000


# Canonical KiSystemCall64 prologue on x64 Windows (stable from Win7 onward):
#
#     0F 01 F8                          swapgs
#     65 48 89 24 25 10 00 00 00        mov   gs:[10h], rsp     ; save user rsp
#
# 12 bytes total, unique to this entry — Microsoft hasn't changed the
# instruction sequence in over a decade because it's literally how the CPU
# transitions from user to kernel on syscall.
_KISYSTEMCALL64_SIGNATURE = bytes.fromhex("0F01F8654889242510000000")


def _find_kisystemcall64_via_signature(session, kbase, ntos_size):
    """Locate `nt!KiSystemCall64` by signature scan of ntoskrnl's text.

    Used when the QEMU GDB stub doesn't expose MSR LSTAR (which is the case
    for vanilla `qemu-system-x86_64 -gdb tcp:` — the monitor has no `rdmsr`,
    and `info registers` doesn't print MSRs).

    Reads ntoskrnl in 1 MiB chunks with a 16-byte overlap (the signature is
    12 bytes, so 16 is more than enough to handle a chunk boundary cut), and
    returns the first hit. The .text section starts a few KB after the PE
    header, so we begin at +0x1000 to skip headers, and stop after `ntos_size`
    or 8 MiB, whichever comes first.
    """
    if not ntos_size:
        ntos_size = 0x800000  # 8 MiB fallback if module list lookup failed

    chunk_size = 0x100000      # 1 MiB
    overlap = 16
    end_offset = min(ntos_size, 0x800000)

    offset = 0x1000  # skip PE headers
    while offset < end_offset:
        to_read = min(chunk_size, end_offset - offset)
        chunk = session.read_virtual(kbase + offset, to_read)
        if not chunk:
            offset += chunk_size - overlap
            continue
        idx = chunk.find(_KISYSTEMCALL64_SIGNATURE)
        if idx != -1:
            hit = kbase + offset + idx
            info(f"  KiSystemCall64 signature found at {hit:#x}")
            return hit
        offset += len(chunk) - overlap

    return 0


def _find_sdt_via_kisystemcall64(session, kbase, kernel_hi, ntos_size):
    """Locate `nt!KeServiceDescriptorTable` by disassembling KiSystemCall64.

    `KeServiceDescriptorTable` is no longer exported on Win10/11 — Microsoft
    removed it years ago. The reliable trick is:

      1. Find `KiSystemCall64`. We try MSR LSTAR (0xC0000082) first; if the
         transport can't read MSRs (QEMU GDB stub), fall back to a signature
         scan of ntoskrnl's text section.
      2. Disassemble its body (and the contiguous KiSystemServiceUser /
         KiSystemServiceStart helpers it falls into).
      3. Scan for `lea r64, [rip+disp32]` (REX.W or REX.W+REX.R variants).
      4. For each in-kernel target, treat it as a `_SERVICE_DESCRIPTOR_TABLE`
         (qword ServiceTableBase, qword pad, qword NumberOfServices) and
         validate that NumberOfServices is in the sane range and that
         ServiceTableBase points into the kernel image.

    Returns the SDT virtual address or 0.
    """
    # Try LSTAR first — fast path for kernel transports that expose it.
    kisys = 0
    if hasattr(session, "read_msr_lstar"):
        lstar = session.read_msr_lstar()
        if lstar and lstar >= _KERNEL_MIN:
            kisys = lstar
            info(f"LSTAR / KiSystemCall64: {kisys:#x}")

    # Signature-scan fallback for transports without MSR access.
    if not kisys:
        info("LSTAR unavailable — locating KiSystemCall64 by signature scan")
        kisys = _find_kisystemcall64_via_signature(session, kbase, ntos_size)
        if not kisys:
            warn("KiSystemCall64 signature not found in ntoskrnl text")
            return 0

    # KiSystemCall64 dispatches into KiSystemServiceUser/KiSystemServiceStart,
    # which live a few hundred bytes after it. The lea-to-SDT instruction
    # often shows up well past the first KB. Read 16 KB to cover all of it.
    code = session.read_virtual(kisys, 0x4000)
    if not code or len(code) < 16:
        warn(f"Could not read KiSystemCall64 body at {kisys:#x}")
        return 0

    # Walk byte-by-byte looking for REX.W lea r64, [rip+disp32]:
    #     48 8D /r  or  4C 8D /r   with ModR/M (modrm & 0xC7) == 0x05
    candidates = []
    seen = set()
    n = len(code)
    i = 0
    while i + 7 <= n:
        b0 = code[i]
        b1 = code[i + 1]
        b2 = code[i + 2]
        if (b0 in (0x48, 0x4C)) and b1 == 0x8D and (b2 & 0xC7) == 0x05:
            disp32 = struct.unpack_from("<i", code, i + 3)[0]
            target = (kisys + i + 7 + disp32) & 0xFFFFFFFFFFFFFFFF
            if target not in seen and kbase <= target < kernel_hi:
                seen.add(target)
                candidates.append(target)
        i += 1

    info(f"  {len(candidates)} in-kernel lea targets to validate")

    for sdt_addr in candidates:
        sdt_data = session.read_virtual(sdt_addr, 32)
        if not sdt_data or len(sdt_data) < 32:
            continue
        service_table_base = struct.unpack_from("<Q", sdt_data, 0x00)[0]
        n_services         = struct.unpack_from("<Q", sdt_data, 0x10)[0]
        if not (_MIN_SERVICES <= n_services <= _MAX_SERVICES):
            continue
        if service_table_base < _KERNEL_MIN:
            continue
        if not (kbase <= service_table_base < kernel_hi):
            continue
        return sdt_addr
    return 0


def _resolve_addr_to_module(addr, modules):
    """Map a kernel address to a `module!offset` string, or None.

    `modules` is the list returned by `_walk_module_list(session)`:
        (dll_base, size_of_image, entry_point, base_name, full_name)
    """
    if not modules:
        return None
    for dll_base, size, _ep, base_name, _full in modules:
        if dll_base <= addr < dll_base + size:
            base_clean = (
                base_name.replace(".sys", "")
                         .replace(".exe", "")
                         .replace(".dll", "")
            )
            return f"{base_clean}!{addr - dll_base:#x}"
    return None


def cmd_kdssdt(debugger, args):
    """Dump the System Service Descriptor Table.

    Usage:
        kdssdt              — show all entries
        kdssdt <count>      — show only the first <count> entries
        kdssdt -h           — only show entries whose handler lies OUTSIDE
                              ntoskrnl (likely rootkit hooks)

    Decodes `nt!KeServiceDescriptorTable`. Each entry is a packed 32-bit
    value: the low 4 bits give the stack-arg count, the upper 28 bits give
    a signed byte offset from `ServiceTableBase` (already shifted left by 4
    when stored). See the module docstring for the gory details.
    """
    from .kd_ps_cmds import _get_session_and_system
    from .kd_cmds import _find_kernel_base, _find_export, _walk_module_list

    session, _sys_eproc = _get_session_and_system()
    if session is None:
        return None

    # ----- argument parsing -------------------------------------------------
    parts = args.strip().split()
    show_only_hooks = False
    max_entries = None
    for tok in parts:
        if tok in ("-h", "--hooks", "--hooked"):
            show_only_hooks = True
            continue
        try:
            max_entries = int(tok, 0)
        except ValueError:
            error(f"Unknown argument: {tok}  (usage: kdssdt [count] [-h])")
            return None

    # ----- locate KeServiceDescriptorTable ----------------------------------
    kbase = _find_kernel_base(session)
    if not kbase:
        error("Cannot locate kernel base — try running `lm` first")
        return None

    # We need ntoskrnl's image size up front: the SDT signature scan needs
    # to know how far to walk into the .text section, and the hook detector
    # below needs the upper bound to flag escapees.
    modules = _walk_module_list(session)
    ntos_base = 0
    ntos_size = 0
    if modules:
        for dll_base, size, _ep, base_name, _full in modules:
            low = base_name.lower()
            if low.startswith("ntoskrnl") or low.startswith("ntkrnl"):
                ntos_base = dll_base
                ntos_size = size
                break
        if not ntos_base:
            ntos_base = kbase

    # KeServiceDescriptorTable was un-exported on modern Win10/11. Try the
    # export first (for old builds and SSDT-shadow builds), and fall back to
    # KiSystemCall64 disassembly (via LSTAR if available, otherwise via a
    # signature scan of ntoskrnl's text).
    rva = _find_export(session, kbase, "KeServiceDescriptorTable")
    if rva:
        sdt_addr = kbase + rva
    else:
        info("KeServiceDescriptorTable not exported — locating via KiSystemCall64")
        sdt_addr = _find_sdt_via_kisystemcall64(
            session, kbase, kbase + 0x2000000, ntos_size
        )
        if not sdt_addr:
            error("Cannot resolve KeServiceDescriptorTable (export missing, KiSystemCall64 scan failed)")
            return None

    # ----- read the descriptor (32 bytes is plenty for the first entry) ----
    sdt_data = session.read_virtual(sdt_addr, 32)
    if not sdt_data or len(sdt_data) < 32:
        error(f"Failed to read SDT at {sdt_addr:#x}")
        return None

    service_table_base = struct.unpack_from("<Q", sdt_data, 0x00)[0]
    n_services         = struct.unpack_from("<Q", sdt_data, 0x10)[0]

    if service_table_base == 0:
        error(f"ServiceTableBase is NULL — bogus read at {sdt_addr:#x}")
        return None

    if not (_MIN_SERVICES <= n_services <= _MAX_SERVICES):
        error(
            f"NumberOfServices = {n_services} is outside sane range "
            f"[{_MIN_SERVICES}, {_MAX_SERVICES}] — likely a bad read."
        )
        return None

    # ----- pull the packed offset array -------------------------------------
    table_bytes = n_services * 4
    table_data = session.read_virtual(service_table_base, table_bytes)
    if not table_data or len(table_data) < table_bytes:
        error(
            f"Failed to read ServiceTable ({table_bytes} bytes) "
            f"at {service_table_base:#x}"
        )
        return None

    # `modules`, `ntos_base`, `ntos_size` were resolved up front (above) — we
    # need them now for symbolisation and the hook detector.

    # ----- header -----------------------------------------------------------
    banner(f"SSDT (KeServiceDescriptorTable @ {sdt_addr:#x})")
    info(
        f"ServiceTableBase: {service_table_base:#x}   "
        f"NumberOfServices: {n_services} ({n_services:#x})"
    )
    if show_only_hooks:
        info("Filter: showing only entries whose handler is OUTSIDE ntoskrnl")

    # ----- table ------------------------------------------------------------
    tbl = Table(
        show_header=True,
        border_style="cyan",
        header_style="bold bright_white",
    )
    tbl.add_column("#",               style="bright_yellow", justify="right")
    tbl.add_column("Args",            style="yellow",        justify="right")
    tbl.add_column("Handler Address", style="bright_cyan")
    tbl.add_column("Symbol",          style="bright_green")
    tbl.add_column("Note",            style="bright_red")

    limit = n_services if max_entries is None else min(max_entries, n_services)

    rows_emitted = 0
    hook_count = 0

    for i in range(limit):
        entry_i32 = struct.unpack_from("<i", table_data, i * 4)[0]
        arg_count = entry_i32 & 0xF
        offset    = entry_i32 >> 4   # arithmetic shift — sign-preserving
        func_addr = (service_table_base + offset) & 0xFFFFFFFFFFFFFFFF

        # Is this handler outside ntoskrnl?
        is_hook = False
        if ntos_base and ntos_size:
            if not (ntos_base <= func_addr < ntos_base + ntos_size):
                is_hook = True
        elif ntos_base:
            # No size known — anything not matching the resolved module is suspect.
            sym_check = _resolve_addr_to_module(func_addr, modules)
            if sym_check and not sym_check.lower().startswith(("ntoskrnl", "ntkrnl")):
                is_hook = True

        if is_hook:
            hook_count += 1

        if show_only_hooks and not is_hook:
            continue

        sym = _resolve_addr_to_module(func_addr, modules) or "<unresolved>"
        note = "<HOOK?>" if is_hook else ""

        tbl.add_row(
            str(i),
            str(arg_count),
            f"{func_addr:#018x}",
            sym,
            note,
        )
        rows_emitted += 1

    console.print(tbl)

    # ----- footer -----------------------------------------------------------
    if show_only_hooks:
        if rows_emitted == 0:
            success(
                f"No SSDT hooks detected — all {limit} scanned entries "
                f"resolve inside ntoskrnl."
            )
        else:
            warn(
                f"{rows_emitted} suspect entries (out of {limit} scanned) "
                f"point outside ntoskrnl."
            )
    else:
        info(
            f"Displayed {rows_emitted} entries"
            + (f" (limited to {max_entries})" if max_entries is not None else "")
            + (f"   suspect: {hook_count}" if hook_count else "")
        )

    return None
