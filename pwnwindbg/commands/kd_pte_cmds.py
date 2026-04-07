"""kdpte — page table walker for x64.

Walks PML4 → PDPT → PD → PT for a virtual address, displaying each
level's entry and the final physical address. Reads CR3 from the
current CPU and uses physical reads to traverse the tables.
"""

import struct

from ..display.formatters import (
    info, error, warn, console, banner,
)

from rich.text import Text
from rich.table import Table


# PTE flag bits (Intel SDM Vol. 3A §4.5)
PTE_P    = 1 << 0    # Present
PTE_RW   = 1 << 1    # Read/Write
PTE_US   = 1 << 2    # User / Supervisor
PTE_PWT  = 1 << 3
PTE_PCD  = 1 << 4
PTE_A    = 1 << 5    # Accessed
PTE_D    = 1 << 6    # Dirty
PTE_PS   = 1 << 7    # Page Size (large page on PD/PDPT)
PTE_G    = 1 << 8    # Global
PTE_NX   = 1 << 63   # Execute disable

PHYS_ADDR_MASK = 0x000FFFFFFFFFF000  # bits [51:12]


def _decode_flags(entry):
    """Return a list of short flag strings for a PTE-like entry."""
    flags = []
    flags.append("P"   if entry & PTE_P   else "-")
    flags.append("RW"  if entry & PTE_RW  else "RO")
    flags.append("US"  if entry & PTE_US  else "S ")
    flags.append("A"   if entry & PTE_A   else "-")
    flags.append("D"   if entry & PTE_D   else "-")
    flags.append("PS"  if entry & PTE_PS  else "  ")
    flags.append("G"   if entry & PTE_G   else "-")
    flags.append("NX"  if entry & PTE_NX  else "X ")
    return flags


def _read_phys(session, phys_addr, size):
    """Read physical memory if the session supports it, else None."""
    if hasattr(session, "read_physical"):
        try:
            return session.read_physical(phys_addr, size)
        except Exception:
            return None
    return None


def cmd_kdpte(debugger, args):
    """Walk the page tables for a virtual address.

    Usage: kdpte <virtual_addr|module+offset>

    Reads CR3 from the current CPU, then walks PML4 → PDPT → PD → PT
    via physical memory reads.
    """
    from .kd_cmds import _get_session, _kd_eval_expr

    session = _get_session()
    if session is None:
        return None
    if not session.stopped:
        error("Target is running. Break first.")
        return None

    expr = args.strip()
    if not expr:
        error("Usage: kdpte <virtual address>")
        return None

    vaddr = _kd_eval_expr(expr, session)
    if vaddr is None:
        error(f"Cannot resolve: {expr}")
        return None

    # Read CR3 (GDB index 31 for x86_64 = cr3)
    cr3 = 0
    if hasattr(session, "_read_raw_register"):
        cr3 = session._read_raw_register(29)  # cr3 is index 29 in QEMU x86_64 sysreg layout
    if not cr3:
        error("Cannot read CR3 — page walk needs the directory base")
        return None

    if not hasattr(session, "read_physical"):
        warn("Physical memory reads not supported by this transport — "
             "page walk may be inaccurate (will fall back to virtual reads)")

    banner(f"PTE walk for {vaddr:#x}")
    console.print(Text(f"  CR3 = {cr3:#018x}", style="bright_black"))
    console.print()

    # Decode the 4 indices
    pml4_idx = (vaddr >> 39) & 0x1FF
    pdpt_idx = (vaddr >> 30) & 0x1FF
    pd_idx   = (vaddr >> 21) & 0x1FF
    pt_idx   = (vaddr >> 12) & 0x1FF
    page_off = vaddr & 0xFFF

    console.print(Text(
        f"  PML4[{pml4_idx:#x}]  PDPT[{pdpt_idx:#x}]  "
        f"PD[{pd_idx:#x}]  PT[{pt_idx:#x}]  off={page_off:#x}",
        style="bright_black"
    ))
    console.print()

    tbl = Table(show_header=True, border_style="cyan", header_style="bold bright_white")
    tbl.add_column("Level", style="bold bright_yellow")
    tbl.add_column("Index", style="bright_yellow", justify="right")
    tbl.add_column("Phys entry addr", style="bright_cyan")
    tbl.add_column("Entry value", style="bright_white")
    tbl.add_column("Flags", style="bright_green")
    tbl.add_column("Next phys", style="bright_magenta")

    levels = [
        ("PML4E", pml4_idx),
        ("PDPTE", pdpt_idx),
        ("PDE",   pd_idx),
        ("PTE",   pt_idx),
    ]

    table_phys = cr3 & PHYS_ADDR_MASK
    final_phys = None
    large_page = False

    for level_name, idx in levels:
        entry_phys = table_phys + idx * 8
        entry_data = _read_phys(session, entry_phys, 8)
        if not entry_data or len(entry_data) < 8:
            tbl.add_row(level_name, f"{idx:#x}", f"{entry_phys:#x}",
                        "<read failed>", "", "")
            console.print(tbl)
            warn("Could not read physical memory — try a transport that exposes 'read_physical'")
            return None

        entry = struct.unpack_from("<Q", entry_data, 0)[0]
        flags = " ".join(_decode_flags(entry))
        next_phys = entry & PHYS_ADDR_MASK

        tbl.add_row(
            level_name,
            f"{idx:#x}",
            f"{entry_phys:#x}",
            f"{entry:#018x}",
            flags,
            f"{next_phys:#x}",
        )

        if not (entry & PTE_P):
            console.print(tbl)
            warn(f"{level_name} not present — translation stops here")
            return None

        # Large page: PS=1 on PDPTE (1 GB) or PDE (2 MB)
        if (entry & PTE_PS) and level_name in ("PDPTE", "PDE"):
            large_page = True
            if level_name == "PDPTE":
                # 1 GB page: phys = next_phys | (vaddr & 0x3FFFFFFF)
                final_phys = (next_phys & 0xFFFFC0000000) | (vaddr & 0x3FFFFFFF)
            else:
                # 2 MB page: phys = next_phys | (vaddr & 0x1FFFFF)
                final_phys = (next_phys & 0xFFFFFFE00000) | (vaddr & 0x1FFFFF)
            break

        table_phys = next_phys

    if final_phys is None:
        # Reached PTE level
        final_phys = table_phys + page_off

    console.print(tbl)
    console.print()
    page_kind = "1 GB page" if (large_page and level_name == "PDPTE") else \
                "2 MB page" if large_page else "4 KB page"
    success_text = Text()
    success_text.append("  → Physical: ", style="bold")
    success_text.append(f"{final_phys:#x}", style="bold bright_green")
    success_text.append(f"   ({page_kind})", style="bright_black")
    console.print(success_text)
    return None
