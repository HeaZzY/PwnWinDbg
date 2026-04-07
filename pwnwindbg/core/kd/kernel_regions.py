"""Classify a kernel virtual address into a known region.

Used by `kdxinfo` to label addresses with their region (module, KUSER_SHARED_DATA,
PML4 self-reference, hyperspace, system PTEs, etc.).
"""

# Well-known fixed Windows kernel addresses (x64)
KUSER_SHARED_DATA       = 0xFFFFF78000000000
KUSER_SHARED_DATA_END   = 0xFFFFF78000001000

# PML4 self-reference (recursive page table mapping). The slot index varies
# per build (commonly 0x1ED on Win10, randomized on Win11), so we use a range.
PML4_SELF_RANGE_LO      = 0xFFFFF68000000000
PML4_SELF_RANGE_HI      = 0xFFFFF70000000000

# Canonical kernel half on x64 (sign-extended above 0x0000_7FFF_FFFF_FFFF)
KERNEL_CANONICAL_LO     = 0xFFFF800000000000


def classify(addr, modules=None):
    """Return a (region_name, detail) tuple for the given address.

    `modules` is the cached kernel module list (from kd_cmds._cached_modules).
    """
    # Modules
    if modules:
        for dll_base, size, ep, bname, fpath in modules:
            if dll_base <= addr < dll_base + size:
                return ("module", f"{bname}+{addr - dll_base:#x}  (size {size:#x})")

    # KUSER_SHARED_DATA
    if KUSER_SHARED_DATA <= addr < KUSER_SHARED_DATA_END:
        return ("KUSER_SHARED_DATA", f"offset {addr - KUSER_SHARED_DATA:#x}")

    # PML4 self-mapping (page table virtual mapping)
    if PML4_SELF_RANGE_LO <= addr < PML4_SELF_RANGE_HI:
        return ("PML4 self-map", "page table window — interpret as PTE/PDE/PDPTE/PML4E")

    # User-mode canonical
    if addr < 0x0000800000000000:
        return ("user", "user-mode canonical address")

    # Kernel canonical, otherwise
    if addr >= KERNEL_CANONICAL_LO:
        # Try to identify common kernel address space ranges (heuristic)
        if 0xFFFFF80000000000 <= addr < 0xFFFFF90000000000:
            return ("kernel", "system / kernel mode (typical ntoskrnl/HAL/drivers)")
        if 0xFFFFF90000000000 <= addr < 0xFFFFFA0000000000:
            return ("session", "session space (win32k.sys etc.)")
        if 0xFFFFFA0000000000 <= addr < 0xFFFFFB0000000000:
            return ("PFN db", "PFN database")
        return ("kernel", "kernel canonical address")

    # Non-canonical (between user and kernel halves)
    return ("invalid", "non-canonical address (would #GP on access)")
