"""VAD (Virtual Address Descriptor) tree walker for kernel debug sessions.

Commands:
    kdvad <pid|name>          — list every VAD of a process
    kdvad <pid|name> -x       — only show executable mappings
    kdvad <pid|name> -w       — only show writable mappings

Background — VAD layout
=======================
Each Windows process owns a userland address space described by an
*RTL_AVL_TREE* of `_MMVAD_SHORT` / `_MMVAD` nodes, rooted at
`EPROCESS.VadRoot`. Each node covers a contiguous range of virtual pages
and carries protection / type / private-vs-mapped flags.

    _RTL_AVL_TREE { _RTL_BALANCED_NODE *Root; }   // +0x00 → root MMVAD_SHORT

    _RTL_BALANCED_NODE {
        _RTL_BALANCED_NODE *Children[2];   // +0x00 Left, +0x08 Right
        ULONG_PTR ParentValue;             // +0x10 (low 3 bits = balance)
    };

    _MMVAD_SHORT {
        _RTL_BALANCED_NODE VadNode;        // +0x00 (24 bytes)
        ULONG  StartingVpn;                // +0x18  (low 32 bits of start VPN)
        ULONG  EndingVpn;                  // +0x1C  (low 32 bits of end   VPN)
        UCHAR  StartingVpnHigh;            // +0x20  (high 8 bits)
        UCHAR  EndingVpnHigh;              // +0x21
        UCHAR  CommitChargeHigh;           // +0x22
        UCHAR  SpareNT64VadUChar;          // +0x23
        LONG   ReferenceCount;             // +0x24
        EX_PUSH_LOCK PushLock;             // +0x28
        ULONG  LongFlags;                  // +0x30  (MMVAD_FLAGS — type/prot/private)
        ULONG  LongFlags1;                 // +0x34
        PVOID  EventList;                  // +0x38
    };  // sizeof = 0x40

The address range described by the node is:
    [StartingVpn << 12, ((EndingVpn + 1) << 12) - 1]

`MMVAD_FLAGS` packs (in `LongFlags`):
    bits 0..2  → VadType
    bits 3..7  → 5-bit Protection index (see _PROT_NAMES table)
    bit  10    → PrivateMemory (1 = MMVAD_SHORT only; 0 = mapped section)
"""

import struct

from ..core.kd.ps_walker import find_process
from ..display.formatters import (
    info, error, warn, console, banner,
)
from .kd_ps_cmds import _get_session_and_system

from rich.table import Table


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# EPROCESS.VadRoot offset varies wildly between Windows builds:
#   Win10 1809:        0x628
#   Win10 19H1/19H2:   0x648
#   Win10 21H1+:       0x7d8
#   Win11:             0x7d8 (also moves around in newer builds)
#
# No exported nt! function leaks this offset directly, so we discover it
# the same way `discover_thread_list_entry_offset` finds ETHREAD layouts:
# scan the EPROCESS for an 8-byte qword that is a plausible kernel pointer
# AND, when treated as an MMVAD_SHORT, has children that round-trip back to
# the parent. Cached per session via `_VAD_ROOT_OFFSET_CACHE`.
_VAD_ROOT_SCAN_LO = 0x400
_VAD_ROOT_SCAN_HI = 0x900
_VAD_ROOT_OFFSET_CACHE = None  # set on first successful discovery

# Kernel half of the canonical x64 address space — anything below this is
# considered an invalid/corrupted node pointer and aborts traversal.
_KERNEL_MIN = 0xFFFF800000000000

# Hard cap on the number of nodes a single walk may visit. Real processes
# rarely exceed a few thousand VADs; this stops a corrupted tree from hanging
# the debugger.
_MAX_NODES = 10000


def _looks_like_vad_node(session, node_addr):
    """Cheap structural check: does `node_addr` look like an MMVAD_SHORT?

    A real VAD node has:
      - both Children pointers either NULL or kernel pointers
      - StartingVpn <= EndingVpn
      - At least one of the children, if non-null, has a ParentValue (low
        bits masked) that points back to `node_addr`.
    """
    blob = session.read_virtual(node_addr, 0x40)
    if not blob or len(blob) < 0x40:
        return False
    left  = struct.unpack_from("<Q", blob, 0x00)[0]
    right = struct.unpack_from("<Q", blob, 0x08)[0]
    parent_value = struct.unpack_from("<Q", blob, 0x10)[0]
    s_vpn = struct.unpack_from("<I", blob, 0x18)[0]
    e_vpn = struct.unpack_from("<I", blob, 0x1C)[0]

    # Children must be NULL or kernel
    if left and left < _KERNEL_MIN:
        return False
    if right and right < _KERNEL_MIN:
        return False
    # Parent (after masking balance bits) must be NULL (we are the root!)
    # OR a kernel pointer.
    parent = parent_value & ~0x7
    if parent and parent < _KERNEL_MIN:
        return False
    # VPN range sanity — VPNs are 36-bit values, very rarely zero, and
    # StartingVpn must not exceed EndingVpn.
    if s_vpn > e_vpn:
        return False
    if s_vpn == 0 and e_vpn == 0:
        return False
    # If we have a left child, recurse one level: the child's parent
    # pointer should map back to us.
    if left:
        cblob = session.read_virtual(left + 0x10, 8)
        if cblob and len(cblob) >= 8:
            cparent = struct.unpack_from("<Q", cblob, 0)[0] & ~0x7
            if cparent and cparent != node_addr:
                return False
    if right:
        cblob = session.read_virtual(right + 0x10, 8)
        if cblob and len(cblob) >= 8:
            cparent = struct.unpack_from("<Q", cblob, 0)[0] & ~0x7
            if cparent and cparent != node_addr:
                return False
    return True


def _discover_vad_root_offset(session, eproc):
    """Find EPROCESS.VadRoot by scanning the eproc body for a qword whose
    target structurally matches an MMVAD_SHORT root.

    Caches the discovered offset globally so subsequent kdvad invocations
    don't re-scan.
    """
    global _VAD_ROOT_OFFSET_CACHE
    if _VAD_ROOT_OFFSET_CACHE is not None:
        return _VAD_ROOT_OFFSET_CACHE

    # Bulk-read the EPROCESS region we want to scan, in one shot.
    region = session.read_virtual(eproc + _VAD_ROOT_SCAN_LO,
                                  _VAD_ROOT_SCAN_HI - _VAD_ROOT_SCAN_LO)
    if not region:
        return None

    for off in range(0, len(region) - 8, 8):
        candidate = struct.unpack_from("<Q", region, off)[0]
        if candidate < _KERNEL_MIN:
            continue
        if _looks_like_vad_node(session, candidate):
            discovered = _VAD_ROOT_SCAN_LO + off
            _VAD_ROOT_OFFSET_CACHE = discovered
            return discovered
    return None


def invalidate_vad_root_cache():
    """Clear the cached VadRoot offset (called on disconnect)."""
    global _VAD_ROOT_OFFSET_CACHE
    _VAD_ROOT_OFFSET_CACHE = None


_PROT_NAMES = {
    0:  "NOACCESS",
    1:  "READONLY",
    2:  "EXECUTE",
    3:  "EXECUTE_READ",
    4:  "READWRITE",
    5:  "WRITECOPY",
    6:  "EXECUTE_READWRITE",
    7:  "EXECUTE_WRITECOPY",
    8:  "NOACCESS",
    9:  "GUARD | READONLY",
    10: "GUARD | EXECUTE",
    11: "GUARD | EXECUTE_READ",
    12: "GUARD | READWRITE",
    13: "GUARD | WRITECOPY",
    14: "GUARD | EXECUTE_READWRITE",
    15: "GUARD | EXECUTE_WRITECOPY",
    16: "NOCACHE | NOACCESS",
    17: "NOCACHE | READONLY",
    18: "NOCACHE | EXECUTE",
    19: "NOCACHE | EXECUTE_READ",
    20: "NOCACHE | READWRITE",
    21: "NOCACHE | WRITECOPY",
    22: "NOCACHE | EXECUTE_READWRITE",
    23: "NOCACHE | EXECUTE_WRITECOPY",
    24: "WRITECOMBINE | NOACCESS",
    25: "WRITECOMBINE | READONLY",
    26: "WRITECOMBINE | EXECUTE",
    27: "WRITECOMBINE | EXECUTE_READ",
    28: "WRITECOMBINE | READWRITE",
    29: "WRITECOMBINE | WRITECOPY",
    30: "WRITECOMBINE | EXECUTE_READWRITE",
    31: "WRITECOMBINE | EXECUTE_WRITECOPY",
}


_VAD_TYPES = {
    0: "None",
    1: "DevPhys",
    2: "Image",
    3: "Awe",
    4: "WriteWatch",
    5: "LargePage",
    6: "Rotate",
    7: "LargePageSec",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_size(n):
    """Pretty-print a byte count as B / K / M / G / T."""
    f = float(n)
    for unit in ("B", "K", "M", "G"):
        if f < 1024:
            return f"{f:.0f}{unit}"
        f /= 1024
    return f"{f:.0f}T"


def _walk_vad_tree(session, root_node, max_nodes=_MAX_NODES):
    """Iterative in-order traversal of an RTL_AVL_TREE of MMVAD_SHORT nodes.

    Yields `(node_addr, blob)` where `blob` is the raw 0x40-byte MMVAD_SHORT.
    Safe against corrupted trees: bounded depth, visited-set cycle detection,
    and a kernel-address sanity check on every child pointer.
    """
    if not root_node or root_node < _KERNEL_MIN:
        return

    stack = []
    node = root_node
    visited = set()
    count = 0

    while (node or stack) and count < max_nodes:
        # Descend left as far as possible.
        while node:
            if node in visited:
                node = None
                break
            if node < _KERNEL_MIN:
                node = None
                break
            visited.add(node)
            stack.append(node)
            data = session.read_virtual(node, 8)
            if not data or len(data) < 8:
                node = None
                break
            left = struct.unpack_from("<Q", data, 0)[0]
            if left and left < _KERNEL_MIN:
                # Bogus pointer — stop descending here.
                node = None
                break
            node = left

        if not stack:
            break

        node = stack.pop()
        blob = session.read_virtual(node, 0x40)
        if blob and len(blob) >= 0x40:
            yield node, blob
            count += 1

        # Move to right subtree.
        rdata = session.read_virtual(node + 8, 8)
        if rdata and len(rdata) >= 8:
            right = struct.unpack_from("<Q", rdata, 0)[0]
            if right and right < _KERNEL_MIN:
                node = None
            else:
                node = right
        else:
            node = None


def _parse_vad(node_addr, blob):
    """Decode a raw MMVAD_SHORT blob into a dict of useful fields."""
    starting_vpn  = struct.unpack_from("<I", blob, 0x18)[0]
    ending_vpn    = struct.unpack_from("<I", blob, 0x1C)[0]
    starting_high = blob[0x20]
    ending_high   = blob[0x21]
    long_flags    = struct.unpack_from("<I", blob, 0x30)[0]

    start_vpn_full = (starting_high << 32) | starting_vpn
    end_vpn_full   = (ending_high   << 32) | ending_vpn

    start_addr = start_vpn_full << 12
    end_addr   = ((end_vpn_full + 1) << 12) - 1

    vad_type    = long_flags & 0x7
    protection  = (long_flags >> 3) & 0x1F
    private_mem = (long_flags >> 10) & 0x1

    return {
        "node": node_addr,
        "start": start_addr,
        "end": end_addr,
        "size": end_addr - start_addr + 1,
        "vad_type": vad_type,
        "protection": protection,
        "private": bool(private_mem),
        "long_flags": long_flags,
    }


def _color_protection(prot_name):
    """Wrap a protection string in a Rich color tag based on RWX semantics."""
    name = prot_name
    has_exec  = "EXECUTE" in name
    has_write = ("WRITE" in name) or ("READWRITE" in name)
    if has_exec and has_write:
        return f"[red]{name}[/]"
    if has_exec:
        return f"[bright_red]{name}[/]"
    if has_write:
        return f"[blue]{name}[/]"
    if "NOACCESS" in name:
        return f"[bright_black]{name}[/]"
    return f"[green]{name}[/]"


# ---------------------------------------------------------------------------
# kdvad — main entry point
# ---------------------------------------------------------------------------

def cmd_kdvad(debugger, args):
    """Walk the VAD tree of a process and list its userland mappings.

    Usage:
        kdvad <pid|name>          — list all VADs
        kdvad <pid|name> -x       — only executable mappings
        kdvad <pid|name> -w       — only writable mappings
    """
    session, sys_eproc = _get_session_and_system()
    if session is None:
        return None

    parts = args.strip().split()
    if not parts:
        error("Usage: kdvad <pid|name> [-x|-w]")
        return None

    target = parts[0]
    only_exec = False
    only_write = False
    for opt in parts[1:]:
        if opt == "-x":
            only_exec = True
        elif opt == "-w":
            only_write = True
        else:
            error(f"Unknown option: {opt}  (expected -x or -w)")
            return None

    proc = None
    try:
        proc = find_process(session, sys_eproc, pid=int(target, 0))
    except ValueError:
        proc = find_process(session, sys_eproc, name=target)
    if proc is None:
        error(f"Process not found: {target}")
        return None

    # Discover VadRoot offset against this build's EPROCESS, then read the
    # AVL root pointer from the target process's EPROCESS at that offset.
    # We discover against the System process (always alive, well-populated).
    vad_root_offset = _discover_vad_root_offset(session, sys_eproc)
    if vad_root_offset is None:
        error("Could not auto-discover EPROCESS.VadRoot offset on this build")
        return None
    info(f"EPROCESS.VadRoot offset (dynamic): {vad_root_offset:#x}")

    vad_root_addr = proc["eproc"] + vad_root_offset
    rdata = session.read_virtual(vad_root_addr, 8)
    if not rdata or len(rdata) < 8:
        error(f"Cannot read VadRoot at {vad_root_addr:#x}")
        return None
    root_node = struct.unpack_from("<Q", rdata, 0)[0]

    if not root_node or root_node < _KERNEL_MIN:
        error(f"VadRoot looks bogus: {root_node:#x} "
              f"(expected kernel pointer ≥ {_KERNEL_MIN:#x})")
        return None

    banner(f"VAD tree for {proc['name']} (PID {proc['pid']})")
    info(f"EPROCESS: {proc['eproc']:#x}   "
         f"VadRoot@{vad_root_addr:#x} → {root_node:#x}")

    tbl = Table(show_header=True, border_style="cyan", header_style="bold bright_white")
    tbl.add_column("Start",      style="bright_yellow")
    tbl.add_column("End",        style="bright_yellow")
    tbl.add_column("Size",       style="bright_white", justify="right")
    tbl.add_column("Type",       style="bright_cyan")
    tbl.add_column("Protection", style="bright_green")
    tbl.add_column("Priv",       style="bright_black")
    tbl.add_column("Node",       style="bright_black")

    total_nodes = 0
    shown_nodes = 0
    total_committed = 0
    exec_count = 0
    write_count = 0

    for node_addr, blob in _walk_vad_tree(session, root_node):
        v = _parse_vad(node_addr, blob)
        total_nodes += 1
        total_committed += v["size"]

        prot_name = _PROT_NAMES.get(v["protection"], f"?{v['protection']}")
        type_name = _VAD_TYPES.get(v["vad_type"], f"?{v['vad_type']}")

        is_exec  = "EXECUTE" in prot_name
        is_write = ("WRITE" in prot_name) or ("READWRITE" in prot_name)
        if is_exec:
            exec_count += 1
        if is_write:
            write_count += 1

        if only_exec and not is_exec:
            continue
        if only_write and not is_write:
            continue

        tbl.add_row(
            f"{v['start']:#018x}",
            f"{v['end']:#018x}",
            _fmt_size(v["size"]),
            type_name,
            _color_protection(prot_name),
            "P" if v["private"] else "M",
            f"{v['node']:#x}",
        )
        shown_nodes += 1

    if total_nodes == 0:
        warn("VAD tree is empty (or unreadable).")
        return None

    console.print(tbl)

    if total_nodes >= _MAX_NODES:
        warn(f"Reached max-nodes cap ({_MAX_NODES}); tree may be larger.")

    summary = (
        f"VAD nodes: {total_nodes}"
        f"  shown: {shown_nodes}"
        f"  total committed: {_fmt_size(total_committed)}"
        f"  exec regions: {exec_count}"
        f"  writable: {write_count}"
    )
    info(summary)
    return None
