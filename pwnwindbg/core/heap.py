"""Windows heap analysis engine.

Reads the target process PEB to enumerate heaps, then walks NT heap segments
using the documented (public-symbol-derived) _HEAP / _HEAP_SEGMENT layout.

Supports:
- NT Heap (HeapAlloc/HeapFree via ntdll.dll) — full chunk walking with
  encoded HEAP_ENTRY decode (XOR with _HEAP.Encoding)
- Segment Heap (Win10+) — detection plus large-allocation walking via the
  RTL_RB_TREE rooted in _SEGMENT_HEAP.LargeAllocMetadata. Backend / VS / LFH
  small chunk walking is *not* implemented because those allocators rely on
  per-context XOR-encoded headers whose offsets shift across builds. We
  expose the high-level _SEGMENT_HEAP fields instead.

Linux-style malloc chunks: msvcrt/ucrt malloc on Windows is a thin wrapper
over HeapAlloc on the process default heap, so the chunks you allocate with
malloc() show up as NT heap chunks here.
"""

import ctypes
import struct
from enum import Enum
from typing import List, Optional
from dataclasses import dataclass

from .memory import read_memory_safe, virtual_query
from ..utils.constants import (
    ntdll,
    PROCESS_BASIC_INFORMATION,
    ProcessBasicInformation,
)


# ---- x64 PEB offsets (Win10/11) ----
PEB_PROCESS_HEAP_OFFSET = 0x30      # PEB.ProcessHeap (default heap)
PEB_NUMBER_OF_HEAPS_OFFSET = 0xE8   # PEB.NumberOfHeaps (ULONG)
PEB_PROCESS_HEAPS_OFFSET = 0xF0     # PEB.ProcessHeaps (PVOID*)

# ---- _HEAP / _HEAP_SEGMENT signatures ----
NT_HEAP_SIGNATURE = 0xFFEEFFEE       # _HEAP_SEGMENT.SegmentSignature
SEGMENT_HEAP_SIGNATURE = 0xDDEEDDEE  # _SEGMENT_HEAP.Signature

# ---- _SEGMENT_HEAP layout (Win10/11 x64, common offsets) ----
# Public symbol layout from a recent Win11 ntdll PDB. Stable across most
# 19041+ builds, but may shift slightly on earlier 1809-era builds.
#   +0x000 Signature                ULONG  (0xddeeddee)
#   +0x004 GlobalFlags              ULONG
#   +0x008 Interceptor              ULONG
#   +0x00c ProcessHeapListIndex     USHORT
#   +0x00e GlobalLockCount          USHORT
#   +0x010 GlobalLockOwner          ULONG
#   +0x018 LargeMetadataLock        RTL_SRWLOCK
#   +0x020 LargeAllocMetadata       RTL_RB_TREE     (Root, Min)
#   +0x030 LargeReservedPages       SIZE_T
#   +0x038 LargeCommittedPages      SIZE_T
SEGHEAP_SIGNATURE_OFF        = 0x000
SEGHEAP_GLOBAL_FLAGS_OFF     = 0x004
SEGHEAP_INTERCEPTOR_OFF      = 0x008
SEGHEAP_PROCESS_INDEX_OFF    = 0x00c
SEGHEAP_LARGE_RB_ROOT_OFF    = 0x020   # RTL_RB_TREE.Root
SEGHEAP_LARGE_RB_MIN_OFF     = 0x028   # RTL_RB_TREE.Min
SEGHEAP_LARGE_RESERVED_OFF   = 0x030
SEGHEAP_LARGE_COMMITTED_OFF  = 0x038

# ---- _HEAP_LARGE_ALLOC_DATA layout (x64) ----
# Each large allocation has a metadata record reachable through the RB tree.
#   +0x000 TreeNode             RTL_BALANCED_NODE  (Left/Right/ParentValue)
#   +0x018 VirtualAddress       PVOID  (top bits encode AllocatedPages)
#   +0x020 UnusedBytes          USHORT
#   +0x022 ExtraPresent         bit
#   +0x024 Spare                : 11
#   +0x026 GuardPageCount       : 1
#   +0x028 AllocatedPages       SIZE_T   (in 0x1000 units; alt path)
LARGE_ALLOC_TREE_NODE_OFF    = 0x000
LARGE_ALLOC_VA_OFF           = 0x018
LARGE_ALLOC_UNUSED_BYTES_OFF = 0x020
LARGE_ALLOC_PAGES_OFF        = 0x028

# ---- _HEAP layout (Win10/11 x64, validated against live data) ----
# _HEAP starts with a _HEAP_SEGMENT (size 0x70), then:
#   +0x070 Flags            ULONG
#   +0x074 ForceFlags       ULONG
#   +0x078 Compatibility    ULONG
#   +0x07C EncodeFlagMask   ULONG  (must be 0x100000 for encoding to be active)
#   +0x080 Encoding         _HEAP_ENTRY (16 bytes)
#   +0x098 Signature        ULONG  (= 0xeeffeeff)
#
# The XOR encoding key is the SECOND 8 bytes of _HEAP.Encoding (offsets 0x88..0x8F),
# which corresponds to the part of every _HEAP_ENTRY that contains Size/Flags/etc.
HEAP_FLAGS_X64 = 0x70
HEAP_FORCE_FLAGS_X64 = 0x74
HEAP_ENCODE_FLAG_MASK_X64 = 0x7C
HEAP_ENCODING_OFFSET = 0x80          # _HEAP.Encoding (HEAP_ENTRY, 16B)
HEAP_ENCODING_KEY_OFFSET = 0x88      # Bytes 8..15 of Encoding — the actual XOR key
HEAP_SIGNATURE_X64 = 0x98            # _HEAP.Signature

# ---- _HEAP_SEGMENT layout (x64) ----
SEG_SIGNATURE = 0x10
SEG_FLAGS = 0x14
SEG_LIST_ENTRY = 0x18           # LIST_ENTRY linking segments together
SEG_HEAP = 0x28                  # back pointer to _HEAP
SEG_BASE_ADDRESS = 0x30
SEG_NUMBER_OF_PAGES = 0x38
SEG_FIRST_ENTRY = 0x40           # first chunk in segment
SEG_LAST_VALID_ENTRY = 0x48      # end of valid chunk range
SEG_NUMBER_OF_UNCOMMITTED_PAGES = 0x50

# ---- _HEAP_ENTRY layout (16 bytes on x64) ----
# +0x000 PreviousBlockPrivateData : Ptr64 Void   (NOT encoded)
# +0x008 Size                    : USHORT        ┐
# +0x00a Flags                   : UCHAR         │
# +0x00b SmallTagIndex           : UCHAR         │ XORed with the
# +0x00c PreviousSize            : USHORT        │ 8-byte encoding key
# +0x00e SegmentOffset           : UCHAR         │
# +0x00f UnusedBytes             : UCHAR         ┘
#
# Flags bits:
#   0x01 BUSY      0x02 EXTRA_PRESENT      0x04 FILL_PATTERN
#   0x08 VIRTUAL   0x10 LAST_ENTRY         0x20 FIRST_ENTRY
HEAP_GRANULARITY = 16
HEAP_ENTRY_SIZE = 16
HEAP_ENTRY_HEADER_OFFSET = 8  # offset within the entry where the encoded fields live

HEAP_FLAG_BUSY = 0x01
HEAP_FLAG_EXTRA_PRESENT = 0x02
HEAP_FLAG_FILL_PATTERN = 0x04
HEAP_FLAG_VIRTUAL_ALLOC = 0x08
HEAP_FLAG_LAST_ENTRY = 0x10
HEAP_FLAG_FIRST_ENTRY = 0x20


class HeapType(Enum):
    UNKNOWN = 0
    NT_HEAP = 1
    SEGMENT = 2
    LFH = 3


class ChunkState(Enum):
    FREE = 0
    BUSY = 1
    CORRUPTED = 2


@dataclass
class HeapChunk:
    address: int          # address of user data (after header)
    size: int             # full chunk size including header
    user_size: int        # usable user size
    state: ChunkState
    heap_type: HeapType
    flags: int = 0
    data: Optional[bytes] = None

    @property
    def end_address(self) -> int:
        return self.address - HEAP_ENTRY_SIZE + self.size

    @property
    def data_preview(self) -> str:
        if not self.data:
            return "." * 16 if self.state == ChunkState.FREE else "<?>"
        try:
            preview = self.data[:16].decode('latin-1', errors='replace')
            preview = ''.join(c if c.isprintable() and c != '\n' else '.' for c in preview)
            return preview.ljust(16, '.')[:16]
        except Exception:
            return ' '.join(f'{b:02x}' for b in self.data[:8])


@dataclass
class HeapInfo:
    address: int
    size: int
    heap_type: HeapType
    flags: int = 0
    name: str = ""
    is_default: bool = False

    @property
    def lfh_enabled(self) -> bool:
        return self.heap_type == HeapType.NT_HEAP and (self.flags & 0x2) != 0


@dataclass
class SegmentHeapInfo:
    """High-level fields read from a _SEGMENT_HEAP header."""
    address: int
    signature: int
    global_flags: int
    interceptor: int
    process_heap_list_index: int
    large_reserved_pages: int
    large_committed_pages: int
    large_alloc_count: int = 0
    large_allocs: list = None  # List[dict] populated by walk_segment_large_allocs

    def __post_init__(self):
        if self.large_allocs is None:
            self.large_allocs = []


class WindowsHeapAnalyzer:
    """Heap analyzer for the live target process."""

    def __init__(self, debugger):
        self.debugger = debugger
        self._heap_cache = {}
        self._chunk_cache = {}
        self._encoding_cache = {}  # heap_addr -> 8-byte XOR key

    # ---- low-level read helpers ----

    def _read(self, addr: int, size: int) -> Optional[bytes]:
        if not addr:
            return None
        return read_memory_safe(self.debugger.process_handle, addr, size)

    def _read_u32(self, addr: int) -> int:
        data = self._read(addr, 4)
        if not data or len(data) < 4:
            return 0
        return struct.unpack("<I", data)[0]

    def _read_u16(self, addr: int) -> int:
        data = self._read(addr, 2)
        if not data or len(data) < 2:
            return 0
        return struct.unpack("<H", data)[0]

    def _read_ptr(self, addr: int) -> int:
        data = self._read(addr, 8)
        if not data or len(data) < 8:
            return 0
        return struct.unpack("<Q", data)[0]

    # ---- PEB / heap discovery ----

    def _get_peb(self) -> Optional[int]:
        """Read PebBaseAddress via NtQueryInformationProcess."""
        if not self.debugger.process_handle:
            return None
        pbi = PROCESS_BASIC_INFORMATION()
        ret_len = ctypes.c_ulong(0)
        status = ntdll.NtQueryInformationProcess(
            self.debugger.process_handle,
            ProcessBasicInformation,
            ctypes.byref(pbi),
            ctypes.sizeof(pbi),
            ctypes.byref(ret_len),
        )
        if status != 0 or not pbi.PebBaseAddress:
            return None
        return pbi.PebBaseAddress

    def _get_process_heaps(self):
        """Return (default_heap, [all_heaps]) read from PEB.ProcessHeaps[]."""
        peb = self._get_peb()
        if not peb:
            return (0, [])

        default_heap = self._read_ptr(peb + PEB_PROCESS_HEAP_OFFSET)
        num_heaps = self._read_u32(peb + PEB_NUMBER_OF_HEAPS_OFFSET)
        if num_heaps == 0 or num_heaps > 1024:
            return (default_heap, [default_heap] if default_heap else [])

        heaps_array = self._read_ptr(peb + PEB_PROCESS_HEAPS_OFFSET)
        if not heaps_array:
            return (default_heap, [default_heap] if default_heap else [])

        heaps = []
        for i in range(num_heaps):
            h = self._read_ptr(heaps_array + i * 8)
            if h:
                heaps.append(h)
        return (default_heap, heaps)

    def detect_heaps(self) -> List[HeapInfo]:
        if not self.debugger.process_id:
            return []

        default_heap, heap_addrs = self._get_process_heaps()
        out = []
        for i, addr in enumerate(heap_addrs):
            info = self._analyze_heap(addr, i)
            if info:
                if addr == default_heap:
                    info.is_default = True
                    info.name += " (default)"
                out.append(info)
        return out

    def _analyze_heap(self, heap_addr: int, index: int = 0) -> Optional[HeapInfo]:
        if heap_addr in self._heap_cache:
            return self._heap_cache[heap_addr]

        # Detect via signature. NT heap puts SegmentSignature at +0x10.
        # Segment heap puts Signature at +0x08.
        sig_nt = self._read_u32(heap_addr + SEG_SIGNATURE)
        sig_seg = self._read_u32(heap_addr + 0x08)

        info = HeapInfo(
            address=heap_addr,
            size=0,
            heap_type=HeapType.UNKNOWN,
            name=f"Heap #{index}",
        )

        if sig_nt == NT_HEAP_SIGNATURE:
            info.heap_type = HeapType.NT_HEAP
            info.name = f"NT Heap #{index}"
            info.flags = self._read_u32(heap_addr + HEAP_FLAGS_X64)
        elif sig_seg == SEGMENT_HEAP_SIGNATURE:
            info.heap_type = HeapType.SEGMENT
            info.name = f"Segment Heap #{index}"

        # Region size from VirtualQueryEx
        try:
            mbi = virtual_query(self.debugger.process_handle, heap_addr)
            if mbi:
                info.size = mbi.RegionSize
        except Exception:
            pass

        self._heap_cache[heap_addr] = info
        return info

    # ---- chunk walking ----

    def _get_encoding_key(self, heap_addr: int) -> bytes:
        """Read the 8-byte XOR key from _HEAP.Encoding[8..15].

        On Win10/11 x64, _HEAP.Encoding is at offset 0x80 and is itself a
        _HEAP_ENTRY (16 bytes). Only its second half (bytes 8..15) is used to
        XOR the matching bytes of every chunk's _HEAP_ENTRY header.
        """
        if heap_addr in self._encoding_cache:
            return self._encoding_cache[heap_addr]
        encode_flag = self._read_u32(heap_addr + HEAP_ENCODE_FLAG_MASK_X64)
        if encode_flag != 0x100000:
            key = b"\x00" * 8
        else:
            key = self._read(heap_addr + HEAP_ENCODING_KEY_OFFSET, 8) or (b"\x00" * 8)
            if len(key) < 8:
                key = b"\x00" * 8
        self._encoding_cache[heap_addr] = key
        return key

    def _decode_entry(self, raw: bytes, key: bytes) -> bytes:
        """XOR-decode bytes 8..15 of a HEAP_ENTRY (the part that holds Size/Flags)."""
        if len(raw) < 16 or len(key) < 8:
            return raw
        decoded_tail = bytes(a ^ b for a, b in zip(raw[8:16], key[:8]))
        return raw[:8] + decoded_tail

    def _iter_segments(self, heap_addr: int):
        """Yield each _HEAP_SEGMENT address starting from the heap itself.

        The heap structure begins with a _HEAP_SEGMENT, and additional segments
        are linked via SegmentListEntry (LIST_ENTRY at +0x18). We follow .Flink
        until we cycle back to the head.
        """
        # The first segment is the heap itself
        yield heap_addr

        head = heap_addr + SEG_LIST_ENTRY
        flink = self._read_ptr(head)
        seen = {heap_addr}
        guard = 0
        while flink and flink != head and guard < 64:
            seg = flink - SEG_LIST_ENTRY
            if seg in seen:
                break
            seen.add(seg)
            # Sanity: confirm signature
            if self._read_u32(seg + SEG_SIGNATURE) != NT_HEAP_SIGNATURE:
                break
            yield seg
            flink = self._read_ptr(flink)
            guard += 1

    def get_chunks(self, heap_addr: int, max_chunks: int = 4096) -> List[HeapChunk]:
        if heap_addr in self._chunk_cache:
            return self._chunk_cache[heap_addr]

        info = self._analyze_heap(heap_addr)
        if not info:
            return []

        chunks: List[HeapChunk] = []
        if info.heap_type == HeapType.NT_HEAP:
            chunks = self._walk_nt_heap(heap_addr, max_chunks)
        elif info.heap_type == HeapType.SEGMENT:
            # Segment heap walking not implemented yet — return empty
            chunks = []

        self._chunk_cache[heap_addr] = chunks
        return chunks

    def _walk_nt_heap(self, heap_addr: int, max_chunks: int) -> List[HeapChunk]:
        key = self._get_encoding_key(heap_addr)
        chunks: List[HeapChunk] = []

        for seg in self._iter_segments(heap_addr):
            first_entry = self._read_ptr(seg + SEG_FIRST_ENTRY)
            last_valid = self._read_ptr(seg + SEG_LAST_VALID_ENTRY)
            if not first_entry or not last_valid or last_valid <= first_entry:
                continue

            cur = first_entry
            seg_guard = 0
            while cur < last_valid and len(chunks) < max_chunks and seg_guard < max_chunks:
                seg_guard += 1
                raw = self._read(cur, HEAP_ENTRY_SIZE)
                if not raw or len(raw) < HEAP_ENTRY_SIZE:
                    break
                decoded = self._decode_entry(raw, key)
                # Decoded fields live at offset 8..15 of the HEAP_ENTRY:
                #   +0x08 USHORT Size (in 16-byte units)
                #   +0x0a UCHAR  Flags
                #   +0x0b UCHAR  SmallTagIndex
                #   +0x0c USHORT PreviousSize
                #   +0x0e UCHAR  SegmentOffset
                #   +0x0f UCHAR  UnusedBytes
                size_units = struct.unpack_from("<H", decoded, HEAP_ENTRY_HEADER_OFFSET + 0)[0]
                flags = decoded[HEAP_ENTRY_HEADER_OFFSET + 2]
                unused = decoded[HEAP_ENTRY_HEADER_OFFSET + 7]

                if size_units == 0:
                    break

                chunk_size = size_units * HEAP_GRANULARITY
                if chunk_size < HEAP_ENTRY_SIZE or chunk_size > 0x10000000:
                    break

                user_addr = cur + HEAP_ENTRY_SIZE
                user_size = max(0, chunk_size - HEAP_ENTRY_SIZE - unused)

                state = ChunkState.BUSY if (flags & HEAP_FLAG_BUSY) else ChunkState.FREE

                # Read up to 64 bytes of user data for previews / search
                data = self._read(user_addr, min(user_size, 64)) if user_size > 0 else b""

                chunks.append(HeapChunk(
                    address=user_addr,
                    size=chunk_size,
                    user_size=user_size,
                    state=state,
                    heap_type=HeapType.NT_HEAP,
                    flags=flags,
                    data=data or b"",
                ))

                if flags & HEAP_FLAG_LAST_ENTRY:
                    break

                next_addr = cur + chunk_size
                if next_addr <= cur or next_addr >= last_valid:
                    break
                cur = next_addr

        return chunks

    # ---- search ----

    def find_chunks(self, **filters) -> List[HeapChunk]:
        out = []
        for heap in self.detect_heaps():
            for chunk in self.get_chunks(heap.address):
                if self._chunk_matches(chunk, **filters):
                    out.append(chunk)
        return out

    def _chunk_matches(self, chunk: HeapChunk, **f) -> bool:
        if 'size' in f and chunk.size != f['size']:
            return False
        if 'min_size' in f and chunk.size < f['min_size']:
            return False
        if 'max_size' in f and chunk.size > f['max_size']:
            return False
        if 'state' in f and chunk.state != f['state']:
            return False
        if 'heap_type' in f and chunk.heap_type != f['heap_type']:
            return False
        if 'contains' in f:
            needle = f['contains']
            if isinstance(needle, str):
                needle = needle.encode('latin-1', errors='replace')
            if not chunk.data or needle not in chunk.data:
                return False
        return True

    # ---- Segment Heap inspection ----

    def read_segment_heap(self, heap_addr: int) -> Optional[SegmentHeapInfo]:
        """Read the high-level _SEGMENT_HEAP header fields.

        Returns None if the address doesn't carry the segment-heap signature.
        Use walk_segment_large_allocs() to populate the .large_allocs list.
        """
        sig = self._read_u32(heap_addr + SEGHEAP_SIGNATURE_OFF)
        if sig != SEGMENT_HEAP_SIGNATURE:
            return None

        return SegmentHeapInfo(
            address=heap_addr,
            signature=sig,
            global_flags=self._read_u32(heap_addr + SEGHEAP_GLOBAL_FLAGS_OFF),
            interceptor=self._read_u32(heap_addr + SEGHEAP_INTERCEPTOR_OFF),
            process_heap_list_index=self._read_u16(heap_addr + SEGHEAP_PROCESS_INDEX_OFF),
            large_reserved_pages=self._read_ptr(heap_addr + SEGHEAP_LARGE_RESERVED_OFF),
            large_committed_pages=self._read_ptr(heap_addr + SEGHEAP_LARGE_COMMITTED_OFF),
        )

    def walk_segment_large_allocs(self, heap_addr: int, max_count: int = 4096):
        """Walk the LargeAllocMetadata RB tree of a segment heap.

        Returns a list of dicts {address, size, unused_bytes, metadata_addr}.
        Each entry corresponds to a single VirtualAlloc-backed allocation.

        The RB tree root is at SEGHEAP_LARGE_RB_ROOT_OFF; nodes are
        RTL_BALANCED_NODE { Left, Right, ParentValue }. Each node is the
        TreeNode field of a HEAP_LARGE_ALLOC_DATA at offset 0, so the metadata
        record address equals the node address.
        """
        root = self._read_ptr(heap_addr + SEGHEAP_LARGE_RB_ROOT_OFF)
        if not root:
            return []

        out = []
        # Iterative in-order traversal with a manual stack
        stack = []
        node = root
        seen = set()
        while (node or stack) and len(out) < max_count:
            while node and node not in seen:
                if len(seen) > max_count * 4:
                    return out
                seen.add(node)
                stack.append(node)
                left = self._read_ptr(node + 0x00)  # RTL_BALANCED_NODE.Left
                if not left or left in seen:
                    break
                node = left

            if not stack:
                break
            node = stack.pop()

            # node is the TreeNode field at offset 0 of HEAP_LARGE_ALLOC_DATA
            meta_addr = node
            va_raw = self._read_ptr(meta_addr + LARGE_ALLOC_VA_OFF)
            unused = self._read_u16(meta_addr + LARGE_ALLOC_UNUSED_BYTES_OFF)
            pages = self._read_ptr(meta_addr + LARGE_ALLOC_PAGES_OFF)

            # The bottom 12 bits of VirtualAddress can hold flags; mask to page
            user_va = va_raw & ~0xFFF
            total_size = pages * 0x1000 if pages else 0
            user_size = max(0, total_size - unused) if total_size else 0

            if user_va and total_size and total_size < (1 << 40):
                out.append({
                    "address": user_va,
                    "size": total_size,
                    "user_size": user_size,
                    "unused_bytes": unused,
                    "metadata_addr": meta_addr,
                })

            right = self._read_ptr(node + 0x08)  # RTL_BALANCED_NODE.Right
            node = right if right and right not in seen else None

        return out

    def invalidate(self):
        self._heap_cache.clear()
        self._chunk_cache.clear()
        self._encoding_cache.clear()
