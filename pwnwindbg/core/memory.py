"""Memory read/write operations and VirtualQueryEx wrappers."""

import ctypes
from ctypes import c_ubyte, c_size_t, sizeof, create_string_buffer
from ..utils.constants import (
    kernel32, MEMORY_BASIC_INFORMATION, HANDLE, LPVOID, SIZE_T,
    MEM_COMMIT, MEM_FREE, MEM_RESERVE, PVOID,
)
import struct


class MemoryError(Exception):
    """Raised on memory operation failure."""
    pass


def read_memory(process_handle, address, size):
    """Read `size` bytes from `address` in the target process. Returns bytes."""
    buf = create_string_buffer(size)
    bytes_read = c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        buf,
        size,
        ctypes.byref(bytes_read),
    )
    if not ok:
        raise MemoryError(f"ReadProcessMemory failed at {address:#x} (size={size}, err={ctypes.GetLastError()})")
    return buf.raw[:bytes_read.value]


def read_memory_safe(process_handle, address, size):
    """Like read_memory but returns None on failure instead of raising."""
    try:
        return read_memory(process_handle, address, size)
    except MemoryError:
        return None


def write_memory(process_handle, address, data):
    """Write `data` bytes to `address` in the target process."""
    buf = ctypes.create_string_buffer(data)
    bytes_written = c_size_t(0)
    ok = kernel32.WriteProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        buf,
        len(data),
        ctypes.byref(bytes_written),
    )
    if not ok:
        raise MemoryError(f"WriteProcessMemory failed at {address:#x} (err={ctypes.GetLastError()})")
    kernel32.FlushInstructionCache(process_handle, ctypes.c_void_p(address), len(data))
    return bytes_written.value


def read_ptr(process_handle, address, ptr_size=None):
    """Read a pointer-sized value at `address`."""
    if ptr_size is None:
        ptr_size = 4  # default to 32-bit, caller should pass correct size
    data = read_memory_safe(process_handle, address, ptr_size)
    if data is None:
        return None
    if ptr_size == 8:
        return struct.unpack("<Q", data)[0]
    else:
        return struct.unpack("<I", data)[0]


def read_qword(process_handle, address):
    """Read a QWORD (8 bytes) at address."""
    data = read_memory_safe(process_handle, address, 8)
    if data is None:
        return None
    return struct.unpack("<Q", data)[0]


def read_dword(process_handle, address):
    """Read a DWORD (4 bytes) at address."""
    data = read_memory_safe(process_handle, address, 4)
    if data is None:
        return None
    return struct.unpack("<I", data)[0]


def read_word(process_handle, address):
    """Read a WORD (2 bytes) at address."""
    data = read_memory_safe(process_handle, address, 2)
    if data is None:
        return None
    return struct.unpack("<H", data)[0]


def read_byte(process_handle, address):
    """Read a single byte at address."""
    data = read_memory_safe(process_handle, address, 1)
    if data is None:
        return None
    return data[0]


def read_string(process_handle, address, max_len=256, encoding="utf-8"):
    """Read a null-terminated string at address."""
    data = read_memory_safe(process_handle, address, max_len)
    if data is None:
        return None
    # Find null terminator
    idx = data.find(b'\x00')
    if idx >= 0:
        data = data[:idx]
    try:
        return data.decode(encoding, errors="replace")
    except Exception:
        return data.hex()


def read_wstring(process_handle, address, max_len=512):
    """Read a null-terminated wide string at address."""
    data = read_memory_safe(process_handle, address, max_len)
    if data is None:
        return None
    # Find double-null (wide null)
    for i in range(0, len(data) - 1, 2):
        if data[i] == 0 and data[i+1] == 0:
            data = data[:i]
            break
    try:
        return data.decode("utf-16-le", errors="replace")
    except Exception:
        return data.hex()


def virtual_query(process_handle, address):
    """Query memory region info at address. Returns MEMORY_BASIC_INFORMATION or None."""
    mbi = MEMORY_BASIC_INFORMATION()
    result = kernel32.VirtualQueryEx(
        process_handle,
        ctypes.c_void_p(address),
        ctypes.byref(mbi),
        sizeof(mbi),
    )
    if result == 0:
        return None
    return mbi


def enumerate_memory_regions(process_handle):
    """Enumerate all memory regions. Yields (base_address, mbi) tuples."""
    address = 0
    max_addr = (1 << 64) - 1 if struct.calcsize("P") == 8 else 0x7FFFFFFF
    while address < max_addr:
        mbi = virtual_query(process_handle, address)
        if mbi is None:
            break
        base = mbi.BaseAddress if mbi.BaseAddress else 0
        # Convert to int properly
        if isinstance(base, int):
            base_int = base
        else:
            base_int = base or 0
        size = mbi.RegionSize
        if size == 0:
            break
        yield (base_int, mbi)
        address = base_int + size
        if address <= base_int:
            break


def get_memory_protection(process_handle, address):
    """Get protection flags for the memory region containing address."""
    mbi = virtual_query(process_handle, address)
    if mbi is None:
        return None
    return mbi.Protect
