"""Standalone PDB downloader for Microsoft's symbol server.

DbgHelp's `srv*` directive only works when symsrv.dll sits next to
dbghelp.dll. On a stock Windows install symsrv.dll is missing — it ships
with the Windows SDK / Debugging Tools — so dbghelp silently falls back to
PE exports and we never get real symbols.

This module sidesteps symsrv entirely:
  1. Read the CodeView debug record from the on-disk PE to get
     (pdb_name, guid, age).
  2. Build the symstore URL:
        https://msdl.microsoft.com/download/symbols/<pdb>/<GUID><AGE>/<pdb>
  3. Download to the same on-disk layout under our cache:
        <cache>/<pdb>/<GUID><AGE>/<pdb>
  4. Hand that path back so the caller can point DbgHelp at the file
     directly (e.g. by appending the GUID-dir to the search path).

The cache layout matches what dbghelp would have produced via symsrv, so
existing PDBs from prior runs are picked up without re-download.
"""

import os
import struct
import urllib.request
import urllib.error

MS_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"

# IMAGE_DEBUG_TYPE_CODEVIEW
_DEBUG_TYPE_CODEVIEW = 2


def read_pe_codeview(image_path: str):
    """Return (pdb_basename, guid_str, age) for an on-disk PE, or None.

    GUID is uppercase hex with no dashes, age is the integer (caller picks
    formatting). Both come from the CodeView 'RSDS' record.
    """
    if not image_path or not os.path.isfile(image_path):
        return None
    try:
        import pefile
    except ImportError:
        return None
    try:
        pe = pefile.PE(image_path, fast_load=True)
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']]
            )
            if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
                return None
            for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                if dbg.struct.Type != _DEBUG_TYPE_CODEVIEW:
                    continue
                # Prefer raw-file offset (PointerToRawData) — pe.__data__ is
                # the raw file image, not the memory-mapped layout.
                offset = dbg.struct.PointerToRawData
                size = dbg.struct.SizeOfData
                if not offset or not size:
                    continue
                data = pe.__data__[offset:offset + size]
                if data[:4] != b"RSDS" or len(data) < 25:
                    continue
                guid_bytes = data[4:20]
                age = struct.unpack("<I", data[20:24])[0]
                pdb_path = data[24:].split(b"\x00", 1)[0]
                pdb_name = os.path.basename(
                    pdb_path.decode("utf-8", errors="replace")
                )

                # Microsoft GUID encoding: little-endian for the first three
                # fields, big-endian for the last 8 bytes.
                d1 = struct.unpack("<I", guid_bytes[0:4])[0]
                d2 = struct.unpack("<H", guid_bytes[4:6])[0]
                d3 = struct.unpack("<H", guid_bytes[6:8])[0]
                d4 = guid_bytes[8:16].hex().upper()
                guid_str = f"{d1:08X}{d2:04X}{d3:04X}{d4}"
                return (pdb_name, guid_str, age)
        finally:
            pe.close()
    except Exception:
        return None
    return None


def cache_pdb_path(cache_dir: str, pdb_name: str, guid_str: str, age: int) -> str:
    """Return the on-disk cache path matching the symstore layout."""
    return os.path.join(cache_dir, pdb_name, f"{guid_str}{age:X}", pdb_name)


def cache_pdb_dir(cache_dir: str, pdb_name: str, guid_str: str, age: int) -> str:
    """Directory containing the cached PDB (for adding to search path)."""
    return os.path.join(cache_dir, pdb_name, f"{guid_str}{age:X}")


def download_pdb(image_path: str, cache_dir: str, timeout: float = 30.0):
    """Download a PDB for the given image. Returns (status, path_or_msg).

    status is one of: 'cached', 'downloaded', 'no_codeview', 'http_error'.
    On success path_or_msg is the absolute file path; on failure it is the
    error message.
    """
    cv = read_pe_codeview(image_path)
    if not cv:
        return ("no_codeview", "no CodeView record in PE")
    pdb_name, guid_str, age = cv

    target = cache_pdb_path(cache_dir, pdb_name, guid_str, age)
    if os.path.isfile(target) and os.path.getsize(target) > 0:
        return ("cached", target)

    os.makedirs(os.path.dirname(target), exist_ok=True)

    url = f"{MS_SYMBOL_SERVER}/{pdb_name}/{guid_str}{age:X}/{pdb_name}"
    req = urllib.request.Request(
        url, headers={"User-Agent": "Microsoft-Symbol-Server/10.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            tmp = target + ".part"
            with open(tmp, "wb") as f:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
            os.replace(tmp, target)
        return ("downloaded", target)
    except urllib.error.HTTPError as e:
        return ("http_error", f"HTTP {e.code} {e.reason}")
    except Exception as e:
        return ("http_error", f"{type(e).__name__}: {e}")
