"""Symbol resolution via DbgHelp and module tracking.

Symbol path setup
-----------------
On init we configure DbgHelp to fetch missing PDBs from Microsoft's symbol
server, caching them locally so subsequent runs reuse the same files.

Resolution order for the search path:
  1. `_NT_SYMBOL_PATH` env var if set (full passthrough — user knows best)
  2. Auto-built path:
        srv*<cache>*https://msdl.microsoft.com/download/symbols
     where <cache> = %LOCALAPPDATA%\\pwnWinDbg\\symbols (created if missing)

The first time you resolve a symbol in a module without local PDBs, DbgHelp
will quietly download the matching PDB from Microsoft. After that the cache
makes lookups instant.
"""

import ctypes
import os
from ctypes import c_ulonglong, byref, sizeof, create_string_buffer
from ..utils.constants import (
    kernel32, HANDLE, DWORD, BOOL,
    DBGHELP_AVAILABLE, dbghelp,
    SYMOPT_UNDNAME, SYMOPT_DEFERRED_LOADS, SYMOPT_LOAD_LINES,
    SYMOPT_AUTO_PUBLICS, SYMOPT_NO_PROMPTS, SYMOPT_FAIL_CRITICAL_ERRORS,
    IMAGEHLP_MODULE64, SYM_TYPE_NAMES, SymNone, SymDeferred, SymExport,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, MODULEENTRY32W,
    INVALID_HANDLE_VALUE, MAX_PATH, SYMENUMPROC,
)


MS_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"


def default_symbol_cache_dir() -> str:
    """Return the default local PDB cache directory, creating it if missing."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    cache = os.path.join(base, "pwnWinDbg", "symbols")
    try:
        os.makedirs(cache, exist_ok=True)
    except OSError:
        pass
    return cache


def build_default_symbol_path() -> str:
    """Build the DbgHelp search path: honor _NT_SYMBOL_PATH or build srv* path."""
    env_path = os.environ.get("_NT_SYMBOL_PATH", "").strip()
    if env_path:
        return env_path
    return f"srv*{default_symbol_cache_dir()}*{MS_SYMBOL_SERVER}"


class ModuleInfo:
    """Represents a loaded module/DLL."""

    def __init__(self, name, path, base_address, size):
        self.name = name
        self.path = path
        self.base_address = base_address
        self.size = size
        self.end_address = base_address + size

    def contains(self, address):
        return self.base_address <= address < self.end_address

    def offset_of(self, address):
        return address - self.base_address

    def __repr__(self):
        return f"{self.name} @ {self.base_address:#x}-{self.end_address:#x}"


class SymbolManager:
    """Manages symbol resolution and module tracking."""

    def __init__(self):
        self.modules = []  # List[ModuleInfo]
        self.modules_by_base = {}  # base_address -> ModuleInfo
        self.process_handle = None
        self.dbghelp_initialized = False
        # Export caches: name_lower -> (module_name, func_name, runtime_address)
        self._export_by_name = {}
        # addr -> (module_name, func_name)
        self._export_by_addr = {}
        self._exports_loaded = False
        # base_address -> int  (real symbol count after a force-load enum,
        # since IMAGEHLP_MODULE64.NumSyms is unreliable post-load)
        self._sym_counts = {}

    def init_dbghelp(self, process_handle):
        """Initialize DbgHelp with the Microsoft symbol server wired up.

        We pass fInvadeProcess=FALSE because at this point the target is
        usually suspended at the very first instruction and DbgHelp's module
        enumeration would fail (or come up empty). Modules get registered
        later via SymRefreshModuleList from refresh_dbghelp_modules() once
        LOAD_DLL_DEBUG_EVENTs have fired.
        """
        self.process_handle = process_handle
        self._init_error = None
        if not DBGHELP_AVAILABLE:
            self._init_error = "dbghelp.dll not available"
            return False

        # Make sure no prior SymInitialize is still active for this handle —
        # SymInitialize fails with ERROR_INVALID_PARAMETER if called twice.
        try:
            dbghelp.SymCleanup(process_handle)
        except Exception:
            pass

        try:
            dbghelp.SymSetOptions(
                SYMOPT_UNDNAME
                | SYMOPT_DEFERRED_LOADS
                | SYMOPT_LOAD_LINES
                | SYMOPT_AUTO_PUBLICS
                | SYMOPT_NO_PROMPTS
                | SYMOPT_FAIL_CRITICAL_ERRORS
            )
            sym_path = build_default_symbol_path()

            # First attempt: full path + no invasive enumeration.
            result = dbghelp.SymInitialize(
                process_handle, sym_path.encode("utf-8"), False
            )
            if result:
                self.dbghelp_initialized = True
                self._symbol_path = sym_path
                return True

            err1 = ctypes.get_last_error()

            # Second attempt: NULL path, then SymSetSearchPath after init.
            result = dbghelp.SymInitialize(process_handle, None, False)
            if result:
                self.dbghelp_initialized = True
                try:
                    dbghelp.SymSetSearchPath(
                        process_handle, sym_path.encode("utf-8")
                    )
                except Exception:
                    pass
                self._symbol_path = sym_path
                return True

            err2 = ctypes.get_last_error()
            self._init_error = (
                f"SymInitialize failed: with-path err={err1}, "
                f"null-path err={err2}"
            )
        except Exception as e:
            self._init_error = f"exception: {e!r}"
        return False

    # ---- symbol path management ----

    def get_search_path(self) -> str:
        """Return the current DbgHelp search path."""
        if not self.dbghelp_initialized:
            return ""
        buf = ctypes.create_string_buffer(2048)
        try:
            ok = dbghelp.SymGetSearchPath(self.process_handle, buf, len(buf))
            if ok:
                return buf.value.decode("utf-8", errors="replace")
        except Exception:
            pass
        return ""

    def set_search_path(self, path: str) -> bool:
        """Replace the DbgHelp search path. Returns True on success."""
        if not self.dbghelp_initialized:
            return False
        try:
            ok = dbghelp.SymSetSearchPath(self.process_handle, path.encode("utf-8"))
            if ok:
                self._symbol_path = path
                # Refresh module list so new path applies on next lookup
                try:
                    dbghelp.SymRefreshModuleList(self.process_handle)
                except Exception:
                    pass
                return True
        except Exception:
            pass
        return False

    # ---- per-module PDB status / forced loads ----

    def get_module_sym_info(self, base_address: int):
        """Return IMAGEHLP_MODULE64 for a loaded module, or None."""
        if not self.dbghelp_initialized:
            return None
        info = IMAGEHLP_MODULE64()
        info.SizeOfStruct = ctypes.sizeof(IMAGEHLP_MODULE64)
        try:
            if dbghelp.SymGetModuleInfo64(self.process_handle, base_address, byref(info)):
                return info
        except Exception:
            pass
        return None

    def get_module_sym_status(self, base_address: int) -> dict:
        """Return a dict describing PDB load state for a module."""
        info = self.get_module_sym_info(base_address)
        if not info:
            return {
                "loaded": False,
                "deferred": False,
                "export_only": False,
                "type": "unknown",
                "num_syms": 0,
                "pdb": "",
                "lines": False,
            }
        sym_type = info.SymType
        # Prefer our own enumerated count when we have it: NumSyms from
        # SymGetModuleInfo64 only reflects symbols already pulled into
        # dbghelp's per-module cache, which is 0 immediately after a fresh
        # load even when the PDB is fully mapped.
        num = self._sym_counts.get(base_address)
        if num is None:
            num = int(info.NumSyms)
        return {
            "loaded": sym_type not in (SymNone, SymDeferred),
            "deferred": sym_type == SymDeferred,
            "export_only": sym_type == SymExport,
            "type": SYM_TYPE_NAMES.get(sym_type, f"?{sym_type}"),
            "num_syms": num,
            "pdb": info.LoadedPdbName.decode("utf-8", errors="replace"),
            "lines": bool(info.LineNumbers),
        }

    def force_load_module(self, mod) -> bool:
        """Download (if needed) and force-load the PDB for a module.

        Stock Windows ships dbghelp.dll without symsrv.dll, so dbghelp's
        built-in `srv*…` resolution cannot reach Microsoft's server. We do
        the download ourselves via core.pdb_downloader, drop the file under
        our cache (matching the symstore layout), then prepend that GUID
        directory to dbghelp's search path so SymLoadModuleEx finds it.

        Returns True only if the module ends up with a real PDB-backed
        symbol type (not just SymExport fallback).
        """
        if not self.dbghelp_initialized or not mod:
            return False

        # 1. Try to grab the matching PDB ourselves first.
        download_status = None
        if mod.path:
            from . import pdb_downloader as pdl
            cache = default_symbol_cache_dir()
            status, payload = pdl.download_pdb(mod.path, cache)
            download_status = (status, payload)
            if status in ("cached", "downloaded"):
                pdb_dir = os.path.dirname(payload)
                self._prepend_search_path(pdb_dir)

        # Temporarily clear DEFERRED_LOADS so dbghelp parses symbols eagerly
        # for *this* module — otherwise NumSyms stays at 0 until the first
        # lookup, and the status table looks like nothing was loaded.
        old_opts = None
        try:
            old_opts = dbghelp.SymGetOptions()
            dbghelp.SymSetOptions(old_opts & ~SYMOPT_DEFERRED_LOADS)
        except Exception:
            pass

        try:
            # 2. Drop any prior entry so we re-trigger the load path.
            try:
                dbghelp.SymUnloadModule64(self.process_handle, mod.base_address)
            except Exception:
                pass

            image_name = mod.path.encode("utf-8") if mod.path else None
            dbghelp.SymLoadModuleEx(
                self.process_handle,
                None,
                image_name,
                None,
                mod.base_address,
                mod.size,
                None,
                0,
            )

            # Force dbghelp to walk the public/global symbol streams so we
            # get a real count and the per-module cache is hot for future
            # name lookups.
            self._sym_counts.pop(mod.base_address, None)
            count = self._enum_module_symbols(mod.base_address)
            if count > 0:
                self._sym_counts[mod.base_address] = count

            st = self.get_module_sym_status(mod.base_address)
            self._last_load_status = (st, download_status)
            # Only count it as a win when we got real PDB symbols, not the
            # PE-export fallback.
            return st["loaded"] and not st["export_only"]
        except Exception:
            return False
        finally:
            if old_opts is not None:
                try:
                    dbghelp.SymSetOptions(old_opts)
                except Exception:
                    pass

    def _enum_module_symbols(self, base_address: int) -> int:
        """Walk every symbol in a module via SymEnumSymbols, return the count.

        This is the only reliable way to (a) force dbghelp to actually
        parse the symbol streams of a freshly-loaded PDB and (b) get a
        meaningful number to display in the status table.
        """
        if not self.dbghelp_initialized:
            return 0
        counter = [0]

        def _cb(_sym_info_ptr, _sym_size, _ctx):
            counter[0] += 1
            return True  # keep enumerating

        try:
            cb = SYMENUMPROC(_cb)
            dbghelp.SymEnumSymbols(
                self.process_handle, base_address, b"*", cb, None
            )
        except Exception:
            pass
        return counter[0]

    def _prepend_search_path(self, directory: str):
        """Add a directory to the front of dbghelp's search path (idempotent)."""
        if not directory:
            return
        try:
            current = self.get_search_path()
            parts = current.split(";") if current else []
            if directory in parts:
                return
            new_path = directory + (";" + current if current else "")
            dbghelp.SymSetSearchPath(
                self.process_handle, new_path.encode("utf-8")
            )
        except Exception:
            pass

    def cleanup(self):
        """Cleanup DbgHelp."""
        if self.dbghelp_initialized and self.process_handle and DBGHELP_AVAILABLE:
            try:
                dbghelp.SymCleanup(self.process_handle)
            except Exception:
                pass
            self.dbghelp_initialized = False

    def add_module(self, name, path, base_address, size):
        """Register a loaded module."""
        mod = ModuleInfo(name, path, base_address, size)
        self.modules.append(mod)
        self.modules_by_base[base_address] = mod
        return mod

    def remove_module(self, base_address):
        """Unregister a module by base address."""
        if base_address in self.modules_by_base:
            mod = self.modules_by_base.pop(base_address)
            self.modules = [m for m in self.modules if m.base_address != base_address]
            return mod
        return None

    def get_module_at(self, address):
        """Find which module contains the given address."""
        for mod in self.modules:
            if mod.contains(address):
                return mod
        return None

    def refresh_modules(self, pid):
        """Refresh module list using Toolhelp32Snapshot."""
        self.modules.clear()
        self.modules_by_base.clear()
        self._sym_counts.clear()

        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if snap == INVALID_HANDLE_VALUE or snap is None:
            return

        try:
            me = MODULEENTRY32W()
            me.dwSize = sizeof(me)

            if kernel32.Module32FirstW(snap, byref(me)):
                while True:
                    name = me.szModule
                    path = me.szExePath
                    base = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value or 0
                    size = me.modBaseSize
                    self.add_module(name, path, base, size)
                    me.dwSize = sizeof(me)
                    if not kernel32.Module32NextW(snap, byref(me)):
                        break
        finally:
            kernel32.CloseHandle(snap)

        # Invalidate export cache so it gets rebuilt on next use
        self._exports_loaded = False
        self._export_by_name.clear()
        self._export_by_addr.clear()
        # Drop the cached NT syscall table — it's tied to live ntdll bytes,
        # so a fresh attach/respawn means a (possibly) different ntdll base
        # and stub locations.
        if hasattr(self, "_nt_syscall_table"):
            self._nt_syscall_table.invalidate()

        # Sync DbgHelp's internal module list with the live process so it
        # knows about every DLL we've seen via LOAD_DLL events.
        self.refresh_dbghelp_modules()

    def refresh_dbghelp_modules(self) -> bool:
        """Tell DbgHelp to re-enumerate modules in the target process.

        Without this, DbgHelp only knows about modules present at SymInitialize
        time — every DLL loaded later (via LOAD_DLL_DEBUG_EVENT) is invisible
        to symbol resolution and to SymGetModuleInfo64.
        """
        if not self.dbghelp_initialized:
            return False
        try:
            return bool(dbghelp.SymRefreshModuleList(self.process_handle))
        except Exception:
            return False

    def _ensure_exports_loaded(self):
        """Parse PE exports for all loaded modules (lazy, done once per refresh).

        Forwarded exports (e.g. kernel32!HeapAlloc → kernelbase!HeapAlloc →
        ntdll!RtlAllocateHeap) are detected and chased to their final
        implementation. Without this, pefile's RVA for a forwarder points
        inside the export name table — placing a BP there fires zero times
        because no thread ever lands inside the export directory. The user
        cares about the *real* address, not the forwarder thunk that the
        loader has long since IAT-rewritten away.
        """
        if self._exports_loaded:
            return
        self._exports_loaded = True
        try:
            import pefile
        except ImportError:
            return

        # First pass: collect every export. For real (non-forwarded) exports
        # we already know the runtime address. For forwarders we record the
        # `DLL.FUNC` chain target so the second pass can resolve it.
        # Maps: (mod_name_lower, func_name_lower) -> entry
        # entry = ("real", mod_name, func_name, runtime_addr)
        #       | ("fwd",  mod_name, func_name, fwd_dll, fwd_func)
        per_module = {}
        for mod in self.modules:
            if not mod.path or not os.path.isfile(mod.path):
                continue
            try:
                pe = pefile.PE(mod.path, fast_load=True)
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
                )
                if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    pe.close()
                    continue
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if not exp.name:
                        continue
                    func_name = exp.name.decode('utf-8', errors='replace')
                    fwd = getattr(exp, "forwarder", None)
                    if fwd:
                        try:
                            fwd_str = fwd.decode("utf-8", errors="replace")
                        except Exception:
                            continue
                        if "." not in fwd_str:
                            continue
                        next_mod, next_func = fwd_str.split(".", 1)
                        per_module[(mod.name.lower(), func_name.lower())] = (
                            "fwd", mod.name, func_name, next_mod, next_func
                        )
                    else:
                        runtime_addr = mod.base_address + exp.address
                        per_module[(mod.name.lower(), func_name.lower())] = (
                            "real", mod.name, func_name, runtime_addr
                        )
                pe.close()
            except Exception:
                continue

        # Helper: resolve a (mod, func) entry through any forwarder chain.
        # Returns (real_mod_name, real_func_name, real_addr) or None.
        def _resolve(mod_l, func_l, depth):
            if depth > 16:
                return None
            entry = per_module.get((mod_l, func_l))
            if entry is None:
                return None
            kind = entry[0]
            if kind == "real":
                return (entry[1], entry[2], entry[3])
            # Forwarder — try a few mod-name spellings.
            _, _, _, fwd_dll, fwd_func = entry
            cands = [
                fwd_dll.lower() + ".dll",
                fwd_dll.lower(),
                f"{fwd_dll.lower()}.dll".lower(),
            ]
            seen = set()
            for cand in cands:
                if cand in seen:
                    continue
                seen.add(cand)
                resolved = _resolve(cand, fwd_func.lower(), depth + 1)
                if resolved is not None:
                    return resolved
            return None

        # Second pass: emit one cache entry per (mod, func), chasing
        # forwarders. Bare-name keys (`heapalloc`) win on the first
        # encountered REAL implementation — that way, when the user types
        # `bp HeapAlloc` we hand them the ntdll!RtlAllocateHeap address
        # rather than the kernel32 thunk.
        bare_seen = set()
        for (mod_l, func_l), entry in per_module.items():
            resolved = _resolve(mod_l, func_l, 0)
            if resolved is None:
                continue
            real_mod, real_func, real_addr = resolved
            # Always store the qualified key for the *original* module so
            # `kernel32!HeapAlloc` and `kernelbase!HeapAlloc` both resolve
            # to the chased ntdll address.
            orig_mod = entry[1]
            orig_func = entry[2]
            mod_key = f"{orig_mod.lower()}!{orig_func.lower()}"
            self._export_by_name[mod_key] = (real_mod, real_func, real_addr)
            stem = orig_mod.lower().rsplit('.', 1)[0] if '.' in orig_mod else orig_mod.lower()
            stem_key = f"{stem}!{orig_func.lower()}"
            if stem_key != mod_key:
                self._export_by_name[stem_key] = (real_mod, real_func, real_addr)
            # Bare-name entry: only set on the first hit so the chased
            # address wins for `HeapAlloc`-style lookups. (kernel32 happens
            # to be early in self.modules but we don't rely on order — we
            # check via `bare_seen` below.)
            bare_key = orig_func.lower()
            if bare_key not in bare_seen:
                bare_seen.add(bare_key)
                self._export_by_name[bare_key] = (real_mod, real_func, real_addr)
            # addr -> name lookup (only for real, non-forwarded entries)
            if entry[0] == "real":
                self._export_by_addr[entry[3]] = (orig_mod, orig_func)

    def resolve_address(self, address):
        """Resolve an address to 'module!symbol' or 'module+offset'.
        Returns a string or None."""
        # Try DbgHelp first
        sym_name = self._resolve_dbghelp(address)
        if sym_name:
            return sym_name

        # Try export cache
        self._ensure_exports_loaded()
        hit = self._export_by_addr.get(address)
        if hit:
            mod_name, func_name = hit
            return f"{mod_name}!{func_name}"

        # Fall back to module+offset
        mod = self.get_module_at(address)
        if mod:
            offset = mod.offset_of(address)
            return f"{mod.name}+{offset:#x}"
        return None

    def _resolve_dbghelp(self, address):
        """Try to resolve via DbgHelp SymFromAddr."""
        if not self.dbghelp_initialized or not DBGHELP_AVAILABLE:
            return None
        try:
            from ..utils.constants import SYMBOL_INFO, MAX_SYM_NAME

            sym = SYMBOL_INFO()
            sym.SizeOfStruct = 88  # sizeof(SYMBOL_INFO) without Name
            sym.MaxNameLen = MAX_SYM_NAME
            displacement = c_ulonglong(0)

            result = dbghelp.SymFromAddr(
                self.process_handle,
                address,
                byref(displacement),
                byref(sym),
            )
            if result:
                name = sym.Name.decode("utf-8", errors="replace")
                mod = self.get_module_at(address)
                mod_prefix = f"{mod.name}!" if mod else ""
                if displacement.value:
                    return f"{mod_prefix}{name}+{displacement.value:#x}"
                return f"{mod_prefix}{name}"
        except Exception:
            pass
        return None

    def resolve_name_to_address(self, name):
        """Try to resolve a symbol name to an address.
        Supports 'module!symbol', 'module+offset', bare module names,
        and bare symbol names (e.g. 'WinExec', 'kernel32!WinExec')."""
        # module+offset
        if '+' in name and '!' not in name:
            parts = name.split('+', 1)
            mod_name = parts[0].strip().lower()
            try:
                offset = int(parts[1].strip(), 0)
            except ValueError:
                return None
            for mod in self.modules:
                mod_lower = mod.name.lower()
                mod_stem = mod_lower.rsplit('.', 1)[0] if '.' in mod_lower else mod_lower
                if mod_lower == mod_name or mod_stem == mod_name:
                    return mod.base_address + offset
            return None

        # Plain hex address
        try:
            return int(name, 0)
        except ValueError:
            pass

        # Try the PE export cache first. It already chased forwarder chains
        # at load time, so for names like `HeapAlloc` it returns the real
        # ntdll!RtlAllocateHeap address — DbgHelp would hand us the kernel32
        # forwarder thunk instead, which is never executed at runtime.
        self._ensure_exports_loaded()
        key = name.strip().lower()
        hit = self._export_by_name.get(key)
        if hit:
            return hit[2]  # runtime_addr

        # Try DbgHelp SymFromName (handles 'module!symbol' and bare symbol)
        addr = self._resolve_sym_by_name(name)
        if addr is not None:
            return addr

        # If bare name with no '!', try each module prefix via DbgHelp
        if '!' not in name:
            for mod in self.modules:
                addr = self._resolve_sym_by_name(f"{mod.name}!{name}")
                if addr is not None:
                    return addr

        # Bare module name → base address
        name_lower = name.strip().lower()
        for mod in self.modules:
            mod_lower = mod.name.lower()
            mod_stem = mod_lower.rsplit('.', 1)[0] if '.' in mod_lower else mod_lower
            if mod_lower == name_lower or mod_stem == name_lower:
                return mod.base_address

        return None

    def _resolve_sym_by_name(self, name):
        """Resolve a symbol name via DbgHelp SymFromName. Returns address or None."""
        if not self.dbghelp_initialized or not DBGHELP_AVAILABLE:
            return None
        try:
            from ..utils.constants import SYMBOL_INFO, MAX_SYM_NAME

            sym = SYMBOL_INFO()
            sym.SizeOfStruct = 88
            sym.MaxNameLen = MAX_SYM_NAME

            result = dbghelp.SymFromName(
                self.process_handle,
                name.encode("utf-8"),
                ctypes.byref(sym),
            )
            if result and sym.Address:
                return sym.Address
        except Exception:
            pass
        return None

    def format_address(self, address):
        """Format address with symbol info if available."""
        sym = self.resolve_address(address)
        if sym:
            return f"{address:#x} <{sym}>"
        return f"{address:#x}"
