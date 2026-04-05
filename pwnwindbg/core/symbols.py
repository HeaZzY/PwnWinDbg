"""Symbol resolution via DbgHelp and module tracking."""

import ctypes
from ctypes import c_ulonglong, byref, sizeof, create_string_buffer
from ..utils.constants import (
    kernel32, HANDLE, DWORD, BOOL,
    DBGHELP_AVAILABLE, dbghelp, SYMOPT_UNDNAME, SYMOPT_DEFERRED_LOADS,
    SYMOPT_LOAD_LINES,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, MODULEENTRY32W,
    INVALID_HANDLE_VALUE, MAX_PATH,
)
import os


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

    def init_dbghelp(self, process_handle):
        """Initialize DbgHelp symbol handler."""
        self.process_handle = process_handle
        if not DBGHELP_AVAILABLE:
            return False
        try:
            dbghelp.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES)
            # Pass None for search path to use default
            result = dbghelp.SymInitialize(process_handle, None, True)
            if result:
                self.dbghelp_initialized = True
                return True
        except Exception:
            pass
        return False

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

    def _ensure_exports_loaded(self):
        """Parse PE exports for all loaded modules (lazy, done once per refresh)."""
        if self._exports_loaded:
            return
        self._exports_loaded = True
        try:
            import pefile
        except ImportError:
            return
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
                    rva = exp.address
                    runtime_addr = mod.base_address + rva
                    key = func_name.lower()
                    self._export_by_name[key] = (mod.name, func_name, runtime_addr)
                    # Also store with module prefix for "module!func" lookups
                    mod_key = f"{mod.name.lower()}!{key}"
                    self._export_by_name[mod_key] = (mod.name, func_name, runtime_addr)
                    # Without extension too
                    stem = mod.name.lower().rsplit('.', 1)[0] if '.' in mod.name else mod.name.lower()
                    stem_key = f"{stem}!{key}"
                    if stem_key != mod_key:
                        self._export_by_name[stem_key] = (mod.name, func_name, runtime_addr)
                    self._export_by_addr[runtime_addr] = (mod.name, func_name)
                pe.close()
            except Exception:
                continue

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
            from .constants import SYMBOL_INFO, MAX_SYM_NAME

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

        # Try PE export cache (covers all loaded DLL exports)
        self._ensure_exports_loaded()
        key = name.strip().lower()
        hit = self._export_by_name.get(key)
        if hit:
            return hit[2]  # runtime_addr

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
