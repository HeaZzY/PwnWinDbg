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

    def resolve_address(self, address):
        """Resolve an address to 'module+offset' or 'module!symbol+offset'.
        Returns a string or None."""
        # Try DbgHelp first
        sym_name = self._resolve_dbghelp(address)
        if sym_name:
            return sym_name

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
        Supports 'module!symbol', 'module+offset', and bare module names."""
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

        # Bare module name → base address
        name_lower = name.strip().lower()
        for mod in self.modules:
            mod_lower = mod.name.lower()
            mod_stem = mod_lower.rsplit('.', 1)[0] if '.' in mod_lower else mod_lower
            if mod_lower == name_lower or mod_stem == name_lower:
                return mod.base_address

        return None

    def format_address(self, address):
        """Format address with symbol info if available."""
        sym = self.resolve_address(address)
        if sym:
            return f"{address:#x} <{sym}>"
        return f"{address:#x}"
