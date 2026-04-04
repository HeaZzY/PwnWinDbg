"""Windows constants, structures, and ctypes definitions for the debug API."""

import ctypes
import ctypes.wintypes as wt
from ctypes import (
    Structure, Union, POINTER, sizeof, c_ulonglong, c_ulong, c_ushort, c_ubyte,
    c_void_p, c_char, c_size_t, c_int, c_longlong, c_byte,
)
import struct
import sys

# ---------------------------------------------------------------------------
# Architecture detection helpers
# ---------------------------------------------------------------------------

def is_64bit_python():
    return struct.calcsize("P") == 8

PYTHON_64 = is_64bit_python()

# ---------------------------------------------------------------------------
# Basic type aliases
# ---------------------------------------------------------------------------

BYTE = c_ubyte
WORD = c_ushort
DWORD = c_ulong
QWORD = c_ulonglong
LONG = ctypes.c_long
ULONG_PTR = c_ulonglong if PYTHON_64 else c_ulong
PVOID = c_void_p
LPVOID = c_void_p
SIZE_T = c_size_t
HANDLE = wt.HANDLE
BOOL = wt.BOOL
LPSTR = ctypes.c_char_p
LPCSTR = ctypes.c_char_p
LPCWSTR = ctypes.c_wchar_p

# ---------------------------------------------------------------------------
# Process creation flags
# ---------------------------------------------------------------------------

DEBUG_PROCESS = 0x00000001
DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_SUSPENDED = 0x00000004
STARTF_USESTDHANDLES = 0x00000100
PROCESS_ALL_ACCESS = 0x001FFFFF
THREAD_ALL_ACCESS = 0x001FFFFF
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SUSPEND_RESUME = 0x0002

INFINITE = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# Debug event codes
# ---------------------------------------------------------------------------

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

# ---------------------------------------------------------------------------
# Exception codes
# ---------------------------------------------------------------------------

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_GUARD_PAGE = 0x80000001
EXCEPTION_STACK_OVERFLOW = 0xC00000FD
STATUS_WX86_BREAKPOINT = 0x4000001F
STATUS_WX86_SINGLE_STEP = 0x4000001E

# Continue status
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

# ---------------------------------------------------------------------------
# Memory protection flags
# ---------------------------------------------------------------------------

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

# Memory state
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

# Memory type
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

# ---------------------------------------------------------------------------
# Context flags
# ---------------------------------------------------------------------------

CONTEXT_AMD64 = 0x00100000
CONTEXT_i386 = 0x00010000

CONTEXT_CONTROL_AMD64 = CONTEXT_AMD64 | 0x0001
CONTEXT_INTEGER_AMD64 = CONTEXT_AMD64 | 0x0002
CONTEXT_SEGMENTS_AMD64 = CONTEXT_AMD64 | 0x0004
CONTEXT_FLOATING_POINT_AMD64 = CONTEXT_AMD64 | 0x0008
CONTEXT_DEBUG_REGISTERS_AMD64 = CONTEXT_AMD64 | 0x0010
CONTEXT_FULL_AMD64 = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64 | CONTEXT_FLOATING_POINT_AMD64
CONTEXT_ALL_AMD64 = CONTEXT_FULL_AMD64 | CONTEXT_SEGMENTS_AMD64 | CONTEXT_DEBUG_REGISTERS_AMD64

CONTEXT_CONTROL_i386 = CONTEXT_i386 | 0x0001
CONTEXT_INTEGER_i386 = CONTEXT_i386 | 0x0002
CONTEXT_SEGMENTS_i386 = CONTEXT_i386 | 0x0004
CONTEXT_FLOATING_POINT_i386 = CONTEXT_i386 | 0x0008
CONTEXT_DEBUG_REGISTERS_i386 = CONTEXT_i386 | 0x0010
CONTEXT_FULL_i386 = CONTEXT_CONTROL_i386 | CONTEXT_INTEGER_i386 | CONTEXT_SEGMENTS_i386
CONTEXT_ALL_i386 = CONTEXT_FULL_i386 | CONTEXT_FLOATING_POINT_i386 | CONTEXT_DEBUG_REGISTERS_i386

# WoW64
WOW64_CONTEXT_i386 = 0x00010000
WOW64_CONTEXT_CONTROL = WOW64_CONTEXT_i386 | 0x0001
WOW64_CONTEXT_INTEGER = WOW64_CONTEXT_i386 | 0x0002
WOW64_CONTEXT_SEGMENTS = WOW64_CONTEXT_i386 | 0x0004
WOW64_CONTEXT_FLOATING_POINT = WOW64_CONTEXT_i386 | 0x0008
WOW64_CONTEXT_DEBUG_REGISTERS = WOW64_CONTEXT_i386 | 0x0010
WOW64_CONTEXT_FULL = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS
WOW64_CONTEXT_ALL = WOW64_CONTEXT_FULL | WOW64_CONTEXT_FLOATING_POINT | WOW64_CONTEXT_DEBUG_REGISTERS

# ---------------------------------------------------------------------------
# Trap flag for single stepping
# ---------------------------------------------------------------------------

EFLAGS_TF = 0x100
EFLAGS_RF = 0x10000

# ---------------------------------------------------------------------------
# Structures: STARTUPINFO, PROCESS_INFORMATION
# ---------------------------------------------------------------------------

class STARTUPINFOW(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPCWSTR),
        ("lpDesktop", LPCWSTR),
        ("lpTitle", LPCWSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", POINTER(BYTE)),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]

# ---------------------------------------------------------------------------
# Debug event structures
# ---------------------------------------------------------------------------

class EXCEPTION_RECORD(Structure):
    pass

EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", DWORD),
    ("ExceptionFlags", DWORD),
    ("ExceptionRecord", POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", PVOID),
    ("NumberParameters", DWORD),
    ("ExceptionInformation", ULONG_PTR * 15),
]

class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", DWORD),
    ]

class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("hThread", HANDLE),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID),
    ]

class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", HANDLE),
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("lpBaseOfImage", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD),
    ]

class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", DWORD),
    ]

class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", DWORD),
    ]

class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", HANDLE),
        ("lpBaseOfDll", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD),
    ]

class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", LPVOID),
    ]

class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ("lpDebugStringData", LPVOID),
        ("fUnicode", WORD),
        ("nDebugStringLength", WORD),
    ]

class RIP_INFO(Structure):
    _fields_ = [
        ("dwError", DWORD),
        ("dwType", DWORD),
    ]

class _DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]

class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", _DEBUG_EVENT_UNION),
    ]

# ---------------------------------------------------------------------------
# CONTEXT structures (x64)
# ---------------------------------------------------------------------------

class M128A(Structure):
    _fields_ = [
        ("Low", c_ulonglong),
        ("High", c_longlong),
    ]

class XMM_SAVE_AREA32(Structure):
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", BYTE * 96),
    ]

class CONTEXT64(Structure):
    _pack_ = 16
    _fields_ = [
        ("P1Home", c_ulonglong),
        ("P2Home", c_ulonglong),
        ("P3Home", c_ulonglong),
        ("P4Home", c_ulonglong),
        ("P5Home", c_ulonglong),
        ("P6Home", c_ulonglong),
        ("ContextFlags", DWORD),
        ("MxCsr", DWORD),
        ("SegCs", WORD),
        ("SegDs", WORD),
        ("SegEs", WORD),
        ("SegFs", WORD),
        ("SegGs", WORD),
        ("SegSs", WORD),
        ("EFlags", DWORD),
        ("Dr0", c_ulonglong),
        ("Dr1", c_ulonglong),
        ("Dr2", c_ulonglong),
        ("Dr3", c_ulonglong),
        ("Dr6", c_ulonglong),
        ("Dr7", c_ulonglong),
        ("Rax", c_ulonglong),
        ("Rcx", c_ulonglong),
        ("Rdx", c_ulonglong),
        ("Rbx", c_ulonglong),
        ("Rsp", c_ulonglong),
        ("Rbp", c_ulonglong),
        ("Rsi", c_ulonglong),
        ("Rdi", c_ulonglong),
        ("R8", c_ulonglong),
        ("R9", c_ulonglong),
        ("R10", c_ulonglong),
        ("R11", c_ulonglong),
        ("R12", c_ulonglong),
        ("R13", c_ulonglong),
        ("R14", c_ulonglong),
        ("R15", c_ulonglong),
        ("Rip", c_ulonglong),
        ("FltSave", XMM_SAVE_AREA32),
        ("VectorRegister", M128A * 26),
        ("VectorControl", c_ulonglong),
        ("DebugControl", c_ulonglong),
        ("LastBranchToRip", c_ulonglong),
        ("LastBranchFromRip", c_ulonglong),
        ("LastExceptionToRip", c_ulonglong),
        ("LastExceptionFromRip", c_ulonglong),
    ]

# ---------------------------------------------------------------------------
# CONTEXT structure (x86 / WoW64)
# ---------------------------------------------------------------------------

class FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
    ]

class CONTEXT32(Structure):
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
    ]

# WOW64_CONTEXT is same layout as CONTEXT32
WOW64_CONTEXT = CONTEXT32

# ---------------------------------------------------------------------------
# MEMORY_BASIC_INFORMATION
# ---------------------------------------------------------------------------

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]

# On 64-bit, pad with alignment field
if PYTHON_64:
    class MEMORY_BASIC_INFORMATION64(Structure):
        _fields_ = [
            ("BaseAddress", c_ulonglong),
            ("AllocationBase", c_ulonglong),
            ("AllocationProtect", DWORD),
            ("__alignment1", DWORD),
            ("RegionSize", c_ulonglong),
            ("State", DWORD),
            ("Protect", DWORD),
            ("Type", DWORD),
            ("__alignment2", DWORD),
        ]

# ---------------------------------------------------------------------------
# Toolhelp32 snapshot structures
# ---------------------------------------------------------------------------

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPTHREAD = 0x00000004

MAX_MODULE_NAME32 = 255
MAX_PATH = 260

class MODULEENTRY32W(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("th32ModuleID", DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage", DWORD),
        ("ProccntUsage", DWORD),
        ("modBaseAddr", POINTER(BYTE)),
        ("modBaseSize", DWORD),
        ("hModule", HANDLE),
        ("szModule", ctypes.c_wchar * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", ctypes.c_wchar * MAX_PATH),
    ]

class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ThreadID", DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri", LONG),
        ("tpDeltaPri", LONG),
        ("dwFlags", DWORD),
    ]

# ---------------------------------------------------------------------------
# Kernel32 / ntdll function bindings
# ---------------------------------------------------------------------------

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# Process creation
kernel32.CreateProcessW.argtypes = [
    LPCWSTR, ctypes.c_wchar_p, LPVOID, LPVOID, BOOL, DWORD,
    LPVOID, LPCWSTR, POINTER(STARTUPINFOW), POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = BOOL

# Debug API
kernel32.WaitForDebugEvent.argtypes = [POINTER(DEBUG_EVENT), DWORD]
kernel32.WaitForDebugEvent.restype = BOOL

kernel32.ContinueDebugEvent.argtypes = [DWORD, DWORD, DWORD]
kernel32.ContinueDebugEvent.restype = BOOL

kernel32.DebugActiveProcess.argtypes = [DWORD]
kernel32.DebugActiveProcess.restype = BOOL

kernel32.DebugActiveProcessStop.argtypes = [DWORD]
kernel32.DebugActiveProcessStop.restype = BOOL

kernel32.DebugSetProcessKillOnExit.argtypes = [BOOL]
kernel32.DebugSetProcessKillOnExit.restype = BOOL

# Memory
kernel32.ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
kernel32.ReadProcessMemory.restype = BOOL

kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
kernel32.WriteProcessMemory.restype = BOOL

kernel32.VirtualQueryEx.argtypes = [HANDLE, LPVOID, POINTER(MEMORY_BASIC_INFORMATION), SIZE_T]
kernel32.VirtualQueryEx.restype = SIZE_T

kernel32.VirtualProtectEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, POINTER(DWORD)]
kernel32.VirtualProtectEx.restype = BOOL

# Thread context
kernel32.GetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT64)]
kernel32.GetThreadContext.restype = BOOL

kernel32.SetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT64)]
kernel32.SetThreadContext.restype = BOOL

kernel32.SuspendThread.argtypes = [HANDLE]
kernel32.SuspendThread.restype = DWORD

kernel32.ResumeThread.argtypes = [HANDLE]
kernel32.ResumeThread.restype = DWORD

# WoW64 context
kernel32.Wow64GetThreadContext.argtypes = [HANDLE, POINTER(WOW64_CONTEXT)]
kernel32.Wow64GetThreadContext.restype = BOOL

kernel32.Wow64SetThreadContext.argtypes = [HANDLE, POINTER(WOW64_CONTEXT)]
kernel32.Wow64SetThreadContext.restype = BOOL

# Process info
kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
kernel32.OpenProcess.restype = HANDLE

kernel32.OpenThread.argtypes = [DWORD, BOOL, DWORD]
kernel32.OpenThread.restype = HANDLE

kernel32.CloseHandle.argtypes = [HANDLE]
kernel32.CloseHandle.restype = BOOL

kernel32.GetCurrentProcess.argtypes = []
kernel32.GetCurrentProcess.restype = HANDLE

kernel32.IsWow64Process.argtypes = [HANDLE, POINTER(BOOL)]
kernel32.IsWow64Process.restype = BOOL

kernel32.FlushInstructionCache.argtypes = [HANDLE, LPVOID, SIZE_T]
kernel32.FlushInstructionCache.restype = BOOL

# Toolhelp
kernel32.CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
kernel32.CreateToolhelp32Snapshot.restype = HANDLE

kernel32.Module32FirstW.argtypes = [HANDLE, POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = BOOL

kernel32.Module32NextW.argtypes = [HANDLE, POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = BOOL

kernel32.Thread32First.argtypes = [HANDLE, POINTER(THREADENTRY32)]
kernel32.Thread32First.restype = BOOL

kernel32.Thread32Next.argtypes = [HANDLE, POINTER(THREADENTRY32)]
kernel32.Thread32Next.restype = BOOL

# File mapping (for getting DLL name)
kernel32.GetFinalPathNameByHandleW.argtypes = [HANDLE, ctypes.c_wchar_p, DWORD, DWORD]
kernel32.GetFinalPathNameByHandleW.restype = DWORD

kernel32.GetModuleFileNameExW = None
try:
    psapi = ctypes.windll.psapi
    psapi.GetModuleFileNameExW.argtypes = [HANDLE, HANDLE, ctypes.c_wchar_p, DWORD]
    psapi.GetModuleFileNameExW.restype = DWORD
except Exception:
    psapi = None

kernel32.GetProcessId.argtypes = [HANDLE]
kernel32.GetProcessId.restype = DWORD

kernel32.TerminateProcess.argtypes = [HANDLE, ctypes.c_uint]
kernel32.TerminateProcess.restype = BOOL

kernel32.DebugBreakProcess.argtypes = [HANDLE]
kernel32.DebugBreakProcess.restype = BOOL

kernel32.CreateFileW.argtypes = [LPCWSTR, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE]
kernel32.CreateFileW.restype = HANDLE

kernel32.GetStdHandle.argtypes = [DWORD]
kernel32.GetStdHandle.restype = HANDLE

kernel32.SetConsoleCtrlHandler.argtypes = [ctypes.c_void_p, BOOL]
kernel32.SetConsoleCtrlHandler.restype = BOOL

# user32 — for GetAsyncKeyState (keyboard polling)
user32 = ctypes.windll.user32
user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
user32.GetAsyncKeyState.restype = ctypes.c_short

VK_F12 = 0x7B

# ---------------------------------------------------------------------------
# DbgHelp bindings for symbol resolution
# ---------------------------------------------------------------------------

try:
    dbghelp = ctypes.windll.dbghelp

    SYMOPT_UNDNAME = 0x00000002
    SYMOPT_DEFERRED_LOADS = 0x00000004
    SYMOPT_LOAD_LINES = 0x00000010
    SYMOPT_DEBUG = 0x80000000

    # Symbol info structure
    MAX_SYM_NAME = 2000

    class SYMBOL_INFO(Structure):
        _fields_ = [
            ("SizeOfStruct", DWORD),
            ("TypeIndex", DWORD),
            ("Reserved", c_ulonglong * 2),
            ("Index", DWORD),
            ("Size", DWORD),
            ("ModBase", c_ulonglong),
            ("Flags", DWORD),
            ("Value", c_ulonglong),
            ("Address", c_ulonglong),
            ("Register", DWORD),
            ("Scope", DWORD),
            ("Tag", DWORD),
            ("NameLen", DWORD),
            ("MaxNameLen", DWORD),
            ("Name", c_char * MAX_SYM_NAME),
        ]

    dbghelp.SymInitialize.argtypes = [HANDLE, LPCSTR, BOOL]
    dbghelp.SymInitialize.restype = BOOL

    dbghelp.SymCleanup.argtypes = [HANDLE]
    dbghelp.SymCleanup.restype = BOOL

    dbghelp.SymSetOptions.argtypes = [DWORD]
    dbghelp.SymSetOptions.restype = DWORD

    dbghelp.SymFromAddr.argtypes = [HANDLE, c_ulonglong, POINTER(c_ulonglong), POINTER(SYMBOL_INFO)]
    dbghelp.SymFromAddr.restype = BOOL

    dbghelp.SymLoadModuleEx.argtypes = [
        HANDLE, HANDLE, LPCSTR, LPCSTR, c_ulonglong, DWORD, LPVOID, DWORD,
    ]
    dbghelp.SymLoadModuleEx.restype = c_ulonglong

    DBGHELP_AVAILABLE = True
except Exception:
    DBGHELP_AVAILABLE = False
    dbghelp = None

# ---------------------------------------------------------------------------
# Helper: protection flags to string
# ---------------------------------------------------------------------------

_PROT_MAP = {
    PAGE_NOACCESS: "---",
    PAGE_READONLY: "r--",
    PAGE_READWRITE: "rw-",
    PAGE_WRITECOPY: "rw-c",
    PAGE_EXECUTE: "--x",
    PAGE_EXECUTE_READ: "r-x",
    PAGE_EXECUTE_READWRITE: "rwx",
    PAGE_EXECUTE_WRITECOPY: "rwxc",
}

def prot_to_str(protect):
    """Convert a Windows memory protection constant to a readable string."""
    base = protect & 0xFF
    result = _PROT_MAP.get(base, f"?{protect:#x}")
    if protect & PAGE_GUARD:
        result += "+G"
    if protect & PAGE_NOCACHE:
        result += "+NC"
    return result

def mem_type_to_str(mtype):
    """Convert memory type to string."""
    if mtype == MEM_IMAGE:
        return "Image"
    elif mtype == MEM_MAPPED:
        return "Mapped"
    elif mtype == MEM_PRIVATE:
        return "Private"
    return f"?{mtype:#x}"

def mem_state_to_str(state):
    """Convert memory state to string."""
    if state == MEM_COMMIT:
        return "Commit"
    elif state == MEM_RESERVE:
        return "Reserve"
    elif state == MEM_FREE:
        return "Free"
    return f"?{state:#x}"

# ---------------------------------------------------------------------------
# INVALID_HANDLE_VALUE
# ---------------------------------------------------------------------------

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value  # 0xFFFFFFFFFFFFFFFF on 64-bit
