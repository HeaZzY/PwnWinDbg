"""Build a runtime Nt syscall-number table by parsing live ntdll stubs.

The standard x64 `Nt*` export starts with:

    4c 8b d1                  mov  r10, rcx
    b8 NN NN 00 00            mov  eax, NN
    f6 04 25 08 03 fe 7f 01   test byte ptr [SharedUserData+0x308], 1
    75 03                     jne  +3
    0f 05                     syscall
    c3                        ret

So the syscall number is the dword immediately after `mov r10, rcx;
mov eax,` — at byte offset 4 of the stub. We validate the prologue
bytes (`4c 8b d1 b8`) before trusting the result; anything that
doesn't match is silently skipped, which keeps Wow64 thunks, hooked
exports, and unrelated `Nt*` symbols out of the table.

The table is built lazily on first access and cached on the symbol
manager so subsequent calls are O(1). Restart / reattach invalidates
the cache via `invalidate()`.
"""

import struct

from .memory import read_memory_safe


# x64 stub prologue: mov r10, rcx ; mov eax, imm32
_X64_PROLOGUE = b"\x4c\x8b\xd1\xb8"


class NtSyscallTable:
    """Maps syscall number <-> Nt* function name for the live ntdll."""

    def __init__(self):
        self.num_to_name = {}     # int -> "NtClose"
        self.name_to_num = {}     # "ntclose" -> int
        self.built = False

    def build(self, debugger):
        """Walk every ntdll!Nt* export, extract its syscall number.

        Returns the count of resolved syscalls. Skips exports whose
        prologue doesn't match the expected `mov r10,rcx; mov eax,`
        pattern — that filters out Nt* symbols that aren't real
        syscalls (e.g. NtCurrentTeb is an inline) and any export
        whose stub has been hooked.
        """
        if not debugger.process_handle:
            return 0
        if debugger.is_wow64:
            return 0  # x64 stub layout only

        debugger.symbols._ensure_exports_loaded()
        ph = debugger.process_handle

        seen = set()
        for key, (mod_name, func_name, addr) in \
                debugger.symbols._export_by_name.items():
            if "!" in key:
                continue
            if mod_name.lower() != "ntdll.dll":
                continue
            if not func_name.startswith("Nt"):
                continue
            if addr in seen:
                continue
            seen.add(addr)

            stub = read_memory_safe(ph, addr, 8)
            if not stub or len(stub) < 8:
                continue
            if stub[:4] != _X64_PROLOGUE:
                continue
            ssn = struct.unpack("<I", stub[4:8])[0]
            # Sanity: real syscall numbers fit in a couple of thousand;
            # if we read garbage we'd see huge values.
            if ssn > 0xFFFF:
                continue
            self.num_to_name[ssn] = func_name
            self.name_to_num[func_name.lower()] = ssn

        self.built = True
        return len(self.num_to_name)

    def lookup_num(self, ssn):
        """Return the function name for `ssn`, or None."""
        return self.num_to_name.get(ssn)

    def lookup_name(self, name):
        """Return the syscall number for `name` (case-insensitive), or None."""
        if not name:
            return None
        return self.name_to_num.get(name.lower())

    def invalidate(self):
        self.num_to_name.clear()
        self.name_to_num.clear()
        self.built = False
