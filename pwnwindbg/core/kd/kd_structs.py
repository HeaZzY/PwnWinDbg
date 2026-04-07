"""KD protocol constants and structures."""

import struct

# ---------------------------------------------------------------------------
# Packet leaders
# ---------------------------------------------------------------------------
PACKET_LEADER         = 0x30303030   # "0000" — data packet
CONTROL_PACKET_LEADER = 0x69696969   # "iiii" — control packet
BREAKIN_PACKET_BYTE   = 0x62         # 'b'
PACKET_TRAILING_BYTE  = 0xAA

# ---------------------------------------------------------------------------
# Packet types
# ---------------------------------------------------------------------------
PACKET_TYPE_UNUSED              = 0
PACKET_TYPE_KD_STATE_CHANGE32   = 1
PACKET_TYPE_KD_STATE_MANIPULATE = 2
PACKET_TYPE_KD_DEBUG_IO         = 3
PACKET_TYPE_KD_ACKNOWLEDGE      = 4
PACKET_TYPE_KD_RESEND           = 5
PACKET_TYPE_KD_RESET            = 6
PACKET_TYPE_KD_STATE_CHANGE64   = 7
PACKET_TYPE_KD_POLL_BREAKIN     = 8
PACKET_TYPE_KD_TRACE_IO         = 9
PACKET_TYPE_KD_CONTROL_REQUEST  = 10
PACKET_TYPE_KD_FILE_IO          = 11

# ---------------------------------------------------------------------------
# Packet IDs
# ---------------------------------------------------------------------------
INITIAL_PACKET_ID = 0x80800000
SYNC_PACKET_ID    = 0x00000800

# ---------------------------------------------------------------------------
# State change types (target → debugger)
# ---------------------------------------------------------------------------
DbgKdExceptionStateChange   = 0x00003030
DbgKdLoadSymbolsStateChange = 0x00003031
DbgKdCommandStringStateChange = 0x00003032

# ---------------------------------------------------------------------------
# Manipulate state API numbers
# ---------------------------------------------------------------------------
DbgKdReadVirtualMemoryApi       = 0x00003130
DbgKdWriteVirtualMemoryApi      = 0x00003131
DbgKdGetContextApi              = 0x00003132
DbgKdSetContextApi              = 0x00003133
DbgKdWriteBreakPointApi         = 0x00003134
DbgKdRestoreBreakPointApi       = 0x00003135
DbgKdContinueApi                = 0x00003136
DbgKdReadControlSpaceApi        = 0x00003137
DbgKdWriteControlSpaceApi       = 0x00003138
DbgKdReadIoSpaceApi             = 0x00003139
DbgKdWriteIoSpaceApi            = 0x0000313A
DbgKdRebootApi                  = 0x0000313B
DbgKdContinueApi2               = 0x0000313C
DbgKdReadPhysicalMemoryApi      = 0x0000313D
DbgKdWritePhysicalMemoryApi     = 0x0000313E
DbgKdQuerySpecialCallsApi       = 0x0000313F
DbgKdSetSpecialCallApi          = 0x00003140
DbgKdClearSpecialCallsApi       = 0x00003141
DbgKdSetInternalBreakPointApi   = 0x00003142
DbgKdGetInternalBreakPointApi   = 0x00003143
DbgKdReadIoSpaceExtendedApi     = 0x00003144
DbgKdWriteIoSpaceExtendedApi    = 0x00003145
DbgKdGetVersionApi              = 0x00003146
DbgKdWriteBreakPointExApi       = 0x00003147
DbgKdRestoreBreakPointExApi     = 0x00003148
DbgKdCauseBugCheckApi           = 0x00003149
DbgKdSwitchProcessor            = 0x00003150
DbgKdPageInApi                  = 0x00003151
DbgKdReadMachineSpecificRegister  = 0x00003152
DbgKdWriteMachineSpecificRegister = 0x00003153
DbgKdSearchMemoryApi            = 0x00003156
DbgKdGetBusDataApi              = 0x00003159
DbgKdSetBusDataApi              = 0x0000315A
DbgKdFillMemoryApi              = 0x0000315B
DbgKdQueryMemoryApi             = 0x0000315C
DbgKdSwitchPartition            = 0x0000315D
DbgKdWriteCustomBreakPointApi   = 0x0000315E
DbgKdGetContextExApi            = 0x0000315F
DbgKdSetContextExApi            = 0x00003160

# ---------------------------------------------------------------------------
# Debug I/O types
# ---------------------------------------------------------------------------
DbgKdPrintStringApi = 0x00003230
DbgKdGetStringApi   = 0x00003231

# ---------------------------------------------------------------------------
# Continue statuses
# ---------------------------------------------------------------------------
DBG_CONTINUE                = 0x00010001
DBG_EXCEPTION_NOT_HANDLED   = 0x80010001
DBG_EXCEPTION_HANDLED       = 0x00010001

# ---------------------------------------------------------------------------
# Machine types
# ---------------------------------------------------------------------------
KD_MACH_I386  = 0x014C
KD_MACH_AMD64 = 0x8664
KD_MACH_IA64  = 0x0200
KD_MACH_ARM   = 0x01C0

# ---------------------------------------------------------------------------
# Version flags
# ---------------------------------------------------------------------------
DBGKD_VERS_FLAG_DATA  = 0x0002
DBGKD_VERS_FLAG_PTR64 = 0x0004

# ---------------------------------------------------------------------------
# KD max payload
# ---------------------------------------------------------------------------
KD_MAX_PAYLOAD = 0x800  # 2048 bytes

# ---------------------------------------------------------------------------
# Packet header: 16 bytes
#   leader (4) + type (2) + length (2) + id (4) + checksum (4)
# ---------------------------------------------------------------------------
KD_PACKET_HEADER_FORMAT = "<IHHII"
KD_PACKET_HEADER_SIZE   = struct.calcsize(KD_PACKET_HEADER_FORMAT)  # 16

# ---------------------------------------------------------------------------
# Manipulate state header: 56 bytes
#   ApiNumber (4) + ProcessorLevel (2) + Processor (2) + ReturnStatus (4) + Pad (4)
#   + Union (40 bytes)
# ---------------------------------------------------------------------------
KD_REQ_HEADER_SIZE = 56

# ---------------------------------------------------------------------------
# KDNET constants
# ---------------------------------------------------------------------------
KDNET_MAGIC   = 0x4D444247   # "GBDM"
KDNET_HMAC_SIZE = 16
KDNET_DATA_HEADER_SIZE = 8

# ---------------------------------------------------------------------------
# Context flags for GetContext
# ---------------------------------------------------------------------------
CONTEXT_AMD64             = 0x00100000
CONTEXT_AMD64_CONTROL     = CONTEXT_AMD64 | 0x0001
CONTEXT_AMD64_INTEGER     = CONTEXT_AMD64 | 0x0002
CONTEXT_AMD64_SEGMENTS    = CONTEXT_AMD64 | 0x0004
CONTEXT_AMD64_FLOATING    = CONTEXT_AMD64 | 0x0008
CONTEXT_AMD64_DEBUG_REGS  = CONTEXT_AMD64 | 0x0010
CONTEXT_AMD64_FULL        = CONTEXT_AMD64_CONTROL | CONTEXT_AMD64_INTEGER | CONTEXT_AMD64_FLOATING
CONTEXT_AMD64_ALL         = CONTEXT_AMD64_FULL | CONTEXT_AMD64_SEGMENTS | CONTEXT_AMD64_DEBUG_REGS

CONTEXT_I386              = 0x00010000
CONTEXT_I386_CONTROL      = CONTEXT_I386 | 0x0001
CONTEXT_I386_INTEGER      = CONTEXT_I386 | 0x0002
CONTEXT_I386_SEGMENTS     = CONTEXT_I386 | 0x0004
CONTEXT_I386_FLOATING     = CONTEXT_I386 | 0x0008
CONTEXT_I386_DEBUG_REGS   = CONTEXT_I386 | 0x0010
CONTEXT_I386_FULL         = CONTEXT_I386_CONTROL | CONTEXT_I386_INTEGER | CONTEXT_I386_SEGMENTS
CONTEXT_I386_ALL          = CONTEXT_I386_FULL | CONTEXT_I386_FLOATING | CONTEXT_I386_DEBUG_REGS

# ---------------------------------------------------------------------------
# AMD64 CONTEXT offsets (for parsing raw CONTEXT buffer)
# From ReactOS windbgkd.h / Microsoft CONTEXT structure
# ---------------------------------------------------------------------------
# AMD64 CONTEXT is ~1232 bytes.  Key register offsets:
AMD64_CONTEXT_OFFSETS = {
    # Header
    "ContextFlags": (0x030, "<I"),
    "MxCsr":        (0x034, "<I"),
    # Segment selectors
    "SegCs":   (0x038, "<H"),
    "SegDs":   (0x03A, "<H"),
    "SegEs":   (0x03C, "<H"),
    "SegFs":   (0x03E, "<H"),
    "SegGs":   (0x040, "<H"),
    "SegSs":   (0x042, "<H"),
    "EFlags":  (0x044, "<I"),
    # Debug registers
    "Dr0": (0x048, "<Q"),
    "Dr1": (0x050, "<Q"),
    "Dr2": (0x058, "<Q"),
    "Dr3": (0x060, "<Q"),
    "Dr6": (0x068, "<Q"),
    "Dr7": (0x070, "<Q"),
    # Integer registers
    "Rax": (0x078, "<Q"),
    "Rcx": (0x080, "<Q"),
    "Rdx": (0x088, "<Q"),
    "Rbx": (0x090, "<Q"),
    "Rsp": (0x098, "<Q"),
    "Rbp": (0x0A0, "<Q"),
    "Rsi": (0x0A8, "<Q"),
    "Rdi": (0x0B0, "<Q"),
    "R8":  (0x0B8, "<Q"),
    "R9":  (0x0C0, "<Q"),
    "R10": (0x0C8, "<Q"),
    "R11": (0x0D0, "<Q"),
    "R12": (0x0D8, "<Q"),
    "R13": (0x0E0, "<Q"),
    "R14": (0x0E8, "<Q"),
    "R15": (0x0F0, "<Q"),
    # Control
    "Rip": (0x0F8, "<Q"),
}

# i386 CONTEXT offsets
I386_CONTEXT_OFFSETS = {
    "ContextFlags": (0x00, "<I"),
    "Dr0": (0x04, "<I"),
    "Dr1": (0x08, "<I"),
    "Dr2": (0x0C, "<I"),
    "Dr3": (0x10, "<I"),
    "Dr6": (0x14, "<I"),
    "Dr7": (0x18, "<I"),
    "SegGs": (0x8C, "<I"),
    "SegFs": (0x90, "<I"),
    "SegEs": (0x94, "<I"),
    "SegDs": (0x98, "<I"),
    "Edi":   (0x9C, "<I"),
    "Esi":   (0xA0, "<I"),
    "Ebx":   (0xA4, "<I"),
    "Edx":   (0xA8, "<I"),
    "Ecx":   (0xAC, "<I"),
    "Eax":   (0xB0, "<I"),
    "Ebp":   (0xB4, "<I"),
    "Eip":   (0xB8, "<I"),
    "SegCs": (0xBC, "<I"),
    "EFlags":(0xC0, "<I"),
    "Esp":   (0xC4, "<I"),
    "SegSs": (0xC8, "<I"),
}
