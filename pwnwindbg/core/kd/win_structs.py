"""Windows kernel struct offsets (x64).

EPROCESS field offsets shift between Windows builds. We provide three
known-good offset sets and pick at runtime based on the OS build number
read from KUSER_SHARED_DATA+0x260.

Supported groups:
    - Win10 1809   (build 17763)         — RS5
    - Win10 1903+  (builds 18362-18363)  — 19H1/19H2
    - Win10 21H1+  (builds 19041+ and Win11)
"""


# Default class is mutated at runtime by `select_offsets_for_build()`
# so existing imports of `EPROCESS.UniqueProcessId` keep working.
class EPROCESS:
    Pcb                       = 0x000
    UniqueProcessId           = 0x440
    ActiveProcessLinks        = 0x448
    Token                     = 0x4b8
    InheritedFromUniqueProcessId = 0x540
    ImageFileName             = 0x5a8   # CHAR[15]
    ThreadListHead            = 0x5e0


# Per-build offset tables (only fields that differ across versions)
_EPROCESS_OFFSETS = {
    # Win10 1809 RS5 — build 17763
    "win10_rs5": {
        "UniqueProcessId":              0x2e0,
        "ActiveProcessLinks":           0x2e8,
        "Token":                        0x358,
        "InheritedFromUniqueProcessId": 0x3e0,
        "ImageFileName":                0x450,
        "ThreadListHead":               0x488,
    },
    # Win10 1903 / 1909 — builds 18362, 18363
    "win10_19h1": {
        "UniqueProcessId":              0x2e8,
        "ActiveProcessLinks":           0x2f0,
        "Token":                        0x360,
        "InheritedFromUniqueProcessId": 0x3e8,
        "ImageFileName":                0x450,
        "ThreadListHead":               0x488,
    },
    # Win10 2004 / 20H2 / 21H1 / 21H2 / 22H2  +  Win11 21H2 / 22H2 / 23H2 / 24H2
    "win10_21h1_plus": {
        "UniqueProcessId":              0x440,
        "ActiveProcessLinks":           0x448,
        "Token":                        0x4b8,
        "InheritedFromUniqueProcessId": 0x540,
        "ImageFileName":                0x5a8,
        "ThreadListHead":               0x5e0,
    },
}


def _group_for_build(build):
    if build <= 0:
        return "win10_21h1_plus"      # safe-ish default
    if build <= 17763:
        return "win10_rs5"
    if build < 19041:
        return "win10_19h1"
    return "win10_21h1_plus"


def select_offsets_for_build(build):
    """Mutate EPROCESS class fields in-place to match the given build.

    Returns the chosen group name (for logging).
    """
    group = _group_for_build(build)
    table = _EPROCESS_OFFSETS[group]
    for name, value in table.items():
        setattr(EPROCESS, name, value)
    return group


# _KPROCESS (embedded at EPROCESS+0)
class KPROCESS:
    DirectoryTableBase = 0x028  # CR3 for this process
    ThreadListHead     = 0x030  # _LIST_ENTRY of _KTHREAD


# _KTHREAD (embedded at ETHREAD+0)
class KTHREAD:
    Process              = 0x220  # PKPROCESS
    StackBase            = 0x038
    StackLimit           = 0x030
    KernelStack          = 0x058
    KernelApcDisable     = 0x1e4  # for proper SYSRET cleanup


# _ETHREAD (x64)
class ETHREAD:
    Tcb                  = 0x000  # _KTHREAD (embedded)
    Cid                  = 0x650  # _CLIENT_ID { UniqueProcess, UniqueThread }
    ThreadListEntry      = 0x4e8  # _LIST_ENTRY (linked through ThreadListHead in EPROCESS)
    TrapFrame           = 0x090  # _KTRAP_FRAME* - for SYSRET cleanup


# _KTRAP_FRAME (x64) - saved userland state for SYSRET
class KTRAP_FRAME:
    Rbp                  = 0x158
    Rip                  = 0x168
    EFlags               = 0x178
    Rsp                  = 0x180


# _KPCR / _KPRCB (per-CPU control structures, addressed via gs_base)
class KPCR:
    Self                 = 0x018  # ptr to self
    CurrentPrcb          = 0x020  # ptr to KPRCB
    Prcb                 = 0x180  # embedded KPRCB
    IdtBase              = 0x038  # for read_idt_base


class KPRCB:
    CurrentThread        = 0x008  # PKTHREAD
    NextThread           = 0x010
    IdleThread           = 0x018


# _TOKEN (selected fields)
class TOKEN:
    TokenId              = 0x028  # _LUID
    Privileges           = 0x040  # _SEP_TOKEN_PRIVILEGES { Present, Enabled, EnabledByDefault }
    SessionId            = 0x208


# Bitmask to strip the EX_FAST_REF reference count from a Token pointer
TOKEN_REF_MASK = ~0xF & 0xFFFFFFFFFFFFFFFF


# Per-build overrides for offsets that drift between Windows versions.
# Empty for now — Win10/11 share the offsets above.
WIN_BUILD_OVERRIDES = {
    # build_number: { "EPROCESS.Token": 0x4b8, ... }
}


def offsets_for_build(build_number: int):
    """Return a dict of overridden offsets for the given Windows build.

    Currently a no-op stub — Win10 1809 → Win11 24H2 share the offsets above.
    """
    return WIN_BUILD_OVERRIDES.get(build_number, {})
