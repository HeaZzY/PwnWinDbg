"""Hardware watchpoints via x86 debug registers DR0-DR3.

Each watchpoint occupies one of four hardware slots. DR0..DR3 hold the
target addresses, DR7 holds enable bits + per-slot type/length encoding,
and DR6 reports which slot fired on EXCEPTION_SINGLE_STEP.

Watchpoints are *per-thread*: setting DR0 only affects that one thread's
context. To behave like a process-wide watchpoint we keep an authoritative
table on the manager and re-apply it to every existing and newly-created
thread (via Debugger.apply_watchpoints_to_thread on CREATE_THREAD events).

DR7 layout (relevant bits)
--------------------------
  bit  0 (L0)        : local enable for slot 0
  bit  1 (G0)        : global enable for slot 0   ──────┐
  bits 2-7           : same for slots 1, 2, 3            │ enable bits
  bit  8 (LE) / 9 (GE) : exact data match enable        │
  bits 16-17 (R/W0)  : 00 exec, 01 write, 11 read+write │
  bits 18-19 (LEN0)  : 00 1B, 01 2B, 11 4B, 10 8B       │ slot 0 config
  bits 20-23         : R/W1 + LEN1                       │
  bits 24-27         : R/W2 + LEN2                       │ slots 1-3
  bits 28-31         : R/W3 + LEN3                       │

DR6 (status)
------------
  bits 0-3 (B0..B3)  : breakpoint condition detected on slot N

Caveats
-------
* x86 hardware does not support a watch-on-exec on a slot whose length
  is anything other than 1. We enforce that.
* Length-8 (`10`) only works on x86_64.
* DR6 is *not* automatically cleared by the CPU after a hit — we explicitly
  zero the B0..B3 bits in the new context written back to the thread.
"""

# Access type
WATCH_EXEC = "x"
WATCH_WRITE = "w"
WATCH_READ_WRITE = "rw"

_RW_BITS = {
    WATCH_EXEC: 0b00,
    WATCH_WRITE: 0b01,
    WATCH_READ_WRITE: 0b11,
}

_LEN_BITS = {
    1: 0b00,
    2: 0b01,
    4: 0b11,
    8: 0b10,  # x86_64 only
}

NUM_SLOTS = 4

# DR7 mask of "always on" reserved bits Windows expects to be set on x64
_DR7_RESERVED = 0x400


class Watchpoint:
    """A single hardware watchpoint occupying one DR slot."""

    _next_id = 1

    def __init__(self, slot, address, access, length):
        self.id = Watchpoint._next_id
        Watchpoint._next_id += 1
        self.slot = slot
        self.address = address
        self.access = access  # WATCH_*
        self.length = length
        self.enabled = True
        self.hit_count = 0

    def __repr__(self):
        access_label = {WATCH_EXEC: "exec", WATCH_WRITE: "write",
                        WATCH_READ_WRITE: "read+write"}[self.access]
        state = "enabled" if self.enabled else "disabled"
        return (f"WP#{self.id} slot={self.slot} {self.address:#x} "
                f"len={self.length} {access_label} ({state}, hits={self.hit_count})")


class WatchpointManager:
    """Tracks hardware watchpoint slot allocation across threads.

    The manager owns the *intent* (which slot holds what). Actually
    pushing the bits into a thread's CONTEXT is delegated to the caller
    (Debugger) which has access to thread handles and the WoW64 flag.
    """

    def __init__(self):
        self.slots = [None] * NUM_SLOTS  # slot_index -> Watchpoint
        self.by_id = {}                  # id -> Watchpoint

    def add(self, address: int, access: str, length: int) -> "Watchpoint":
        """Allocate a slot. Raises ValueError if no slot is free or args are bad."""
        if access not in _RW_BITS:
            raise ValueError(f"invalid access {access!r}, expected w/rw/x")
        if length not in _LEN_BITS:
            raise ValueError(f"invalid length {length}, expected 1/2/4/8")
        if access == WATCH_EXEC and length != 1:
            raise ValueError("execute watchpoints require length=1")
        if length > 1 and address % length != 0:
            raise ValueError(f"address {address:#x} is not {length}-byte aligned")

        # Find a free slot
        slot = next((i for i, w in enumerate(self.slots) if w is None), None)
        if slot is None:
            raise ValueError("no free hardware watchpoint slots (max 4)")

        wp = Watchpoint(slot, address, access, length)
        self.slots[slot] = wp
        self.by_id[wp.id] = wp
        return wp

    def remove_by_id(self, wp_id: int) -> bool:
        wp = self.by_id.pop(wp_id, None)
        if not wp:
            return False
        self.slots[wp.slot] = None
        return True

    def remove_by_address(self, address: int) -> bool:
        wp = next((w for w in self.slots if w and w.address == address), None)
        if not wp:
            return False
        return self.remove_by_id(wp.id)

    def list_all(self) -> list:
        return [w for w in self.slots if w is not None]

    def get_by_id(self, wp_id: int):
        return self.by_id.get(wp_id)

    # ------------------------------------------------------------------
    # Bit packing
    # ------------------------------------------------------------------

    def build_dr7(self) -> int:
        """Build the DR7 control word from current slot assignments."""
        dr7 = _DR7_RESERVED
        for slot, wp in enumerate(self.slots):
            if wp is None or not wp.enabled:
                continue
            # Local enable bit (use local rather than global so the watch
            # is cleared on context switch — we'll re-arm it ourselves
            # via apply_watchpoints_to_thread).
            dr7 |= 1 << (slot * 2)
            rw = _RW_BITS[wp.access]
            length = _LEN_BITS[wp.length]
            shift = 16 + slot * 4
            dr7 |= rw << shift
            dr7 |= length << (shift + 2)
        return dr7

    def slot_addresses(self) -> list:
        """Return [dr0, dr1, dr2, dr3] addresses (0 for empty slots)."""
        return [w.address if w else 0 for w in self.slots]

    def hit_slot(self, dr6: int):
        """Return the Watchpoint that fired given a DR6 value, or None.

        Multiple bits can theoretically be set if the same address triggers
        more than one watch — we return the first.
        """
        for slot in range(NUM_SLOTS):
            if dr6 & (1 << slot):
                wp = self.slots[slot]
                if wp:
                    wp.hit_count += 1
                    return wp
        return None
