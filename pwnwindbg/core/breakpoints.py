"""Breakpoint management: INT3 software breakpoints."""

from .memory import read_memory, write_memory  # same package (core)


INT3 = b'\xCC'


class Breakpoint:
    """Represents a software breakpoint."""

    _next_id = 1

    def __init__(self, address, original_byte=None):
        self.id = Breakpoint._next_id
        Breakpoint._next_id += 1
        self.address = address
        self.original_byte = original_byte
        self.enabled = True
        self.hit_count = 0
        self.temporary = False  # For internal use (e.g., finish command)
        # Conditional BP: optional Python expression evaluated each hit.
        # If set and evaluates to a falsy value, the debugger silently
        # continues. See core/bp_conditions.py for the eval namespace.
        self.condition = None

    def __repr__(self):
        state = "enabled" if self.enabled else "disabled"
        cond = f" if {self.condition}" if self.condition else ""
        return f"BP#{self.id} @ {self.address:#x} ({state}, hits={self.hit_count}){cond}"


class BreakpointManager:
    """Manages software breakpoints via INT3 injection."""

    def __init__(self):
        self.breakpoints = {}  # address -> Breakpoint
        self.bp_by_id = {}     # id -> Breakpoint
        self.saved_addresses = set()  # addresses that persist across re-run/attach

    def add(self, process_handle, address, temporary=False):
        """Set a breakpoint at address. Returns the Breakpoint."""
        if address in self.breakpoints:
            bp = self.breakpoints[address]
            if not bp.enabled:
                self._enable(process_handle, bp)
            return bp

        # Read original byte
        orig = read_memory(process_handle, address, 1)
        bp = Breakpoint(address, original_byte=orig[0:1])
        bp.temporary = temporary

        # Write INT3
        write_memory(process_handle, address, INT3)

        self.breakpoints[address] = bp
        self.bp_by_id[bp.id] = bp
        return bp

    def save_address(self, address):
        """Mark an address as persistent (survives re-run/attach)."""
        self.saved_addresses.add(address)

    def unsave_address(self, address):
        """Remove an address from the persistent set."""
        self.saved_addresses.discard(address)

    def reapply_saved(self, process_handle):
        """Re-apply all saved breakpoints to a new process. Returns count applied."""
        count = 0
        for addr in list(self.saved_addresses):
            try:
                self.add(process_handle, addr)
                count += 1
            except Exception:
                pass  # address may not be mapped yet
        return count

    def remove(self, process_handle, bp_id):
        """Remove a breakpoint by ID."""
        if bp_id not in self.bp_by_id:
            return False
        bp = self.bp_by_id[bp_id]
        self._disable(process_handle, bp)
        self.saved_addresses.discard(bp.address)
        del self.breakpoints[bp.address]
        del self.bp_by_id[bp_id]
        return True

    def remove_by_address(self, process_handle, address):
        """Remove a breakpoint by address."""
        if address not in self.breakpoints:
            return False
        bp = self.breakpoints[address]
        return self.remove(process_handle, bp.id)

    def _enable(self, process_handle, bp):
        """Enable a breakpoint (write INT3)."""
        if not bp.enabled:
            write_memory(process_handle, bp.address, INT3)
            bp.enabled = True

    def _disable(self, process_handle, bp):
        """Disable a breakpoint (restore original byte)."""
        if bp.enabled and bp.original_byte:
            write_memory(process_handle, bp.address, bp.original_byte)
            bp.enabled = False

    def on_breakpoint_hit(self, process_handle, address):
        """Handle a breakpoint hit. Returns the Breakpoint or None."""
        if address not in self.breakpoints:
            return None
        bp = self.breakpoints[address]
        bp.hit_count += 1

        # Restore original byte so we can execute the real instruction
        self._disable(process_handle, bp)

        return bp

    def re_enable_after_single_step(self, process_handle, bp):
        """Re-enable a breakpoint after single-stepping past it."""
        if bp.temporary:
            # Remove temporary breakpoint
            if bp.address in self.breakpoints:
                del self.breakpoints[bp.address]
            if bp.id in self.bp_by_id:
                del self.bp_by_id[bp.id]
        else:
            self._enable(process_handle, bp)

    def get_by_address(self, address):
        """Get breakpoint at address, or None."""
        return self.breakpoints.get(address)

    def get_by_id(self, bp_id):
        """Get breakpoint by ID, or None."""
        return self.bp_by_id.get(bp_id)

    def list_all(self):
        """Return list of all breakpoints."""
        return list(self.bp_by_id.values())

    def disable_all(self, process_handle):
        """Disable all breakpoints."""
        for bp in self.breakpoints.values():
            self._disable(process_handle, bp)

    def enable_all(self, process_handle):
        """Enable all breakpoints."""
        for bp in self.breakpoints.values():
            self._enable(process_handle, bp)

    def clear_all(self, process_handle):
        """Remove all active breakpoints (saved addresses are preserved)."""
        for bp in list(self.breakpoints.values()):
            self._disable(process_handle, bp)
        self.breakpoints.clear()
        self.bp_by_id.clear()

    def clear_all_and_saved(self, process_handle):
        """Remove all breakpoints AND clear saved addresses."""
        self.clear_all(process_handle)
        self.saved_addresses.clear()
