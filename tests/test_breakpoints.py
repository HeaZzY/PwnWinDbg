"""Unit tests for the software breakpoint manager."""

import pytest
from unittest.mock import MagicMock, call

from pwnwindbg.core.breakpoints import Breakpoint, BreakpointManager, INT3


class TestBreakpoint:
    """Tests for the Breakpoint data class."""

    def test_id_auto_increment(self):
        Breakpoint._next_id = 1
        bp1 = Breakpoint(0x401000)
        bp2 = Breakpoint(0x402000)
        assert bp1.id == 1
        assert bp2.id == 2

    def test_default_state(self):
        bp = Breakpoint(0x401000, original_byte=b"\x90")
        assert bp.enabled is True
        assert bp.hit_count == 0
        assert bp.temporary is False
        assert bp.condition is None
        assert bp.action is None
        assert bp.thread_id is None

    def test_repr_basic(self):
        bp = Breakpoint(0x401000)
        assert "BP#" in repr(bp)
        assert "0x401000" in repr(bp)

    def test_repr_with_condition(self):
        bp = Breakpoint(0x401000)
        bp.condition = "rax == 0"
        r = repr(bp)
        assert "if rax == 0" in r

    def test_repr_with_thread(self):
        bp = Breakpoint(0x401000)
        bp.thread_id = 1234
        r = repr(bp)
        assert "thread 1234" in r


class TestBreakpointManager:
    """Tests for BreakpointManager using mocked process handles."""

    @pytest.fixture
    def mgr(self):
        return BreakpointManager()

    @pytest.fixture
    def mock_proc(self):
        """Return a mock process handle (just an int)."""
        return 0xDEADBEEF

    def test_add_breakpoint(self, mgr, mock_proc, monkeypatch):
        """Adding a BP should write INT3 and store the original byte."""
        orig_byte = b"\x90"
        written = []

        def fake_read(ph, addr, size):
            return orig_byte

        def fake_write(ph, addr, data):
            written.append((addr, data))

        monkeypatch.setattr("pwnwindbg.core.breakpoints.read_memory", fake_read)
        monkeypatch.setattr("pwnwindbg.core.breakpoints.write_memory", fake_write)

        bp = mgr.add(mock_proc, 0x401000)

        assert bp.address == 0x401000
        assert bp.original_byte == orig_byte
        assert bp.enabled is True
        assert bp in mgr.list_all()
        assert mgr.get_by_address(0x401000) is bp
        assert mgr.get_by_id(bp.id) is bp
        # INT3 should have been written
        assert written == [(0x401000, INT3)]

    def test_remove_breakpoint(self, mgr, mock_proc, monkeypatch):
        """Removing a BP should restore the original byte."""
        restored = []

        def fake_read(ph, addr, size):
            return b"\x90"

        def fake_write(ph, addr, data):
            restored.append((addr, data))

        monkeypatch.setattr("pwnwindbg.core.breakpoints.read_memory", fake_read)
        monkeypatch.setattr("pwnwindbg.core.breakpoints.write_memory", fake_write)

        bp = mgr.add(mock_proc, 0x401000)
        assert len(mgr.list_all()) == 1

        ok = mgr.remove(mock_proc, bp.id)
        assert ok is True
        assert len(mgr.list_all()) == 0
        # Original byte should have been restored on removal
        assert any(addr == 0x401000 and data == b"\x90" for addr, data in restored)

    def test_remove_unknown_id(self, mgr, mock_proc):
        assert mgr.remove(mock_proc, 999) is False

    def test_remove_by_address(self, mgr, mock_proc, monkeypatch):
        def fake_read(ph, addr, size):
            return b"\x90"

        def fake_write(ph, addr, data):
            pass

        monkeypatch.setattr("pwnwindbg.core.breakpoints.read_memory", fake_read)
        monkeypatch.setattr("pwnwindbg.core.breakpoints.write_memory", fake_write)

        bp = mgr.add(mock_proc, 0x401000)
        assert mgr.remove_by_address(mock_proc, 0x401000) is True
        assert mgr.get_by_address(0x401000) is None

    def test_re_enable_after_hit(self, mgr, mock_proc, monkeypatch):
        """When a BP is hit, it is disabled; re-enable should write INT3 again."""
        writes = []

        def fake_read(ph, addr, size):
            return b"\x90"

        def fake_write(ph, addr, data):
            writes.append((addr, data))

        monkeypatch.setattr("pwnwindbg.core.breakpoints.read_memory", fake_read)
        monkeypatch.setattr("pwnwindbg.core.breakpoints.write_memory", fake_write)

        bp = mgr.add(mock_proc, 0x401000)
        writes.clear()

        # Simulate hit
        mgr.on_breakpoint_hit(mock_proc, 0x401000)
        assert bp.enabled is False
        assert bp.hit_count == 1

        # Re-enable
        mgr.re_enable_after_single_step(mock_proc, bp)
        assert bp.enabled is True
        assert writes == [(0x401000, INT3)]

    def test_temporary_breakpoint_removed_after_step(self, mgr, mock_proc, monkeypatch):
        """Temporary BPs should be deleted after stepping over them."""

        def fake_read(ph, addr, size):
            return b"\x90"

        def fake_write(ph, addr, data):
            pass

        monkeypatch.setattr("pwnwindbg.core.breakpoints.read_memory", fake_read)
        monkeypatch.setattr("pwnwindbg.core.breakpoints.write_memory", fake_write)

        bp = mgr.add(mock_proc, 0x401000, temporary=True)
        assert bp.temporary is True
        assert len(mgr.list_all()) == 1

        mgr.re_enable_after_single_step(mock_proc, bp)
        assert len(mgr.list_all()) == 0
        assert mgr.get_by_id(bp.id) is None

    def test_saved_addresses_persist(self, mgr, mock_proc, monkeypatch):
        """Saved addresses should survive clear_all and be re-applied."""

        def fake_read(ph, addr, size):
            return b"\x90"

        def fake_write(ph, addr, data):
            pass

        monkeypatch.setattr("pwnwindbg.core.breakpoints.read_memory", fake_read)
        monkeypatch.setattr("pwnwindbg.core.breakpoints.write_memory", fake_write)

        bp = mgr.add(mock_proc, 0x401000)
        mgr.save_address(0x401000)
        mgr.clear_all(mock_proc)
        assert len(mgr.list_all()) == 0

        # Re-apply saved
        count = mgr.reapply_saved(mock_proc)
        assert count == 1
        assert mgr.get_by_address(0x401000) is not None

    def test_disable_all(self, mgr, mock_proc, monkeypatch):
        restores = []

        def fake_read(ph, addr, size):
            return b"\x90"

        def fake_write(ph, addr, data):
            restores.append((addr, data))

        monkeypatch.setattr("pwnwindbg.core.breakpoints.read_memory", fake_read)
        monkeypatch.setattr("pwnwindbg.core.breakpoints.write_memory", fake_write)

        mgr.add(mock_proc, 0x401000)
        mgr.add(mock_proc, 0x402000)
        restores.clear()

        mgr.disable_all(mock_proc)
        assert len(restores) == 2
        assert all(data == b"\x90" for _, data in restores)

    def test_clear_all_and_saved(self, mgr, mock_proc, monkeypatch):
        def fake_read(ph, addr, size):
            return b"\x90"

        def fake_write(ph, addr, data):
            pass

        monkeypatch.setattr("pwnwindbg.core.breakpoints.read_memory", fake_read)
        monkeypatch.setattr("pwnwindbg.core.breakpoints.write_memory", fake_write)

        mgr.add(mock_proc, 0x401000)
        mgr.save_address(0x401000)
        mgr.clear_all_and_saved(mock_proc)
        assert len(mgr.saved_addresses) == 0
        assert mgr.reapply_saved(mock_proc) == 0
