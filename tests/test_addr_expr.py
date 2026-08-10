"""Unit tests for the address expression evaluator."""

import pytest
from unittest.mock import MagicMock

from pwnwindbg.utils.addr_expr import eval_expr
from pwnwindbg.core.debugger import DebuggerState


class MockSymbolManager:
    """Minimal symbol manager for testing."""

    def __init__(self, mappings=None):
        self._map = mappings or {}

    def resolve_name_to_address(self, name):
        return self._map.get(name)


@pytest.fixture
def stopped_debugger():
    """Return a mocked debugger in STOPPED state with some registers."""
    dbg = MagicMock()
    dbg.state = DebuggerState.STOPPED
    dbg.get_registers.return_value = (
        {"rax": 0x41414141, "rsp": 0x7FFF0000, "rip": 0x401000},
        set(),
    )
    dbg.symbols = MockSymbolManager({"ntdll": 0x77000000, "kernel32": 0x75000000})
    return dbg


class TestEvalExprLiterals:
    """Tests for hex/decimal literals."""

    def test_hex_literal(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "0x401000") == 0x401000

    def test_decimal_literal(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "12345") == 12345

    def test_hex_with_uppercase(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "0xDEADBEEF") == 0xDEADBEEF

    def test_empty_string(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "") is None

    def test_whitespace_only(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "   ") is None


class TestEvalExprRegisters:
    """Tests for register resolution."""

    def test_register_rax(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "rax") == 0x41414141

    def test_register_rsp(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "rsp") == 0x7FFF0000

    def test_register_dollar_prefix(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "$rax") == 0x41414141

    def test_register_case_insensitive(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "RAX") == 0x41414141
        assert eval_expr(stopped_debugger, "RaX") == 0x41414141

    def test_unknown_register(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "xmm0") is None

    def test_unknown_dollar_register(self, stopped_debugger):
        """$unknown should NOT fall back to symbol lookup."""
        assert eval_expr(stopped_debugger, "$nosuchreg") is None


class TestEvalExprArithmetic:
    """Tests for +/- arithmetic."""

    def test_add_offset(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "0x401000+0x10") == 0x401010

    def test_sub_offset(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "0x401000-0x10") == 0x400FF0

    def test_register_plus_offset(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "rax+8") == 0x41414149

    def test_register_minus_offset(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "rsp-0x100") == 0x7FFEFF00

    def test_chained_arithmetic(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "0x1000+0x10-0x8") == 0x1008


class TestEvalExprSymbols:
    """Tests for module/symbol resolution."""

    def test_module_name(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "ntdll") == 0x77000000

    def test_module_plus_offset(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "ntdll+0x1000") == 0x77001000

    def test_unknown_symbol(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "nosuchmodule") is None


class TestEvalExprGdbCompat:
    """Tests for GDB-style prefixes."""

    def test_ampersand_prefix(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "&0x401000") == 0x401000

    def test_star_prefix(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "*0x401000") == 0x401000

    def test_star_prefix_register(self, stopped_debugger):
        assert eval_expr(stopped_debugger, "*rax") == 0x41414141


class TestEvalExprRunningState:
    """Tests when the debugger is NOT stopped."""

    def test_register_when_running(self):
        dbg = MagicMock()
        dbg.state = DebuggerState.RUNNING
        # Register lookup should fail because we are not stopped
        assert eval_expr(dbg, "rax") is None

    def test_literal_when_running(self):
        dbg = MagicMock()
        dbg.state = DebuggerState.RUNNING
        # Literals should still work
        assert eval_expr(dbg, "0x401000") == 0x401000
