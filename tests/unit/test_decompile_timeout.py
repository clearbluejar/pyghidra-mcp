import sys
import types
from contextlib import contextmanager
from unittest.mock import Mock

import pytest

from pyghidra_mcp.tools import DEFAULT_DECOMPILE_TIMEOUT_SECONDS, GhidraTools


def _install_task_monitor(monkeypatch):
    ghidra_module = types.ModuleType("ghidra")
    util_module = types.ModuleType("ghidra.util")
    task_module = types.ModuleType("ghidra.util.task")
    monitor = Mock()
    task_module.ConsoleTaskMonitor = Mock(return_value=monitor)

    monkeypatch.setitem(sys.modules, "ghidra", ghidra_module)
    monkeypatch.setitem(sys.modules, "ghidra.util", util_module)
    monkeypatch.setitem(sys.modules, "ghidra.util.task", task_module)
    return monitor


class _RecordingPool:
    def __init__(self, decompiler):
        self.decompiler = decompiler
        self.timeout = None

    @contextmanager
    def acquire(self, timeout=None):
        self.timeout = timeout
        yield self.decompiler


def _make_tools(pool):
    tools = GhidraTools.__new__(GhidraTools)
    tools.decompiler_pool = pool
    return tools


def test_decompile_uses_one_finite_budget_for_pool_and_ghidra(monkeypatch):
    monitor = _install_task_monitor(monkeypatch)
    decompiled = Mock()
    decompiled.getC.return_value = "int entry(void) { return 0; }"
    decompiled.getSignature.return_value = "int entry(void)"

    result = Mock()
    result.getErrorMessage.return_value = ""
    result.getDecompiledFunction.return_value = decompiled

    decompiler = Mock()
    decompiler.decompileFunction.return_value = result
    pool = _RecordingPool(decompiler)
    tools = _make_tools(pool)
    tools._get_filename = Mock(return_value="entry-1000")
    function = Mock()

    response = tools.decompile_function(function)

    assert pool.timeout == DEFAULT_DECOMPILE_TIMEOUT_SECONDS
    decompiler.decompileFunction.assert_called_once_with(
        function, DEFAULT_DECOMPILE_TIMEOUT_SECONDS, monitor
    )
    assert response.code == "int entry(void) { return 0; }"


def test_decompile_does_not_enter_ghidra_after_pool_budget_expires(monkeypatch):
    _install_task_monitor(monkeypatch)
    decompiler = Mock()
    pool = _RecordingPool(decompiler)
    tools = _make_tools(pool)
    function = Mock()
    monkeypatch.setattr("pyghidra_mcp.tools.time.monotonic", Mock(side_effect=[100, 131]))

    with pytest.raises(TimeoutError, match="Timed out waiting for a decompiler"):
        tools.decompile_function(function, timeout=30)

    assert pool.timeout == 30
    decompiler.decompileFunction.assert_not_called()


def test_decompile_rejects_unbounded_timeout(monkeypatch):
    _install_task_monitor(monkeypatch)
    tools = _make_tools(_RecordingPool(Mock()))

    with pytest.raises(ValueError, match="greater than zero"):
        tools.decompile_function(Mock(), timeout=0)
