"""Unit tests for cancelling in-flight auto-analysis on shutdown.

Ghidra runs auto-analysis inside one transaction and cannot be saved from another
thread, so a server cannot abandon it mid-write. The only safe way to shorten a
wait is to cancel the monitor the analyzers poll; these tests cover that plumbing
without a Ghidra runtime (the ghidra modules are stubbed).
"""

import sys
import types
from unittest.mock import Mock

import pytest

import pyghidra_mcp.indexing_mixin as indexing_mixin
from pyghidra_mcp.indexing_mixin import (
    IndexingMixin,
    cancel_active_analyses,
    register_analysis_monitor,
    unregister_analysis_monitor,
)


@pytest.fixture(autouse=True)
def _clear_registry():
    indexing_mixin._ACTIVE_ANALYSIS_MONITORS.clear()
    yield
    indexing_mixin._ACTIVE_ANALYSIS_MONITORS.clear()


def test_cancel_active_analyses_is_a_noop_without_registered_monitors():
    assert cancel_active_analyses() == 0


def test_registered_monitors_are_cancelled_and_unregistered_ones_are_not():
    monitor = Mock()
    gone = Mock()
    register_analysis_monitor(monitor)
    register_analysis_monitor(gone)
    unregister_analysis_monitor(gone)

    assert cancel_active_analyses() == 1
    monitor.cancel.assert_called_once_with()
    gone.cancel.assert_not_called()


def test_a_monitor_that_fails_to_cancel_does_not_abort_the_others():
    broken = Mock()
    broken.cancel.side_effect = RuntimeError("boom")
    healthy = Mock()
    register_analysis_monitor(broken)
    register_analysis_monitor(healthy)

    assert cancel_active_analyses() == 2
    healthy.cancel.assert_called_once_with()


def test_shutdown_cancels_analysis_before_waiting():
    calls = []
    monitor = Mock()
    monitor.cancel.side_effect = lambda: calls.append("cancel")
    register_analysis_monitor(monitor)

    executor = Mock()
    executor.shutdown.side_effect = lambda **kwargs: calls.append("shutdown")

    mixin = IndexingMixin.__new__(IndexingMixin)
    mixin.shutdown_executor("analysis", executor)

    assert calls == ["cancel", "shutdown"]
    assert executor.shutdown.call_args.kwargs == {"wait": True, "cancel_futures": True}


def test_shutdown_of_other_executors_leaves_analysis_alone():
    monitor = Mock()
    register_analysis_monitor(monitor)

    mixin = IndexingMixin.__new__(IndexingMixin)
    mixin.shutdown_executor("indexing", Mock())

    monitor.cancel.assert_not_called()


def _stub_ghidra(monkeypatch, manager, monitor):
    """Put just enough of the ghidra package tree into sys.modules."""
    ghidra = types.ModuleType("ghidra")
    app = types.ModuleType("ghidra.app")
    plugin = types.ModuleType("ghidra.app.plugin")
    core = types.ModuleType("ghidra.app.plugin.core")
    analysis = types.ModuleType("ghidra.app.plugin.core.analysis")
    direct = types.ModuleType("ghidra.app.plugin.core.analysis.direct")
    analysis.AutoAnalysisManager = Mock()
    analysis.AutoAnalysisManager.getAnalysisManager.return_value = manager
    util = types.ModuleType("ghidra.util")
    task = types.ModuleType("ghidra.util.task")
    task.DummyCancellableTaskMonitor = Mock(return_value=monitor)

    for name, module in (
        ("ghidra", ghidra),
        ("ghidra.app", app),
        ("ghidra.app.plugin", plugin),
        ("ghidra.app.plugin.core", core),
        ("ghidra.app.plugin.core.analysis", analysis),
        ("ghidra.app.plugin.core.analysis.direct", direct),
        ("ghidra.util", util),
        ("ghidra.util.task", task),
    ):
        monkeypatch.setitem(sys.modules, name, module)


def test_analysis_runs_through_the_three_calls_analyze_all_makes(monkeypatch):
    from pyghidra_mcp.context import _analyze_all

    manager = Mock()
    monitor = Mock()
    monitor.isCancelled.return_value = False
    _stub_ghidra(monkeypatch, manager, monitor)

    program = Mock()
    assert _analyze_all(program) is True

    manager.initializeOptions.assert_called_once_with()
    manager.reAnalyzeAll.assert_called_once_with(None)
    manager.startAnalysis.assert_called_once_with(monitor, True)


def test_cancelled_analysis_reports_false_and_is_unregistered(monkeypatch):
    from pyghidra_mcp.context import _analyze_all

    manager = Mock()
    monitor = Mock()
    monitor.isCancelled.return_value = True
    _stub_ghidra(monkeypatch, manager, monitor)

    assert _analyze_all(Mock()) is False
    # The run is over: nothing may be cancelled again on the next shutdown.
    assert cancel_active_analyses() == 0
