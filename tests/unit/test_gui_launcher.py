import sys
import types
from pathlib import Path
from unittest.mock import Mock

import pytest

from pyghidra_mcp.gui_launcher import GuiPyGhidraMcpLauncher


class _FakeAssertError(Exception):
    """Stands in for ghidra.util.exception.AssertException."""


def _stub_ghidra(monkeypatch, get_front_end_tool, run_later=None):
    """Install the small slice of the ghidra namespace the launcher imports."""
    app_info_module = types.ModuleType("ghidra.framework.main")
    app_info_module.AppInfo = types.SimpleNamespace(getFrontEndTool=get_front_end_tool)

    exception_module = types.ModuleType("ghidra.util.exception")
    exception_module.AssertException = _FakeAssertError

    util_module = types.ModuleType("ghidra.util")
    util_module.Swing = types.SimpleNamespace(runLater=run_later or (lambda cb: cb()))

    monkeypatch.setitem(sys.modules, "ghidra.framework.main", app_info_module)
    monkeypatch.setitem(sys.modules, "ghidra.util", util_module)
    monkeypatch.setitem(sys.modules, "ghidra.util.exception", exception_module)


def test_request_shutdown_closes_frontend_tool(monkeypatch):
    front_end_tool = Mock()
    swing_calls = []

    def run_later(callback):
        swing_calls.append(callback)
        callback()

    _stub_ghidra(monkeypatch, lambda: front_end_tool, run_later)

    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))
    launcher.request_shutdown()

    assert len(swing_calls) == 1
    front_end_tool.close.assert_called_once_with()


def test_launcher_accepts_user_agreement_vmarg():
    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))

    assert "-DUSER_AGREEMENT=ACCEPT" in launcher.vm_args


def test_request_shutdown_is_idempotent(monkeypatch):
    front_end_tool = Mock()
    _stub_ghidra(monkeypatch, lambda: front_end_tool)

    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))
    launcher.request_shutdown()
    launcher.request_shutdown()

    front_end_tool.close.assert_called_once_with()


def test_front_end_tool_treats_assert_exception_as_not_ready(monkeypatch):
    """AppInfo asserts instead of returning null until the front end exists."""

    def raise_not_running():
        raise _FakeAssertError("Cannot use AppInfo without a Front End running")

    _stub_ghidra(monkeypatch, raise_not_running)

    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))

    assert launcher._front_end_tool() is None


def test_wait_for_front_end_returns_once_the_tool_appears(monkeypatch):
    front_end_tool = Mock()
    calls = []

    def get_front_end_tool():
        calls.append(1)
        if len(calls) < 3:
            raise _FakeAssertError("Cannot use AppInfo without a Front End running")
        return front_end_tool

    _stub_ghidra(monkeypatch, get_front_end_tool)

    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))

    assert launcher.wait_for_front_end(timeout=5.0) is True


def test_wait_for_front_end_gives_up_when_the_gui_never_starts(monkeypatch):
    def raise_not_running():
        raise _FakeAssertError("Cannot use AppInfo without a Front End running")

    _stub_ghidra(monkeypatch, raise_not_running)

    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))

    assert launcher.wait_for_front_end(timeout=0.5) is False


def test_wait_for_front_end_stops_when_the_gui_is_already_exiting(monkeypatch):
    _stub_ghidra(monkeypatch, Mock())

    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))
    launcher._is_exiting.set()

    assert launcher.wait_for_front_end(timeout=5.0) is False


def test_request_shutdown_without_a_front_end_does_not_raise(monkeypatch):
    def raise_not_running():
        raise _FakeAssertError("Cannot use AppInfo without a Front End running")

    _stub_ghidra(monkeypatch, raise_not_running)

    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))
    launcher.request_shutdown()  # must not propagate out of the Swing callback


def test_interrupt_releases_the_gui_event_loop():
    """A console-thread interrupt has to end the loop the GUI otherwise owns."""
    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))
    launcher.interrupt()

    assert launcher.interrupted is True
    launcher.run_gui_event_loop()  # returns instead of blocking on _is_exiting


def test_gui_event_loop_still_ends_on_a_normal_gui_exit():
    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))
    launcher._is_exiting.set()

    launcher.run_gui_event_loop()

    assert launcher.interrupted is False


@pytest.mark.skipif(sys.platform != "win32", reason="console handlers are Windows-only")
def test_console_ctrl_handler_round_trip():
    from pyghidra_mcp.gui_launcher import (
        install_console_ctrl_handler,
        remove_console_ctrl_handler,
    )

    fired = []
    callback = install_console_ctrl_handler(lambda: fired.append(1))

    assert callback is not None
    remove_console_ctrl_handler(callback)