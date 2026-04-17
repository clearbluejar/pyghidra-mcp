import sys
import types
from pathlib import Path
from unittest.mock import Mock

from pyghidra_mcp.gui_launcher import GuiPyGhidraMcpLauncher


def test_request_shutdown_closes_frontend_tool(monkeypatch):
    front_end_tool = Mock()

    app_info_module = types.ModuleType("ghidra.framework.main")
    app_info_module.AppInfo = types.SimpleNamespace(
        getFrontEndTool=lambda: front_end_tool,
    )

    swing_calls = []

    def run_later(callback):
        swing_calls.append(callback)
        callback()

    util_module = types.ModuleType("ghidra.util")
    util_module.Swing = types.SimpleNamespace(runLater=run_later)

    monkeypatch.setitem(sys.modules, "ghidra.framework.main", app_info_module)
    monkeypatch.setitem(sys.modules, "ghidra.util", util_module)

    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))
    launcher.request_shutdown()

    assert len(swing_calls) == 1
    front_end_tool.close.assert_called_once_with()


def test_launcher_accepts_user_agreement_vmarg():
    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))

    assert "-DUSER_AGREEMENT=ACCEPT" in launcher.vm_args


def test_request_shutdown_is_idempotent(monkeypatch):
    front_end_tool = Mock()

    app_info_module = types.ModuleType("ghidra.framework.main")
    app_info_module.AppInfo = types.SimpleNamespace(
        getFrontEndTool=lambda: front_end_tool,
    )

    util_module = types.ModuleType("ghidra.util")
    util_module.Swing = types.SimpleNamespace(runLater=lambda callback: callback())

    monkeypatch.setitem(sys.modules, "ghidra.framework.main", app_info_module)
    monkeypatch.setitem(sys.modules, "ghidra.util", util_module)

    launcher = GuiPyGhidraMcpLauncher(Path("/tmp/project.gpr"))
    launcher.request_shutdown()
    launcher.request_shutdown()

    front_end_tool.close.assert_called_once_with()
