import concurrent.futures
import signal
import threading
import time
from pathlib import Path
from typing import ClassVar
from unittest.mock import Mock

import click.testing
import pytest

import pyghidra_mcp.server as server
from pyghidra_mcp.indexing_mixin import IndexingMixin


def _common_kwargs():
    return {
        "mcp": Mock(),
        "transport": "stdio",
        "project_name": "proj",
        "project_directory": "/tmp/proj",
        "pyghidra_mcp_dir": Path("/tmp/proj-pyghidra-mcp"),
        "force_analysis": False,
        "verbose_analysis": False,
        "no_symbols": False,
        "gdts": [],
        "program_options_path": None,
        "gzfs_path": None,
        "threaded": True,
        "max_workers": 1,
        "wait_for_analysis": False,
        "list_project_binaries": False,
        "delete_project_binary": None,
        "symbols_path": None,
        "sym_file_path": None,
    }


def test_init_pyghidra_context_skips_full_analysis_for_existing_project(monkeypatch):
    fake_context = Mock()
    fake_context.import_binaries.return_value = []
    fake_context.list_binaries.return_value = ["/bin/existing"]

    monkeypatch.setattr(server, "pyghidra", Mock(start=Mock()))
    monkeypatch.setattr(server, "PyGhidraContext", Mock(return_value=fake_context))

    mcp = server.init_pyghidra_context(
        input_paths=[],
        **_common_kwargs(),
    )

    fake_context.analyze_project.assert_not_called()
    fake_context.schedule_startup_indexing.assert_called_once_with()
    assert mcp._pyghidra_context is fake_context


def test_init_pyghidra_context_analyzes_new_imports(monkeypatch):
    fake_context = Mock()
    fake_context.import_binaries.return_value = ["/bin/new"]
    fake_context.list_binaries.return_value = ["/bin/new"]

    monkeypatch.setattr(server, "pyghidra", Mock(start=Mock()))
    monkeypatch.setattr(server, "PyGhidraContext", Mock(return_value=fake_context))

    server.init_pyghidra_context(
        input_paths=[Path("/tmp/newbin")],
        **_common_kwargs(),
    )

    fake_context.analyze_project.assert_called_once_with()
    fake_context.schedule_indexing.assert_called_once_with("/bin/new")
    fake_context.schedule_startup_indexing.assert_not_called()


def test_init_pyghidra_context_wait_for_analysis_skips_background_indexing(monkeypatch):
    fake_context = Mock()
    fake_context.import_binaries.return_value = ["/bin/new"]
    fake_context.list_binaries.return_value = ["/bin/new"]

    monkeypatch.setattr(server, "pyghidra", Mock(start=Mock()))
    monkeypatch.setattr(server, "PyGhidraContext", Mock(return_value=fake_context))

    kwargs = _common_kwargs()
    kwargs["wait_for_analysis"] = True

    server.init_pyghidra_context(
        input_paths=[Path("/tmp/newbin")],
        **kwargs,
    )

    fake_context.analyze_project.assert_called_once_with()
    fake_context.schedule_indexing.assert_not_called()
    fake_context.schedule_startup_indexing.assert_not_called()


def test_init_pyghidra_context_wait_for_analysis_indexes_for_streamable_server(monkeypatch):
    fake_context = Mock()
    fake_context.import_binaries.return_value = ["/bin/new"]
    fake_context.list_binaries.return_value = ["/bin/new"]
    fake_context.programs = {"/bin/new": Mock()}

    monkeypatch.setattr(server, "pyghidra", Mock(start=Mock()))
    monkeypatch.setattr(server, "PyGhidraContext", Mock(return_value=fake_context))

    kwargs = _common_kwargs()
    kwargs["wait_for_analysis"] = True
    kwargs["transport"] = "streamable-http"

    server.init_pyghidra_context(
        input_paths=[Path("/tmp/newbin")],
        **kwargs,
    )

    fake_context.analyze_project.assert_called_once_with()
    fake_context.schedule_indexing.assert_not_called()
    fake_context.schedule_startup_indexing.assert_called_once_with(max_binaries=1)


class FakeLauncher:
    """Stands in for GuiPyGhidraMcpLauncher, recording lifecycle calls."""

    state: ClassVar[dict] = {}
    interrupt_on_event_loop = False

    def __init__(self, gpr_path):
        FakeLauncher.state["gpr_path"] = gpr_path

    def start(self):
        FakeLauncher.state["started"] = True

    def wait_for_front_end(self, timeout=120.0):
        FakeLauncher.state["waited_for_front_end"] = True
        return True

    def run_gui_event_loop(self):
        FakeLauncher.state["event_loop"] = True
        if FakeLauncher.interrupt_on_event_loop:
            self.interrupt()

    @property
    def interrupted(self):
        return bool(FakeLauncher.state.get("interrupted"))

    def interrupt(self):
        FakeLauncher.state["interrupted"] = True

    def request_shutdown(self):
        FakeLauncher.state["shutdown"] = True

    def wait_for_shutdown(self):
        return True


class FakeThread:
    def __init__(self, target, name, daemon):
        self.target = target
        self.name = name
        self.daemon = daemon

    def start(self):
        self.target()


def _patch_gui_mode(monkeypatch, interrupt_on_event_loop=False):
    """Wire GUI mode up to the fakes and return the launcher's state dict."""
    FakeLauncher.state = {}
    FakeLauncher.interrupt_on_event_loop = interrupt_on_event_loop

    monkeypatch.setattr(server, "register_gui_tools", Mock())
    monkeypatch.setattr(server, "ensure_macos_framework_python", Mock())
    monkeypatch.setattr(server, "GuiPyGhidraMcpLauncher", FakeLauncher)
    monkeypatch.setattr(server.threading, "Thread", FakeThread)
    monkeypatch.setattr(server, "init_gui_context", Mock())
    monkeypatch.setattr(server, "run_mcp_server", Mock())
    monkeypatch.setattr(server, "install_sigint_shutdown_handler", Mock())
    monkeypatch.setattr(server, "install_gui_console_ctrl_handler", Mock(return_value=None))
    monkeypatch.setattr(server, "remove_console_ctrl_handler", Mock())
    if hasattr(server.mcp, "_pyghidra_context"):
        delattr(server.mcp, "_pyghidra_context")
    return FakeLauncher.state


def _gui_cli_args(tmp_path):
    return [
        "--gui",
        "--transport",
        "http",
        "--project-path",
        str(tmp_path),
        "--project-name",
        "new_project",
    ]


def test_gui_mode_allows_missing_project_for_auto_create(monkeypatch, tmp_path):
    launcher_state = _patch_gui_mode(monkeypatch)

    runner = click.testing.CliRunner()
    result = runner.invoke(server.main, _gui_cli_args(tmp_path))

    assert result.exit_code == 0, result.output
    assert launcher_state["gpr_path"] == tmp_path / "new_project.gpr"
    assert launcher_state["started"] is True
    server.init_gui_context.assert_called_once()


def test_gui_mode_exits_130_when_the_console_handler_interrupts(monkeypatch, tmp_path):
    """A console-thread interrupt must end the run the same way Ctrl+C headless does."""
    launcher_state = _patch_gui_mode(monkeypatch, interrupt_on_event_loop=True)

    runner = click.testing.CliRunner()
    result = runner.invoke(server.main, _gui_cli_args(tmp_path))

    assert result.exit_code == 130, result.output
    assert launcher_state["shutdown"] is True
    server.remove_console_ctrl_handler.assert_called_once()


def test_headless_stdio_interrupt_closes_project_before_exiting(monkeypatch):
    class ForcedExitError(Exception):
        pass

    events = []
    context = Mock()
    context.close.side_effect = lambda: events.append("close")
    fake_mcp = Mock(_pyghidra_context=context)

    def interrupt(_mcp, _transport):
        events.append("interrupt")
        raise KeyboardInterrupt

    monkeypatch.setattr(server, "run_mcp_server", interrupt)

    def force_exit(code):
        events.append(("exit", code))
        raise ForcedExitError

    monkeypatch.setattr(server.os, "_exit", force_exit)

    with pytest.raises(ForcedExitError):
        server.run_headless_server(fake_mcp, "stdio")

    assert events == ["interrupt", "close", ("exit", 130)]


def test_headless_http_interrupt_uses_normal_system_exit(monkeypatch):
    context = Mock()
    fake_mcp = Mock(_pyghidra_context=context)
    monkeypatch.setattr(server, "run_mcp_server", Mock(side_effect=KeyboardInterrupt))
    forced_exit = Mock()
    monkeypatch.setattr(server.os, "_exit", forced_exit)

    with pytest.raises(SystemExit) as exc_info:
        server.run_headless_server(fake_mcp, "streamable-http")

    assert exc_info.value.code == 130
    context.close.assert_called_once_with()
    forced_exit.assert_not_called()


class TestSigintShutdownHandler:
    """Ctrl+C must reach Python (JPype hands SIGINT to the JVM otherwise)."""

    def test_first_interrupt_raises_keyboard_interrupt(self):
        handler = server._SigintShutdownHandler()

        with pytest.raises(KeyboardInterrupt):
            handler(signal.SIGINT, None)

    def test_second_interrupt_force_exits_with_130(self, monkeypatch):
        handler = server._SigintShutdownHandler()
        exits = []
        monkeypatch.setattr(server.os, "_exit", exits.append)

        with pytest.raises(KeyboardInterrupt):
            handler(signal.SIGINT, None)
        handler(signal.SIGINT, None)

        assert exits == [130]

    def test_install_registers_handler_and_restores_python_ownership(self):
        previous = signal.getsignal(signal.SIGINT)
        try:
            handler = server.install_sigint_shutdown_handler()
            assert signal.getsignal(signal.SIGINT) is handler
        finally:
            signal.signal(signal.SIGINT, previous)


class TestGuiConsoleCtrlHandler:
    """In GUI mode the Ghidra front end swallows CTRL_C_EVENT before Python sees it."""

    def test_first_interrupt_requests_shutdown_instead_of_raising(self, monkeypatch):
        handler = server._SigintShutdownHandler()
        writes = []
        monkeypatch.setattr(server.os, "write", lambda fd, data: writes.append(data))
        shutdowns = []

        on_interrupt = handler.on_console_interrupt(lambda: shutdowns.append(1))
        on_interrupt()  # a console callback has no frame to raise into

        assert shutdowns == [1]
        assert writes == [handler.GUI_FIRST_INTERRUPT]

    def test_second_interrupt_force_exits_with_130(self, monkeypatch):
        handler = server._SigintShutdownHandler()
        exits = []
        monkeypatch.setattr(server.os, "write", lambda fd, data: None)
        monkeypatch.setattr(server.os, "_exit", exits.append)

        on_interrupt = handler.on_console_interrupt(lambda: None)
        on_interrupt()
        on_interrupt()

        assert exits == [130]

    def test_escalation_is_shared_with_the_signal_path(self, monkeypatch):
        """A Ctrl+C on the console then one on the signal path still force-exits."""
        handler = server._SigintShutdownHandler()
        exits = []
        monkeypatch.setattr(server.os, "write", lambda fd, data: None)
        monkeypatch.setattr(server.os, "_exit", exits.append)

        handler.on_console_interrupt(lambda: None)()
        handler(signal.SIGINT, None)

        assert exits == [130]

    def test_install_is_skipped_when_the_front_end_never_starts(self, monkeypatch):
        monkeypatch.setattr(server.sys, "platform", "win32")
        installs = []
        monkeypatch.setattr(server, "install_console_ctrl_handler", installs.append)
        launcher = Mock()
        launcher.wait_for_front_end.return_value = False

        result = server.install_gui_console_ctrl_handler(launcher, server._SigintShutdownHandler())

        assert result is None
        assert installs == []

    def test_install_waits_for_the_front_end_before_registering(self, monkeypatch):
        monkeypatch.setattr(server.sys, "platform", "win32")
        order = []
        launcher = Mock()
        launcher.wait_for_front_end.side_effect = lambda *a, **k: order.append("wait") or True
        monkeypatch.setattr(
            server,
            "install_console_ctrl_handler",
            lambda on_interrupt: order.append("install") or "callback",
        )

        result = server.install_gui_console_ctrl_handler(launcher, server._SigintShutdownHandler())

        # Registering first would put us behind the front end in the LIFO chain.
        assert order == ["wait", "install"]
        assert result == "callback"

    def test_install_is_a_no_op_off_windows(self, monkeypatch):
        monkeypatch.setattr(server.sys, "platform", "linux")
        launcher = Mock()

        assert (
            server.install_gui_console_ctrl_handler(launcher, server._SigintShutdownHandler())
            is None
        )
        launcher.wait_for_front_end.assert_not_called()


class TestShutdownExecutor:
    """close() must drop queued work but never abandon an in-flight Ghidra task."""

    def test_cancels_queued_work_and_awaits_in_flight_work(self):
        running = threading.Event()
        finished = []

        def task(index):
            if index == 0:
                running.set()
                time.sleep(0.5)
            finished.append(index)

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        futures = [executor.submit(task, index) for index in range(4)]
        assert running.wait(5)

        IndexingMixin.shutdown_executor(object.__new__(IndexingMixin), "test", executor)

        assert finished == [0], "in-flight task was abandoned instead of awaited"
        assert all(future.cancelled() for future in futures[1:]), "queued work was not cancelled"

    def test_tolerates_a_missing_executor(self):
        IndexingMixin.shutdown_executor(object.__new__(IndexingMixin), "test", None)
