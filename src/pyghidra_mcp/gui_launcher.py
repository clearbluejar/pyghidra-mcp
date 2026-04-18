import contextlib
import ctypes
import os
import sys
import threading
import time
from pathlib import Path

from pyghidra.launcher import PyGhidraLauncher, _PyGhidraStdOut

REEXEC_ENV = "PYGHIDRA_MCP_REEXEC"


def _framework_python_path() -> Path:
    return Path(sys.base_exec_prefix) / "Resources/Python.app/Contents/MacOS/Python"


def ensure_macos_framework_python() -> None:
    """Re-exec into framework Python before JVM startup when GUI mode needs it."""
    if sys.platform != "darwin":
        return

    if os.environ.get(REEXEC_ENV):
        # Python.app may preserve the venv's sys.executable after re-exec, so
        # sys.executable is not a reliable framework-Python check here.
        return

    framework_python = _framework_python_path()
    if not framework_python.exists():
        return

    if Path(sys.executable).resolve() == framework_python.resolve():
        return

    env = os.environ.copy()
    env[REEXEC_ENV] = "1"
    os.execve(
        str(framework_python),
        [sys.executable, "-m", "pyghidra_mcp", *sys.argv[1:]],
        env,
    )


class GuiPyGhidraMcpLauncher(PyGhidraLauncher):
    """PyGhidra GUI launcher adapted for MCP-driven lifecycle control."""

    def __init__(self, project_gpr_path: Path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_vmargs("-DUSER_AGREEMENT=ACCEPT")
        self.project_gpr_path = project_gpr_path
        self.args = []
        self._is_exiting = threading.Event()
        self._shutdown_requested = False

    def _launch(self) -> None:
        """Start the Ghidra GUI without blocking the caller."""
        from ghidra import Ghidra
        from java.lang import Runtime, Thread  # type: ignore

        if sys.platform == "win32":
            appid = ctypes.c_wchar_p(self.app_info.name)
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(appid)  # type: ignore[attr-defined]

        Runtime.getRuntime().addShutdownHook(Thread(self._is_exiting.set))

        stdout = _PyGhidraStdOut(sys.stdout)
        stderr = _PyGhidraStdOut(sys.stderr)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            Thread(
                lambda: Ghidra.main(["ghidra.GhidraRun", *self.args])  # pyright: ignore[reportArgumentType]
            ).start()

    def run_gui_event_loop(self) -> None:
        """Block until the GUI is shutting down."""

        if sys.platform == "darwin":
            from pyghidra.launcher import _run_mac_app

            _run_mac_app()

        self._is_exiting.wait()

    def request_shutdown(self) -> None:
        """Ask the running Ghidra front-end to close itself cleanly."""
        if self._shutdown_requested or self._is_exiting.is_set():
            return
        self._shutdown_requested = True

        from ghidra.framework.main import AppInfo
        from ghidra.util import Swing

        def do_close():
            front_end_tool = AppInfo.getFrontEndTool()
            if front_end_tool is not None:
                front_end_tool.close()

        Swing.runLater(do_close)

    def wait_for_shutdown(self, timeout: float = 5.0) -> bool:
        """Wait briefly for a clean GUI shutdown after requesting it."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._is_exiting.wait(timeout=0.1):
                return True
        return self._is_exiting.is_set()
