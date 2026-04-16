import os
import sys
import threading
import time
from pathlib import Path

from pyghidra.launcher import DeferredPyGhidraLauncher

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


class GuiPyGhidraMcpLauncher(DeferredPyGhidraLauncher):
    """Deferred PyGhidra launcher that runs Ghidra GUI as the blocking foreground app."""

    def __init__(self, project_gpr_path: Path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.args = [str(project_gpr_path.absolute())]
        self._is_exiting = threading.Event()
        self._shutdown_requested = False

    def run_gui_event_loop(self) -> None:
        """Initialize the Ghidra GUI and block until the JVM is shutting down."""
        from java.lang import Runtime, Thread  # type: ignore

        Runtime.getRuntime().addShutdownHook(Thread(self._is_exiting.set))

        self.initialize_ghidra(headless=False)

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
