import contextlib
import ctypes
import logging
import os
import sys
import threading
import time
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path

from pyghidra.launcher import PyGhidraLauncher, _PyGhidraStdOut

REEXEC_ENV = "PYGHIDRA_MCP_REEXEC"

logger = logging.getLogger(__name__)

if sys.platform == "win32":
    _CONSOLE_CTRL_ROUTINE = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    CTRL_C_EVENT = 0
    CTRL_BREAK_EVENT = 1
else:  # pragma: no cover - the console handler is a Windows-only concept
    _CONSOLE_CTRL_ROUTINE = None
    CTRL_C_EVENT = 0
    CTRL_BREAK_EVENT = 1


def install_console_ctrl_handler(on_interrupt: Callable[[], None]) -> object | None:
    """Claim Ctrl+C from the Ghidra GUI by registering a native console handler.

    Windows dispatches console control handlers in reverse registration order and
    stops at the first one returning TRUE. Starting the Ghidra front end registers
    a handler that swallows CTRL_C_EVENT, so the Python-level ``SIGINT`` handler --
    registered back when the interpreter started -- is never reached. Registering
    here, *after* the front end is up, puts us at the head of that chain.

    ``on_interrupt`` runs on a console-callback thread owned by the OS, so it must
    return quickly and must not touch Java; signal a waiting thread instead.
    Returns the callback object, which the caller must keep alive for as long as
    the handler is registered, or ``None`` on non-Windows platforms.
    """
    if sys.platform != "win32":
        return None

    def handler(ctrl_type: int) -> bool:
        if ctrl_type not in (CTRL_C_EVENT, CTRL_BREAK_EVENT):
            return False  # let close/logoff/shutdown fall through to the GUI
        on_interrupt()
        return True

    callback = _CONSOLE_CTRL_ROUTINE(handler)
    if not ctypes.windll.kernel32.SetConsoleCtrlHandler(callback, True):
        raise OSError(ctypes.get_last_error(), "SetConsoleCtrlHandler failed")
    return callback


def remove_console_ctrl_handler(callback: object | None) -> None:
    """Unregister a handler from ``install_console_ctrl_handler``.

    Dropping the reference without this leaves Windows holding a pointer to a
    freed ctypes callback, so a late Ctrl+C would land in freed memory.
    """
    if callback is None or sys.platform != "win32":
        return
    if not ctypes.windll.kernel32.SetConsoleCtrlHandler(callback, False):
        logger.warning(
            "Could not unregister the Ctrl+C console handler (error %s).", ctypes.get_last_error()
        )


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
        self._interrupted = threading.Event()
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

    def _front_end_tool(self):
        """Return the front-end tool, or None while the GUI is still starting.

        ``AppInfo.getFrontEndTool()`` asserts rather than returning null before
        the front end exists, so "not up yet" arrives as an exception.
        """
        from ghidra.framework.main import AppInfo
        from ghidra.util.exception import AssertException

        try:
            return AppInfo.getFrontEndTool()
        except AssertException:
            return None

    def wait_for_front_end(self, timeout: float = 120.0) -> bool:
        """Wait until the Ghidra front-end tool exists, so the GUI is really up."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._is_exiting.is_set():
                return False
            if self._front_end_tool() is not None:
                return True
            time.sleep(0.25)
        logger.warning("Ghidra front end was not up after %.0fs.", timeout)
        return False

    def interrupt(self) -> None:
        """Wake ``run_gui_event_loop`` the way a Ctrl+C on the console should."""
        self._interrupted.set()

    @property
    def interrupted(self) -> bool:
        return self._interrupted.is_set()

    def run_gui_event_loop(self) -> None:
        """Block until the GUI is shutting down, or until we are interrupted."""

        if sys.platform == "darwin" and not (
            self._is_exiting.is_set() or self._interrupted.is_set()
        ):
            from pyghidra.launcher import _run_mac_app

            _run_mac_app()

        # Polled rather than a plain wait(): either event ends the loop, and the
        # interrupt one is set from a console-callback thread.
        while not (self._is_exiting.is_set() or self._interrupted.is_set()):
            self._is_exiting.wait(timeout=0.2)

    def request_shutdown(self) -> None:
        """Ask the running Ghidra front-end to close itself cleanly."""
        if self._shutdown_requested or self._is_exiting.is_set():
            return
        self._shutdown_requested = True

        from ghidra.util import Swing

        def do_close():
            front_end_tool = self._front_end_tool()
            if front_end_tool is None:
                logger.warning("No Ghidra front end to close; it never finished starting.")
                return
            front_end_tool.close()

        Swing.runLater(do_close)

    def wait_for_shutdown(self, timeout: float = 5.0) -> bool:
        """Wait briefly for a clean GUI shutdown after requesting it."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._is_exiting.wait(timeout=0.1):
                return True
        return self._is_exiting.is_set()
