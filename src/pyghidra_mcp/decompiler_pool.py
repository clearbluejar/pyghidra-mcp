from __future__ import annotations

import logging
import os
import queue
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ghidra.app.decompiler import DecompInterface

logger = logging.getLogger("pyghidra_mcp.decompiler_pool")


class DecompilerPool:
    """
    Thread-safe pooling, lifecycle management, and resource governance for
    Ghidra DecompInterface instances.
    """

    def __init__(
        self,
        factory: Callable[[], "DecompInterface"],
        *,
        size: int = 1,
        program: Any | None = None,
        idle_timeout_sec: float = 120.0,
        resource_mode: str = "balanced",
        l2_cache: Any | None = None,
    ) -> None:
        self._factory = factory
        self._size = max(1, size)
        self._queue: queue.LifoQueue[DecompInterface] = queue.LifoQueue(maxsize=self._size)
        self._slots = threading.BoundedSemaphore(value=self._size)
        self._created: list[DecompInterface] = []
        self._created_lock = threading.Lock()
        self._closed = False

        self._program = program
        self._l2_cache = l2_cache
        self.resource_mode = resource_mode.lower().strip()
        self.idle_timeout_sec = float(idle_timeout_sec)
        self._is_hibernating = False
        self._hibernated_decompilers: set[int] = set()
        self._in_use_count = 0
        self._last_active_time = time.monotonic()

        self._watchdog_stop = threading.Event()
        self._watchdog_thread: threading.Thread | None = None
        self._start_watchdog()

    @property
    def is_hibernating(self) -> bool:
        return self._is_hibernating

    @is_hibernating.setter
    def is_hibernating(self, value: bool) -> None:
        with self._created_lock:
            self._is_hibernating = value
            if value:
                self._hibernated_decompilers.update(id(d) for d in self._created)
            else:
                self._hibernated_decompilers.clear()

    def _start_watchdog(self) -> None:
        """Starts watchdog reaper thread monitoring native decompiler idle timeout."""
        with self._created_lock:
            if self._closed:
                return
            if self._watchdog_thread is None or not self._watchdog_thread.is_alive():
                self._watchdog_stop.clear()
                self._watchdog_thread = threading.Thread(
                    target=self._watchdog_loop,
                    name="DecompilerReaperWatchdog",
                    daemon=True,
                )
                self._watchdog_thread.start()

    def _watchdog_loop(self) -> None:
        """Polls periodically to reap/hibernate idle native decompiler subprocesses."""
        while not self._watchdog_stop.wait(2.0):
            if self._closed:
                break
            if self.idle_timeout_sec <= 0:
                continue  # Turbo mode: permanently warm / disabled

            idle_duration = time.monotonic() - self._last_active_time
            should_hibernate = False
            with self._created_lock:
                if (
                    not self._is_hibernating
                    and self._in_use_count == 0
                    and len(self._created) > 0
                    and idle_duration >= self.idle_timeout_sec
                ):
                    should_hibernate = True

            if should_hibernate:
                logger.info(
                    "Decompiler idle for %.1fs >= %.1fs. Hibernating native process...",
                    idle_duration,
                    self.idle_timeout_sec,
                )
                self.hibernate()

    def hibernate(self) -> dict[str, Any]:
        """
        Forces immediate native decompiler hibernation & RAM release (Section 8.2).
        Calls decompiler.flushCache(), decompiler.stopProcess(), and triggers System.gc().
        """
        with self._created_lock:
            for decompiler in self._created:
                try:
                    flush = getattr(decompiler, "flushCache", None)
                    if flush is not None:
                        flush()
                except Exception as e:
                    logger.debug("decompiler.flushCache() error: %s", e)
                try:
                    stop = getattr(decompiler, "stopProcess", None)
                    if stop is not None:
                        stop()
                except Exception as e:
                    logger.debug("decompiler.stopProcess() notice: %s", e)
            self._is_hibernating = True
            self._hibernated_decompilers.update(id(d) for d in self._created)

        # Trigger JVM garbage collection safely to release unused native pages
        try:
            import java.lang.System

            java.lang.System.gc()
        except Exception:
            pass

        return {
            "status": "ok",
            "message": "Native decompiler process hibernated; idle RAM reclaimed via System.gc()",
            "is_hibernating": True,
        }

    def _rearm_decompiler(self, decompiler: "DecompInterface") -> None:
        prog = None
        if hasattr(decompiler, "getProgram"):
            try:
                prog = decompiler.getProgram()
            except Exception:
                pass
        if prog is None:
            prog = self._program

        if prog is not None and hasattr(decompiler, "openProgram"):
            try:
                decompiler.openProgram(prog)
            except Exception as e:
                logger.debug("Failed to openProgram during re-arm: %s", e)
        elif hasattr(decompiler, "resetDecompiler"):
            try:
                decompiler.resetDecompiler()
            except Exception:
                pass

    def rearm(self) -> None:
        """Explicitly re-arms all created decompiler instances and wakes the pool."""
        with self._created_lock:
            for decompiler in self._created:
                self._rearm_decompiler(decompiler)
            self._hibernated_decompilers.clear()
            self._is_hibernating = False

    def set_resource_mode(self, mode: str) -> dict[str, Any]:
        """
        Hot-swaps running daemon between eco, balanced, turbo, and auto resource profiles.
        Adjusts idle_timeout_sec, CPU core affinity, and process priority.
        """
        mode_lower = mode.lower().strip()
        target_affinity = None
        target_priority = None

        if mode_lower == "eco":
            self.resource_mode = "eco"
            self.idle_timeout_sec = 15.0
            target_affinity = [0]
            target_priority = "below_normal"
        elif mode_lower == "balanced":
            self.resource_mode = "balanced"
            self.idle_timeout_sec = 120.0
            avail_cores = list(range(min(2, os.cpu_count() or 2)))
            target_affinity = avail_cores
            target_priority = "below_normal"
        elif mode_lower == "turbo":
            self.resource_mode = "turbo"
            self.idle_timeout_sec = 0.0  # 0s / disabled
            all_cores = list(range(os.cpu_count() or 8))
            target_affinity = all_cores
            target_priority = "normal"
        elif mode_lower == "auto":
            self.resource_mode = "auto"
            self.idle_timeout_sec = 60.0
            auto_cores = list(range(min(4, os.cpu_count() or 4)))
            target_affinity = auto_cores
            target_priority = "normal"
        else:
            return {
                "status": "error",
                "message": f"Unknown mode '{mode}'. Choose from: eco, balanced, turbo, auto",
            }

        try:
            import psutil

            p = psutil.Process()
            if target_affinity is not None:
                p.cpu_affinity(target_affinity)
            if target_priority == "below_normal":
                p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if os.name == "nt" else 10)
            elif target_priority == "normal":
                p.nice(psutil.NORMAL_PRIORITY_CLASS if os.name == "nt" else 0)
        except Exception as e:
            logger.debug("psutil resource adaptation notice: %s", e)

        return {
            "status": "ok",
            "mode": self.resource_mode,
            "idle_timeout_sec": self.idle_timeout_sec,
            "message": f"Decompiler pool resource mode updated to '{self.resource_mode}'",
        }

    def _create(self) -> "DecompInterface":
        decompiler = self._factory()
        with self._created_lock:
            if not self._closed:
                self._created.append(decompiler)
                if self._program is None and hasattr(decompiler, "getProgram"):
                    try:
                        self._program = decompiler.getProgram()
                    except Exception:
                        pass
                return decompiler

        self._dispose_one(decompiler)
        raise RuntimeError("Decompiler pool is closed")

    def _ensure_available(self) -> "DecompInterface":
        try:
            return self._queue.get_nowait()
        except queue.Empty:
            return self._create()

    @contextmanager
    def acquire(self, timeout: float | None = None):
        if timeout is not None and timeout < 0:
            raise ValueError("Decompiler pool timeout must be non-negative")

        with self._created_lock:
            if self._closed:
                raise RuntimeError("Decompiler pool is closed")

        if not self._slots.acquire(timeout=timeout):
            raise TimeoutError(f"Timed out waiting for a decompiler after {timeout:g} seconds")

        decompiler = None
        try:
            decompiler = self._ensure_available()
            with self._created_lock:
                self._in_use_count += 1
                self._last_active_time = time.monotonic()
                if self._is_hibernating or id(decompiler) in self._hibernated_decompilers:
                    self._rearm_decompiler(decompiler)
                    self._hibernated_decompilers.discard(id(decompiler))
                    if not self._hibernated_decompilers:
                        self._is_hibernating = False
            yield decompiler
        finally:
            try:
                if decompiler is not None:
                    with self._created_lock:
                        if not self._closed:
                            self._queue.put_nowait(decompiler)
            finally:
                with self._created_lock:
                    self._in_use_count = max(0, self._in_use_count - 1)
                    self._last_active_time = time.monotonic()
                self._slots.release()

    def invalidate_all(self) -> None:
        with self._created_lock:
            decompilers = list(self._created)

        for decompiler in decompilers:
            for method_name in ("flushCache", "resetDecompiler"):
                method = getattr(decompiler, method_name, None)
                if method is not None:
                    method()
                    break

        if self._l2_cache is not None:
            try:
                self._l2_cache.evict(query_type="decompile")
            except Exception as e:
                logger.debug("Failed to evict L2 cache in invalidate_all: %s", e)

    def dispose(self) -> None:
        self._watchdog_stop.set()
        if self._watchdog_thread is not None and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=1.0)

        with self._created_lock:
            self._closed = True
            decompilers = list(self._created)
            self._created.clear()
            self._hibernated_decompilers.clear()

            while True:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    break

        for decompiler in decompilers:
            self._dispose_one(decompiler)

    @staticmethod
    def _dispose_one(decompiler: "DecompInterface") -> None:
        for method_name in ("dispose", "closeProgram"):
            method = getattr(decompiler, method_name, None)
            if method is not None:
                method()
                break
