import queue
import threading
from collections.abc import Callable
from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.app.decompiler import DecompInterface


class DecompilerPool:
    def __init__(
        self,
        factory: Callable[[], "DecompInterface"],
        *,
        size: int = 1,
    ) -> None:
        self._factory = factory
        self._size = max(1, size)
        self._queue: queue.LifoQueue[DecompInterface] = queue.LifoQueue(maxsize=self._size)
        self._slots = threading.BoundedSemaphore(value=self._size)
        self._created: list[DecompInterface] = []
        self._created_lock = threading.Lock()
        self._closed = False

    def _create(self) -> "DecompInterface":
        decompiler = self._factory()
        with self._created_lock:
            if not self._closed:
                self._created.append(decompiler)
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
            yield decompiler
        finally:
            try:
                if decompiler is not None:
                    with self._created_lock:
                        if not self._closed:
                            self._queue.put_nowait(decompiler)
            finally:
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

    def dispose(self) -> None:
        with self._created_lock:
            self._closed = True
            decompilers = list(self._created)
            self._created.clear()

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
