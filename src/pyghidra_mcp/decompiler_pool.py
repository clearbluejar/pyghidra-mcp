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
        self._created: list[DecompInterface] = []
        self._created_lock = threading.Lock()

    def _create(self) -> "DecompInterface":
        decompiler = self._factory()
        with self._created_lock:
            self._created.append(decompiler)
        return decompiler

    def _ensure_available(self) -> "DecompInterface":
        try:
            return self._queue.get_nowait()
        except queue.Empty:
            with self._created_lock:
                if len(self._created) < self._size:
                    pass
                else:
                    return self._queue.get()
            return self._create()

    @contextmanager
    def acquire(self):
        decompiler = self._ensure_available()
        try:
            yield decompiler
        finally:
            self._queue.put(decompiler)

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
            decompilers = list(self._created)
            self._created.clear()

        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break

        for decompiler in decompilers:
            for method_name in ("dispose", "closeProgram"):
                method = getattr(decompiler, method_name, None)
                if method is not None:
                    method()
                    break
