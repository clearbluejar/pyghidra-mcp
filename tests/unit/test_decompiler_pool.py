import threading
import time

from pyghidra_mcp.decompiler_pool import DecompilerPool


def test_concurrent_acquire_never_overcreates_or_blocks_return():
    worker_count = 8
    pool_size = 2
    start = threading.Barrier(worker_count)
    created = []
    created_lock = threading.Lock()
    completed = []

    def factory():
        time.sleep(0.05)
        instance = object()
        with created_lock:
            created.append(instance)
        return instance

    pool = DecompilerPool(factory, size=pool_size)

    def worker():
        start.wait()
        with pool.acquire():
            time.sleep(0.01)
        completed.append(True)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(worker_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert len(completed) == worker_count
    assert len(created) == pool_size
    assert all(not thread.is_alive() for thread in threads)
