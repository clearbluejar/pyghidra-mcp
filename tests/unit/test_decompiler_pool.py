import threading
import time

import pytest

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


def test_acquire_times_out_when_pool_is_exhausted():
    pool = DecompilerPool(object, size=1)

    with pool.acquire():
        started = time.monotonic()
        with pytest.raises(TimeoutError, match="Timed out waiting for a decompiler"):
            with pool.acquire(timeout=0.05):
                pytest.fail("exhausted pool unexpectedly yielded a decompiler")

    assert time.monotonic() - started < 0.5


def test_slow_factory_does_not_prevent_another_caller_timing_out():
    factory_started = threading.Event()
    release_factory = threading.Event()
    creator_finished = threading.Event()

    def factory():
        factory_started.set()
        assert release_factory.wait(timeout=1)
        return object()

    pool = DecompilerPool(factory, size=1)

    def create_first_decompiler():
        with pool.acquire(timeout=1):
            pass
        creator_finished.set()

    creator = threading.Thread(target=create_first_decompiler, daemon=True)
    creator.start()
    assert factory_started.wait(timeout=1)

    started = time.monotonic()
    with pytest.raises(TimeoutError, match="Timed out waiting for a decompiler"):
        with pool.acquire(timeout=0.05):
            pytest.fail("reserved pool slot unexpectedly became available")
    assert time.monotonic() - started < 0.5

    release_factory.set()
    creator.join(timeout=1)
    assert creator_finished.is_set()


def test_factory_failure_releases_pool_capacity():
    attempts = 0

    def factory():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("factory failed")
        return object()

    pool = DecompilerPool(factory, size=1)

    with pytest.raises(RuntimeError, match="factory failed"):
        with pool.acquire(timeout=0.05):
            pass

    with pool.acquire(timeout=0.05) as decompiler:
        assert decompiler is not None

    assert attempts == 2
