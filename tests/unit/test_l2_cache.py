import os
import tempfile
import time

import pytest

from pyghidra_mcp.l2_cache import L2SQLiteCache, get_l2_cache


@pytest.fixture
def temp_cache():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_l2_cache.db")
        cache = L2SQLiteCache(db_path=db_path)
        yield cache
        cache.close()


def test_init_wal_and_sync(temp_cache: L2SQLiteCache):
    assert os.path.exists(temp_cache.db_path)
    with temp_cache._conn_ctx() as conn:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
        sync = conn.execute("PRAGMA synchronous").fetchone()[0]
        assert sync in (1, "1", "NORMAL", "normal")


def test_put_and_get_case_insensitive(temp_cache: L2SQLiteCache):
    now = time.time()
    payload = {
        "status": "ok",
        "name": "FUN_00401000",
        "code": "int main() { return 0; }",
        "signature": "int main(void)",
    }
    temp_cache.put("decompile", "TestBinary:0X00401000", payload, timestamp=now)

    # Fetch using lowercase
    ret1 = temp_cache.get("decompile", "testbinary:0x00401000")
    assert ret1 is not None
    assert ret1.get("l2_cached") is True
    assert ret1.get("code") == "int main() { return 0; }"
    assert ret1.get("name") == "FUN_00401000"
    assert ret1.get("signature") == "int main(void)"
    assert pytest.approx(ret1.get("l2_timestamp"), 0.1) == now

    # Fetch using original mixed case
    ret2 = temp_cache.get("decompile", "TestBinary:0X00401000")
    assert ret2 is not None
    assert ret2.get("code") == "int main() { return 0; }"


def test_get_miss_returns_none(temp_cache: L2SQLiteCache):
    assert temp_cache.get("decompile", "missing:0x1234") is None
    assert temp_cache.get("unknown_type", "0x0") is None


def test_evict_by_key(temp_cache: L2SQLiteCache):
    temp_cache.put("decompile", "bin:0x1000", {"code": "1"})
    temp_cache.put("decompile", "bin:0x2000", {"code": "2"})
    assert temp_cache.count() == 2

    evicted = temp_cache.evict(query_type="decompile", query_key="BIN:0x1000")
    assert evicted == 1
    assert temp_cache.get("decompile", "bin:0x1000") is None
    assert temp_cache.get("decompile", "bin:0x2000") is not None
    assert temp_cache.count() == 1


def test_evict_by_type(temp_cache: L2SQLiteCache):
    temp_cache.put("decompile", "bin:0x1000", {"code": "1"})
    temp_cache.put("decompile", "bin:0x2000", {"code": "2"})
    temp_cache.put("vtable", "bin:0x3000", {"vtable": "3"})
    assert temp_cache.count() == 3

    evicted = temp_cache.evict(query_type="decompile")
    assert evicted == 2
    assert temp_cache.count() == 1
    assert temp_cache.get("decompile", "bin:0x1000") is None
    assert temp_cache.get("vtable", "bin:0x3000") is not None


def test_evict_by_age(temp_cache: L2SQLiteCache):
    now = time.time()
    temp_cache.put("decompile", "bin:0x1000", {"code": "old"}, timestamp=now - 200.0)
    temp_cache.put("decompile", "bin:0x2000", {"code": "medium"}, timestamp=now - 50.0)
    temp_cache.put("decompile", "bin:0x3000", {"code": "new"}, timestamp=now)

    evicted = temp_cache.evict(older_than_sec=100.0)
    assert evicted == 1
    assert temp_cache.get("decompile", "bin:0x1000") is None
    assert temp_cache.get("decompile", "bin:0x2000") is not None
    assert temp_cache.get("decompile", "bin:0x3000") is not None


def test_evict_by_capacity(temp_cache: L2SQLiteCache):
    now = time.time()
    for i in range(8):
        temp_cache.put("decompile", f"bin:0x{i:04x}", {"idx": i}, timestamp=now + i)
    assert temp_cache.count() == 8

    evicted = temp_cache.evict(max_entries=3)
    assert evicted == 5
    assert temp_cache.count() == 3
    # Oldest 5 (0 to 4) evicted
    for i in range(5):
        assert temp_cache.get("decompile", f"bin:0x{i:04x}") is None
    # Newest 3 (5 to 7) remain
    for i in range(5, 8):
        assert temp_cache.get("decompile", f"bin:0x{i:04x}") is not None


def test_clear(temp_cache: L2SQLiteCache):
    temp_cache.put("decompile", "bin:0x1000", {"a": 1})
    temp_cache.put("decompile", "bin:0x2000", {"b": 2})
    assert temp_cache.count() == 2

    deleted = temp_cache.clear()
    assert deleted == 2
    assert temp_cache.count() == 0
    assert temp_cache.get("decompile", "bin:0x1000") is None


def test_get_l2_cache_singleton():
    cache1 = get_l2_cache()
    cache2 = get_l2_cache()
    assert cache1 is cache2
