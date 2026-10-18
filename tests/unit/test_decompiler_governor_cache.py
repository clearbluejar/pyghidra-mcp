import os
import tempfile
import time
from unittest.mock import MagicMock

import pytest

from pyghidra_mcp.decompiler_pool import DecompilerPool
from pyghidra_mcp.l2_cache import L2SQLiteCache
from pyghidra_mcp.models import DecompiledFunction
from pyghidra_mcp.tools import GhidraTools


class MockDecompiler:
    def __init__(self, program=None):
        self.program = program
        self.flushed = False
        self.stopped = False
        self.opened_programs = []

    def flushCache(self):
        self.flushed = True

    def stopProcess(self):
        self.stopped = True

    def getProgram(self):
        return self.program

    def openProgram(self, prog):
        self.opened_programs.append(prog)
        self.program = prog

    def decompileFunction(self, func, timeout, monitor):
        res = MagicMock()
        res.getErrorMessage.return_value = ""
        decomp = MagicMock()
        decomp.getC.return_value = "int target_fn() { return 42; }"
        decomp.getSignature.return_value = "int target_fn(void)"
        res.getDecompiledFunction.return_value = decomp
        return res


def test_decompiler_pool_resource_modes():
    pool = DecompilerPool(lambda: MockDecompiler(), size=1)
    try:
        assert pool.resource_mode == "balanced"
        assert pool.idle_timeout_sec == 120.0

        # Eco
        res_eco = pool.set_resource_mode("eco")
        assert res_eco["status"] == "ok"
        assert pool.resource_mode == "eco"
        assert pool.idle_timeout_sec == 15.0

        # Turbo
        res_turbo = pool.set_resource_mode("turbo")
        assert res_turbo["status"] == "ok"
        assert pool.resource_mode == "turbo"
        assert pool.idle_timeout_sec == 0.0

        # Auto
        res_auto = pool.set_resource_mode("auto")
        assert res_auto["status"] == "ok"
        assert pool.resource_mode == "auto"
        assert pool.idle_timeout_sec == 60.0

        # Invalid mode
        res_inv = pool.set_resource_mode("hyperdrive")
        assert res_inv["status"] == "error"
        assert "Unknown mode" in res_inv["message"]
        assert pool.resource_mode == "auto"
    finally:
        pool.dispose()


def test_decompiler_pool_hibernate_mechanics():
    mock_decomp = MockDecompiler()
    pool = DecompilerPool(lambda: mock_decomp, size=1)
    try:
        # Pre-create instance by acquiring once
        with pool.acquire():
            pass

        assert not pool.is_hibernating
        res = pool.hibernate()
        assert res["status"] == "ok"
        assert res["is_hibernating"] is True
        assert pool.is_hibernating is True
        assert mock_decomp.flushed is True
        assert mock_decomp.stopped is True
    finally:
        pool.dispose()


def test_decompiler_pool_rearm_on_acquire():
    mock_prog = object()
    mock_decomp = MockDecompiler(program=mock_prog)
    pool = DecompilerPool(lambda: mock_decomp, size=1, program=mock_prog)
    try:
        with pool.acquire():
            pass

        pool.hibernate()
        assert pool.is_hibernating is True
        assert mock_decomp.stopped is True

        # Acquire while hibernating must auto re-arm
        with pool.acquire() as decomp:
            assert decomp is mock_decomp
            assert not pool.is_hibernating
            assert mock_prog in mock_decomp.opened_programs
    finally:
        pool.dispose()


def test_decompiler_pool_watchdog_reaps_idle():
    mock_decomp = MockDecompiler()
    # 0.1s idle timeout for immediate testing
    pool = DecompilerPool(lambda: mock_decomp, size=1, idle_timeout_sec=0.1)
    try:
        with pool.acquire():
            pass

        assert not pool.is_hibernating
        # Wait for watchdog to trigger hibernation (polls every 2.0s, wait up to 4s)
        start = time.time()
        while time.time() - start < 4.0:
            if pool.is_hibernating:
                break
            time.sleep(0.1)

        assert pool.is_hibernating is True
        assert mock_decomp.flushed is True
        assert mock_decomp.stopped is True
    finally:
        pool.dispose()


def test_ghidra_tools_decompile_cache_hit_bypasses_decompiler():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_tools_cache.db")
        cache = L2SQLiteCache(db_path=db_path)

        mock_prog = MagicMock()
        mock_prog.getName.return_value = "TestBinary.exe"

        mock_pool = MagicMock()

        prog_info = MagicMock()
        prog_info.program = mock_prog
        prog_info.decompiler_pool = mock_pool

        tools = GhidraTools(prog_info, l2_cache=cache)

        mock_func = MagicMock()
        mock_entry = MagicMock()
        mock_entry.toString.return_value = "0x00401000"
        mock_func.getEntryPoint.return_value = mock_entry

        cache_key = "testbinary.exe:0x00401000"
        cache.put(
            "decompile",
            cache_key,
            {
                "status": "ok",
                "name": "target_fn",
                "code": "void cached_code() { return; }",
                "signature": "void cached_code(void)",
            },
        )

        res = tools.decompile_function(mock_func)
        assert isinstance(res, DecompiledFunction)
        assert res.code == "void cached_code() { return; }"
        assert res.signature == "void cached_code(void)"
        # Critical verification: Java decompiler pool was completely bypassed!
        mock_pool.acquire.assert_not_called()
        cache.close()


def test_ghidra_tools_decompile_cache_miss_populates_l2(monkeypatch):
    import sys
    import types

    ghidra_module = types.ModuleType("ghidra")
    util_module = types.ModuleType("ghidra.util")
    task_module = types.ModuleType("ghidra.util.task")
    task_module.ConsoleTaskMonitor = MagicMock()
    monkeypatch.setitem(sys.modules, "ghidra", ghidra_module)
    monkeypatch.setitem(sys.modules, "ghidra.util", util_module)
    monkeypatch.setitem(sys.modules, "ghidra.util.task", task_module)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_tools_cache_miss.db")
        cache = L2SQLiteCache(db_path=db_path)

        mock_prog = MagicMock()
        mock_prog.getName.return_value = "TestBinary.exe"

        mock_decomp = MockDecompiler(program=mock_prog)
        real_pool = DecompilerPool(lambda: mock_decomp, size=1)

        prog_info = MagicMock()
        prog_info.program = mock_prog
        prog_info.decompiler_pool = real_pool

        tools = GhidraTools(prog_info, l2_cache=cache)

        mock_func = MagicMock()
        mock_entry = MagicMock()
        mock_entry.toString.return_value = "0x00402000"
        mock_func.getEntryPoint.return_value = mock_entry
        mock_func.getSymbol().getName.return_value = "FUN_00402000"
        mock_func.entryPoint = "0x00402000"

        cache_key = "testbinary.exe:0x00402000"
        assert cache.get("decompile", cache_key) is None

        res = tools.decompile_function(mock_func)
        assert res.code == "int target_fn() { return 42; }"

        # Check that L2 cache was populated
        cached = cache.get("decompile", cache_key)
        assert cached is not None
        assert cached.get("l2_cached") is True
        assert cached.get("code") == "int target_fn() { return 42; }"
        assert cached.get("signature") == "int target_fn(void)"

        real_pool.dispose()
        cache.close()


def test_ghidra_tools_eviction_on_symbol_change():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_tools_eviction.db")
        cache = L2SQLiteCache(db_path=db_path)

        mock_prog = MagicMock()
        mock_prog.getName.return_value = "TestBinary.exe"

        mock_pool = MagicMock()
        prog_info = MagicMock()
        prog_info.program = mock_prog
        prog_info.decompiler_pool = mock_pool

        tools = GhidraTools(prog_info, l2_cache=cache)

        mock_func = MagicMock()
        mock_entry = MagicMock()
        mock_entry.toString.return_value = "0x00403000"
        mock_func.getEntryPoint.return_value = mock_entry

        cache_key = "testbinary.exe:0x00403000"
        cache.put("decompile", cache_key, {"code": "initial_code"})
        assert cache.get("decompile", cache_key) is not None

        # Evict specific function
        evicted = tools.evict_function_cache(mock_func)
        assert evicted == 1
        assert cache.get("decompile", cache_key) is None

        # Re-populate and test invalidate_decompiler_cache
        cache.put("decompile", cache_key, {"code": "new_code"})
        assert cache.get("decompile", cache_key) is not None

        tools.invalidate_decompiler_cache()
        assert cache.get("decompile", cache_key) is None
        mock_pool.invalidate_all.assert_called_once()

        cache.close()
