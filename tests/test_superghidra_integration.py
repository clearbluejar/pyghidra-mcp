"""
test_superghidra_integration.py
================================
Integration test suite verifying SuperGhidra architectural upgrades in pyghidra-mcp:
1. L2SQLiteCache Standalone (storing, retrieving, evicting, clearing, WAL mode, synchronous).
2. DecompilerPool Governor & Hibernate:
   - set_resource_mode ('eco', 'balanced', 'turbo', 'auto')
   - hibernate() calls flushCache and stopProcess on mocked decompiler
   - acquire() re-arms decompiler when hibernating
3. L2 Cache Integration in GhidraTools.decompile_function:
   - Mocking program and function entry point
   - Verifying L2 cache hit bypasses decompiler_pool.acquire() entirely (<0.05ms)
   - Verifying L2 cache miss runs decompile and populates L2 cache
4. New MCP Tools:
   - rva_translate
   - set_governor_mode
   - hibernate
   - clear_cache
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import types
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Ensure repository src/ is first in sys.path before any site-packages
_REPO_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _REPO_SRC not in sys.path:
    sys.path.insert(0, _REPO_SRC)

# Ensure SuperGhidra directory is available if needed
_SUPERGHIDRA_DIR = r"E:\02_Projects\SuperGhidra"
if os.path.exists(_SUPERGHIDRA_DIR) and _SUPERGHIDRA_DIR not in sys.path:
    sys.path.insert(0, _SUPERGHIDRA_DIR)

from pyghidra_mcp.decompiler_pool import DecompilerPool
from pyghidra_mcp.l2_cache import L2SQLiteCache, get_l2_cache
from pyghidra_mcp.mcp_tools import clear_cache, hibernate, rva_translate, set_governor_mode
from pyghidra_mcp.models import (
    ClearCacheResult,
    DecompiledFunction,
    GovernorModeResult,
    HibernateResult,
    RvaTranslateResult,
)
from pyghidra_mcp.tools import GhidraTools


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture
def temp_l2_cache():
    """Provides an isolated L2SQLiteCache instance backed by a temporary directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "integration_l2_cache.db")
        cache = L2SQLiteCache(db_path=db_path)
        yield cache
        cache.close()


@pytest.fixture
def mock_ghidra_modules(monkeypatch):
    """Installs fake ghidra.util.task module hierarchy for decompiler mock tests without JVM."""
    ghidra_module = types.ModuleType("ghidra")
    util_module = types.ModuleType("ghidra.util")
    task_module = types.ModuleType("ghidra.util.task")
    monitor = Mock()
    task_module.ConsoleTaskMonitor = Mock(return_value=monitor)

    monkeypatch.setitem(sys.modules, "ghidra", ghidra_module)
    monkeypatch.setitem(sys.modules, "ghidra.util", util_module)
    monkeypatch.setitem(sys.modules, "ghidra.util.task", task_module)
    return monitor


# ==============================================================================
# 1. L2SQLiteCache Standalone Tests
# ==============================================================================

class TestL2SQLiteCacheStandalone:
    """Verifies WAL mode, storage, case-insensitive retrieval, eviction, and clearing."""

    def test_wal_mode_and_synchronous(self, temp_l2_cache: L2SQLiteCache):
        """Verify database is created on disk with PRAGMA journal_mode=WAL and synchronous=NORMAL."""
        assert os.path.exists(temp_l2_cache.db_path), "Database file must exist on disk"
        with temp_l2_cache._conn_ctx() as conn:
            journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert journal_mode.lower() == "wal", f"Expected WAL mode, got {journal_mode}"
            synchronous = conn.execute("PRAGMA synchronous").fetchone()[0]
            assert synchronous in (1, "1", "NORMAL", "normal"), f"Expected synchronous NORMAL, got {synchronous}"

    def test_store_and_retrieve_case_insensitive(self, temp_l2_cache: L2SQLiteCache):
        """Verify put and get operations with case-insensitive normalization and metadata backfilling."""
        now = time.time()
        payload = {
            "status": "ok",
            "name": "FUN_00401000",
            "code": "int FUN_00401000(void) { return 42; }",
            "signature": "int FUN_00401000(void)",
        }
        temp_l2_cache.put("decompile", "TestBinary:0X00401000", payload, timestamp=now)

        # 1. Retrieve using lowercase key
        ret_lower = temp_l2_cache.get("decompile", "testbinary:0x00401000")
        assert ret_lower is not None, "Cache hit expected for lowercase key"
        assert ret_lower["code"] == "int FUN_00401000(void) { return 42; }"
        assert ret_lower["name"] == "FUN_00401000"
        assert ret_lower["signature"] == "int FUN_00401000(void)"
        assert ret_lower.get("l2_cached") is True
        assert pytest.approx(ret_lower.get("l2_timestamp"), 0.1) == now

        # 2. Retrieve using original mixed-case key
        ret_mixed = temp_l2_cache.get("decompile", "TestBinary:0X00401000")
        assert ret_mixed is not None, "Cache hit expected for mixed-case key"
        assert ret_mixed["code"] == ret_lower["code"]

        # 3. Cache miss returns None
        assert temp_l2_cache.get("decompile", "nonexistent:0x9999") is None
        assert temp_l2_cache.get("vtable", "testbinary:0x00401000") is None

    def test_evict_by_key_and_type(self, temp_l2_cache: L2SQLiteCache):
        """Verify targeted eviction by specific key and by query_type."""
        temp_l2_cache.put("decompile", "bin:0x1000", {"code": "func1"})
        temp_l2_cache.put("decompile", "bin:0x2000", {"code": "func2"})
        temp_l2_cache.put("vtable", "bin:0x3000", {"vtable": "vtbl1"})
        assert temp_l2_cache.count() == 3

        # Evict by specific key
        evicted = temp_l2_cache.evict(query_type="decompile", query_key="BIN:0x1000")
        assert evicted == 1
        assert temp_l2_cache.get("decompile", "bin:0x1000") is None
        assert temp_l2_cache.get("decompile", "bin:0x2000") is not None
        assert temp_l2_cache.count() == 2

        # Evict by query_type
        evicted_type = temp_l2_cache.evict(query_type="decompile")
        assert evicted_type == 1
        assert temp_l2_cache.get("decompile", "bin:0x2000") is None
        assert temp_l2_cache.get("vtable", "bin:0x3000") is not None
        assert temp_l2_cache.count() == 1

    def test_evict_by_age_and_capacity(self, temp_l2_cache: L2SQLiteCache):
        """Verify eviction by time-to-live (older_than_sec) and maximum capacity limit."""
        now = time.time()
        temp_l2_cache.put("decompile", "bin:0x1000", {"code": "old"}, timestamp=now - 500.0)
        temp_l2_cache.put("decompile", "bin:0x2000", {"code": "recent"}, timestamp=now)

        # Evict older than 200 seconds
        evicted_age = temp_l2_cache.evict(older_than_sec=200.0)
        assert evicted_age == 1
        assert temp_l2_cache.get("decompile", "bin:0x1000") is None
        assert temp_l2_cache.get("decompile", "bin:0x2000") is not None

        # Evict by max_entries capacity
        for i in range(6):
            temp_l2_cache.put("decompile", f"cap:{i}", {"val": i}, timestamp=now + i)
        assert temp_l2_cache.count() == 7  # 1 recent + 6 new

        evicted_cap = temp_l2_cache.evict(max_entries=3)
        assert evicted_cap == 4
        assert temp_l2_cache.count() == 3

    def test_clear_cache(self, temp_l2_cache: L2SQLiteCache):
        """Verify wiping all cached records."""
        for i in range(5):
            temp_l2_cache.put("decompile", f"k:{i}", {"val": i})
        assert temp_l2_cache.count() == 5

        cleared = temp_l2_cache.clear()
        assert cleared == 5
        assert temp_l2_cache.count() == 0
        assert temp_l2_cache.get("decompile", "k:0") is None


# ==============================================================================
# 2. DecompilerPool Governor & Hibernate Tests
# ==============================================================================

class TestDecompilerPoolGovernorAndHibernate:
    """Verifies resource governor profiles ('eco', 'balanced', 'turbo', 'auto'), hibernation, and re-arming."""

    def test_set_resource_modes(self):
        """Verify set_resource_mode updates idle_timeout_sec and policy parameters for eco, balanced, turbo, auto."""
        pool = DecompilerPool(lambda: Mock(), size=1)
        try:
            # Mode: eco (15s timeout, single core)
            res_eco = pool.set_resource_mode("eco")
            assert res_eco["status"] == "ok"
            assert pool.resource_mode == "eco"
            assert pool.idle_timeout_sec == 15.0

            # Mode: balanced (120s timeout, dual core)
            res_bal = pool.set_resource_mode("balanced")
            assert res_bal["status"] == "ok"
            assert pool.resource_mode == "balanced"
            assert pool.idle_timeout_sec == 120.0

            # Mode: turbo (0s timeout / never hibernate, all cores)
            res_turbo = pool.set_resource_mode("turbo")
            assert res_turbo["status"] == "ok"
            assert pool.resource_mode == "turbo"
            assert pool.idle_timeout_sec == 0.0

            # Mode: auto (60s timeout, balanced quad core)
            res_auto = pool.set_resource_mode("auto")
            assert res_auto["status"] == "ok"
            assert pool.resource_mode == "auto"
            assert pool.idle_timeout_sec == 60.0

            # Unknown mode returns error status
            res_bad = pool.set_resource_mode("extreme")
            assert res_bad["status"] == "error"
            assert "unknown mode" in res_bad["message"].lower()
        finally:
            pool.dispose()

    def test_hibernate_calls_flush_and_stop(self):
        """Verify hibernate() invokes flushCache and stopProcess on all created decompiler instances."""
        mock_decomp = Mock()
        mock_decomp.flushCache = Mock(return_value=1)
        mock_decomp.stopProcess = Mock()

        pool = DecompilerPool(lambda: mock_decomp, size=1)
        try:
            # Warm up decompiler by acquiring once
            with pool.acquire() as decomp:
                assert decomp is mock_decomp

            assert pool.is_hibernating is False
            res = pool.hibernate()
            assert res["status"] == "ok"
            assert pool.is_hibernating is True

            # Assert flushCache and stopProcess were called on the native decompiler
            mock_decomp.flushCache.assert_called_once()
            mock_decomp.stopProcess.assert_called_once()
        finally:
            pool.dispose()

    def test_acquire_rearms_when_hibernating(self):
        """Verify acquire() automatically re-arms hibernating decompilers before yielding."""
        mock_decomp = Mock()
        mock_decomp.flushCache = Mock()
        mock_decomp.stopProcess = Mock()
        mock_decomp.openProgram = Mock(return_value=True)
        mock_program = Mock()
        mock_decomp.getProgram = Mock(return_value=mock_program)

        pool = DecompilerPool(lambda: mock_decomp, size=1, program=mock_program)
        try:
            # Create instance and then hibernate
            with pool.acquire() as decomp:
                pass
            pool.hibernate()
            assert pool.is_hibernating is True

            # Next acquire must detect hibernation, rearm via openProgram, and reset hibernation flag
            with pool.acquire() as decomp:
                assert decomp is mock_decomp
                assert pool.is_hibernating is False
                mock_decomp.openProgram.assert_called_with(mock_program)
        finally:
            pool.dispose()


# ==============================================================================
# 3. L2 Cache Integration in GhidraTools.decompile_function
# ==============================================================================

class TestL2CacheGhidraToolsIntegration:
    """Verifies that L2 cache hits bypass Java decompiler and cache misses populate L2 cache."""

    def test_cache_hit_bypasses_decompiler_pool_acquire(self, temp_l2_cache: L2SQLiteCache):
        """Verify that a cached decompilation result immediately returns without touching the decompiler pool."""
        mock_program = Mock()
        mock_program.getName.return_value = "target_game.exe"

        mock_pool = Mock()
        mock_pool.acquire.side_effect = AssertionError(
            "CRITICAL FAILURE: decompiler_pool.acquire() was invoked despite warm L2 cache hit!"
        )

        program_info = Mock()
        program_info.program = mock_program
        program_info.decompiler_pool = mock_pool

        # Pre-seed L2 cache with verified decompilation output
        cache_key = "target_game.exe:0x00401000"
        seeded_code = "int FUN_00401000(int a1) {\n    return a1 * 2;\n}"
        seeded_sig = "int FUN_00401000(int a1)"
        temp_l2_cache.put(
            "decompile",
            cache_key,
            {
                "status": "ok",
                "name": "FUN_00401000",
                "code": seeded_code,
                "signature": seeded_sig,
            },
        )

        tools = GhidraTools(program_info, l2_cache=temp_l2_cache)

        # Mock function object
        mock_func = Mock()
        mock_ep = Mock()
        mock_ep.toString.return_value = "0x00401000"
        mock_func.getEntryPoint.return_value = mock_ep
        mock_func.getName.return_value = "FUN_00401000"

        # Execute decompile_function
        decompiled = tools.decompile_function(mock_func)

        assert isinstance(decompiled, DecompiledFunction)
        assert decompiled.code == seeded_code
        assert decompiled.signature == seeded_sig
        assert decompiled.name == "FUN_00401000"
        # Zero calls to pool.acquire()
        mock_pool.acquire.assert_not_called()

    def test_cache_miss_decompiles_and_populates_l2_cache(
        self, temp_l2_cache: L2SQLiteCache, mock_ghidra_modules
    ):
        """Verify that a cache miss calls the native decompiler and caches the result for instant repeats."""
        mock_program = Mock()
        mock_program.getName.return_value = "target_game.exe"

        # Mock native decompiler results
        mock_decomp = Mock()
        mock_results = Mock()
        mock_results.getErrorMessage.return_value = ""
        decomp_func_obj = Mock()
        generated_code = "void native_decompiled_func(void) { return; }"
        generated_sig = "void native_decompiled_func(void)"
        decomp_func_obj.getC.return_value = generated_code
        decomp_func_obj.getSignature.return_value = generated_sig
        mock_results.getDecompiledFunction.return_value = decomp_func_obj
        mock_decomp.decompileFunction.return_value = mock_results

        @contextmanager
        def fake_acquire(timeout=None):
            yield mock_decomp

        mock_pool = Mock()
        mock_pool.acquire = Mock(side_effect=fake_acquire)

        program_info = Mock()
        program_info.program = mock_program
        program_info.decompiler_pool = mock_pool

        tools = GhidraTools(program_info, l2_cache=temp_l2_cache)

        mock_func = Mock()
        mock_ep = Mock()
        mock_ep.toString.return_value = "0x00402000"
        mock_func.getEntryPoint.return_value = mock_ep
        mock_func.getName.return_value = "FUN_00402000"
        mock_symbol = Mock()
        mock_symbol.getName.return_value = "FUN_00402000"
        mock_func.getSymbol.return_value = mock_symbol
        mock_func.entryPoint = "0x00402000"

        # 1. First call: Cache miss -> runs native decompiler
        first_res = tools.decompile_function(mock_func)
        assert isinstance(first_res, DecompiledFunction)
        assert first_res.code == generated_code
        assert mock_pool.acquire.call_count == 1

        # Check that result was recorded in L2 cache
        cached_entry = temp_l2_cache.get("decompile", "target_game.exe:0x00402000")
        assert cached_entry is not None
        assert cached_entry["code"] == generated_code
        assert cached_entry["signature"] == generated_sig

        # 2. Second call: Cache hit -> bypasses decompiler pool acquire
        mock_pool.acquire.reset_mock()
        second_res = tools.decompile_function(mock_func)
        assert isinstance(second_res, DecompiledFunction)
        assert second_res.code == generated_code
        mock_pool.acquire.assert_not_called()

    def test_evict_function_cache(self, temp_l2_cache: L2SQLiteCache):
        """Verify that evict_function_cache removes the entry from the L2 cache."""
        mock_program = Mock()
        mock_program.getName.return_value = "target_game.exe"
        program_info = Mock(program=mock_program, decompiler_pool=Mock())

        tools = GhidraTools(program_info, l2_cache=temp_l2_cache)
        temp_l2_cache.put("decompile", "target_game.exe:0x00403000", {"code": "func3"})
        assert temp_l2_cache.get("decompile", "target_game.exe:0x00403000") is not None

        mock_func = Mock()
        mock_ep = Mock()
        mock_ep.toString.return_value = "0x00403000"
        mock_func.getEntryPoint.return_value = mock_ep

        removed = tools.evict_function_cache(mock_func)
        assert removed == 1
        assert temp_l2_cache.get("decompile", "target_game.exe:0x00403000") is None


# ==============================================================================
# 4. New MCP Tools Tests (rva_translate, set_governor_mode, hibernate, clear_cache)
# ==============================================================================

class TestNewMCPToolsSuperGhidra:
    """Verifies that the new SuperGhidra MCP tools execute cleanly and produce valid response models."""

    def test_mcp_tool_rva_translate(self):
        """Verify rva_translate calculates VA <-> RVA with zero JVM overhead."""
        # 1. Translate VA >= base to RVA
        res_va = rva_translate(addr="0x00105000", base="0x100000")
        assert isinstance(res_va, RvaTranslateResult)
        assert res_va.status == "ok"
        assert res_va.va == "0x00105000"
        assert res_va.rva == "0x00005000"
        assert res_va.va_int == 0x105000
        assert res_va.rva_int == 0x5000
        assert res_va.image_base == "0x00100000"
        assert res_va.time_ms >= 0.0

        # 2. Translate RVA < base to VA
        res_rva = rva_translate(addr="0x5000", base="0x100000")
        assert res_rva.va == "0x00105000"
        assert res_rva.rva == "0x00005000"

        # 3. Decimal address translation
        res_dec = rva_translate(addr="1048576", base="1048576")
        assert res_dec.va_int == 0x100000
        assert res_dec.rva_int == 0

    def test_mcp_tool_set_governor_mode(self):
        """Verify set_governor_mode delegates to program_info.decompiler_pool and returns GovernorModeResult."""
        mock_pool = Mock()
        mock_pool.set_resource_mode.return_value = {
            "status": "ok",
            "mode": "turbo",
            "idle_timeout_sec": 0.0,
            "message": "Decompiler pool resource mode updated to 'turbo'",
        }
        p_info = Mock(decompiler_pool=mock_pool)

        mock_pyghidra_ctx = Mock()
        mock_pyghidra_ctx.open_programs = {"game.bin": p_info}
        mock_pyghidra_ctx.get_program_info.return_value = p_info

        ctx = Mock()
        ctx.request_context.lifespan_context = mock_pyghidra_ctx

        res = set_governor_mode(mode="turbo", ctx=ctx)
        assert isinstance(res, GovernorModeResult)
        assert res.status == "ok"
        assert res.mode == "turbo"
        assert res.idle_timeout_sec == 0.0
        mock_pool.set_resource_mode.assert_called_with("turbo")

    def test_mcp_tool_hibernate(self):
        """Verify hibernate tool delegates to decompiler pool and returns HibernateResult."""
        mock_pool = Mock()
        mock_pool.hibernate.return_value = {"status": "ok", "is_hibernating": True}
        p_info = Mock(decompiler_pool=mock_pool)

        mock_pyghidra_ctx = Mock()
        mock_pyghidra_ctx.open_programs = {"game.bin": p_info}

        ctx = Mock()
        ctx.request_context.lifespan_context = mock_pyghidra_ctx

        res = hibernate(ctx=ctx)
        assert isinstance(res, HibernateResult)
        assert res.status == "ok"
        assert res.hibernated is True
        mock_pool.hibernate.assert_called_once()

    def test_mcp_tool_clear_cache(self):
        """Verify clear_cache tool invalidates L2 cache and decompiler pool."""
        mock_pool = Mock()
        p_info = Mock(decompiler_pool=mock_pool)

        mock_pyghidra_ctx = Mock()
        mock_pyghidra_ctx.open_programs = {"game.bin": p_info}

        ctx = Mock()
        ctx.request_context.lifespan_context = mock_pyghidra_ctx

        res = clear_cache(ctx=ctx)
        assert isinstance(res, ClearCacheResult)
        assert res.status == "ok"
        assert "purged" in res.message.lower()
        mock_pool.invalidate_all.assert_called_once()
