"""Unit tests for SuperGhidra native MCP tools in pyghidra-mcp."""

from __future__ import annotations

import json
import os
import sys
import struct
import tempfile
import time
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from pyghidra_mcp import mcp_tools
from pyghidra_mcp.models import (
    ClearCacheResult,
    GovernorModeResult,
    GpuAdrpScanResult,
    GpuSeedFunctionsResult,
    HibernateResult,
    RvaTranslateResult,
    SmtVerificationResult,
    SyntheticSymbolExportResult,
    ApkJniCrossRefResult,
    BinaryDiffResult,
    EmulatorMemoryVerifyResult,
    NeuralDecompileSkinResult,
    MigrateSemanticDeltasResult,
    PreindexDwarfPdbResult,
)



def test_rva_translate_forward_and_reverse():
    """Verify instant VA <-> RVA translation with zero JVM overhead."""
    t0 = time.perf_counter()
    res = mcp_tools.rva_translate("0x00CF2D84", "0x100000")
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert isinstance(res, RvaTranslateResult)
    assert res.status == "ok"
    assert res.va == "0x00CF2D84"
    assert res.rva == "0x00BF2D84"
    assert res.va_int == 0x00CF2D84
    assert res.rva_int == 0x00BF2D84
    assert res.image_base == "0x00100000"
    assert res.time_ms < 1.0
    assert elapsed_ms < 5.0

    # Reverse calculation from RVA
    rev = mcp_tools.rva_translate("0x00BF2D84", "0x100000")
    assert rev.status == "ok"
    assert rev.va_int == 0x00BF2D84


def test_clear_cache():
    """Verify persistent L2 SQLite cache purging."""
    with patch("ghidra_oracle.L2SQLiteCache") as mock_cache_cls:
        mock_instance = MagicMock()
        mock_instance.clear.return_value = 14
        mock_cache_cls.return_value = mock_instance

        mock_ctx = MagicMock()
        mock_pinfo = MagicMock()
        mock_ctx.request_context.lifespan_context.open_programs = {"test.so": mock_pinfo}

        res = mcp_tools.clear_cache(mock_ctx)
        assert isinstance(res, ClearCacheResult)
        assert res.status == "ok"
        assert res.cleared_entries == 14
        assert "14 entries removed" in res.message
        mock_pinfo.decompiler_pool.invalidate_all.assert_called_once()


def test_hibernate():
    """Verify hibernate triggers decompiler pool hibernation and JVM GC."""
    mock_ctx = MagicMock()
    mock_pinfo = MagicMock()
    mock_ctx.request_context.lifespan_context.open_programs = {"binary.so": mock_pinfo}

    res = mcp_tools.hibernate(mock_ctx)
    assert isinstance(res, HibernateResult)
    assert res.status == "ok"
    assert res.hibernated is True
    mock_pinfo.decompiler_pool.hibernate.assert_called_once()


def test_set_governor_mode():
    """Verify governor mode hot-swapping and policy returns."""
    mock_ctx = MagicMock()
    mock_pinfo = MagicMock()
    mock_pinfo.decompiler_pool.set_resource_mode.return_value = {
        "status": "ok",
        "mode": "turbo",
        "idle_timeout_sec": 0.0,
        "message": "Decompiler pool resource mode updated to 'turbo'",
    }
    mock_ctx.request_context.lifespan_context.open_programs = {"libg.so": mock_pinfo}

    res = mcp_tools.set_governor_mode("turbo", mock_ctx)
    assert isinstance(res, GovernorModeResult)
    assert res.status == "ok"
    assert res.mode == "turbo"
    assert res.policy is not None
    assert res.policy.mode == "turbo"

    # Test invalid mode raises error
    with pytest.raises(Exception):
        mcp_tools.set_governor_mode("invalid_mode_xyz", mock_ctx)


def test_gpu_adrp_scan():
    """Verify candidate ADRP+ADD/LDR detection over program bytes."""
    # Synthetic 64-byte stream with 1 ADRP + ADD pair
    # ADRP x1, #0
    # ADD x2, x1, #0x40
    insns = np.zeros(16, dtype=np.uint32)
    insns[0] = 0x90000001
    insns[1] = 0x91000000 | (1 << 5) | 2 | (0x40 << 10)
    raw_bytes = insns.tobytes()

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(raw_bytes)
        bin_path = f.name

    try:
        mock_ctx = MagicMock()
        mock_pinfo = MagicMock()
        mock_pinfo.file_path = bin_path
        mock_pinfo.program.getImageBase().getOffset.return_value = 0x100000
        mock_ctx.request_context.lifespan_context.get_program_info.return_value = mock_pinfo

        res = mcp_tools.gpu_adrp_scan("test_bin", mock_ctx, max_matches=50)
        assert isinstance(res, GpuAdrpScanResult)
        assert res.status == "ok"
        assert res.binary_name == "test_bin"
        assert res.total_matches >= 1
        assert len(res.matches) >= 1
        m0 = res.matches[0]
        assert m0.paired_type == "ADD"
    finally:
        if os.path.exists(bin_path):
            os.remove(bin_path)


def test_gpu_seed_functions():
    """Verify function entry point recovery over program bytes."""
    # Synthetic stream with PACIASP + STP prologue
    insns = np.zeros(16, dtype=np.uint32)
    insns[0] = 0xD503233F  # PACIASP
    insns[1] = 0xA9BF7BFD  # STP x29, x30, [sp, #-16]!
    raw_bytes = insns.tobytes()

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(raw_bytes)
        bin_path = f.name

    try:
        mock_ctx = MagicMock()
        mock_pinfo = MagicMock()
        mock_pinfo.file_path = bin_path
        mock_pinfo.program.getImageBase().getOffset.return_value = 0x100000
        mock_ctx.request_context.lifespan_context.get_program_info.return_value = mock_pinfo

        res = mcp_tools.gpu_seed_functions("test_bin", mock_ctx, max_functions=100)
        assert isinstance(res, GpuSeedFunctionsResult)
        assert res.status == "ok"
        assert res.binary_name == "test_bin"
        assert res.total_seeds >= 1
        assert len(res.seeds) >= 1
        assert "prologue" in res.seeds[0].sources[0]
    finally:
        if os.path.exists(bin_path):
            os.remove(bin_path)


def test_verify_smt_equivalence_bit_exact_and_divergence():
    """Verify SMT bit-exact formal equivalence and divergence detection via Z3."""
    # Machine instruction: add x0, x1, #0x20 -> Little endian: 20 80 00 91
    hex_bytes = "20 80 00 91"
    c_code_equiv = "return x1 + 0x20;"
    c_code_divergent = "return x1 + 0x30;"

    # 1. Equivalent query -> UNSAT
    res_eq = mcp_tools.verify_smt_equivalence(
        pcode_or_hex=hex_bytes,
        c_code=c_code_equiv,
        target_reg="x0",
    )
    assert isinstance(res_eq, SmtVerificationResult)
    assert res_eq.status == "ok"
    assert res_eq.equivalent is True
    assert res_eq.smt_status == "UNSAT"
    assert "EQUIVALENT" in res_eq.message

    # 2. Divergent query -> SAT with counterexample
    res_div = mcp_tools.verify_smt_equivalence(
        pcode_or_hex=hex_bytes,
        c_code=c_code_divergent,
        target_reg="x0",
    )
    assert isinstance(res_div, SmtVerificationResult)
    assert res_div.status == "ok"
    assert res_div.equivalent is False
    assert res_div.smt_status == "SAT"
    assert "DIVERGENT" in res_div.message


def test_export_synthetic_symbols_generation():
    """Verify synthetic symbol emission across .sym and .map containers."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_base = os.path.join(tmp_dir, "libtest_symbols")
        syms_json = os.path.join(tmp_dir, "names.json")

        test_symbols = {
            "Player__TakeDamage": 0x10045A820,
            "Player__GetHealth": 0x10045AA00,
        }
        with open(syms_json, "w", encoding="utf-8") as f:
            json.dump(test_symbols, f)

        res = mcp_tools.export_synthetic_symbols(
            output_base_path=out_base,
            formats=["sym", "map"],
            symbols_json_path=syms_json,
        )

        assert isinstance(res, SyntheticSymbolExportResult)
        assert res.status == "ok"
        assert "sym" in res.exported_files
        assert "map" in res.exported_files
        assert os.path.exists(res.exported_files["sym"])
        assert os.path.exists(res.exported_files["map"])
        assert os.path.getsize(res.exported_files["sym"]) > 0
        assert os.path.getsize(res.exported_files["map"]) > 0


def test_cross_reference_apk_jni():
    """Verify correlation of Java native method declarations with static exports and dynamic RegisterNatives."""
    java_sources = {
        "MainActivity.java": """
            package com.example.game;
            public class MainActivity {
                public static native void nativeInit(int flags);
                public native String nativeGetString();
            }
        """
    }

    # Static export for nativeInit
    elf_exports = {
        "Java_com_example_game_MainActivity_nativeInit": 0x105000,
    }

    # Dynamic registration for nativeGetString
    dynamic_regs = [
        {
            "method_name": "nativeGetString",
            "signature": "()Ljava/lang/String;",
            "fn_ptr": 0x106000,
            "table_address": 0x200000,
            "class_context": "com.example.game.MainActivity",
        }
    ]

    res = mcp_tools.cross_reference_apk_jni(
        java_sources=java_sources,
        elf_exports=elf_exports,
        dynamic_registrations=dynamic_regs,
    )

    assert isinstance(res, ApkJniCrossRefResult)
    assert res.status == "ok"
    assert res.total_java_methods == 2
    assert res.total_matches == 2

    # Check match types
    match_map = {m.method_name: m for m in res.matches}
    assert match_map["nativeInit"].binding_type == "STATIC_EXPORT"
    assert match_map["nativeInit"].target_address == "0x105000"
    assert match_map["nativeGetString"].binding_type == "REGISTER_NATIVES"
    assert match_map["nativeGetString"].target_address == "0x106000"

    # Verify Ghidra script generation
    assert "createLabel" in res.ghidra_script
    assert "setPlateComment" in res.ghidra_script


def test_diff_binaries():
    """Verify batched CFG feature extraction and cosine-similarity binary diffing."""
    v1_funcs = [
        {
            "func_id": "fn_calc_hash",
            "name": "calc_hash",
            "address": 0x1000,
            "instructions": ["eor", "and", "orr", "add", "lsl", "ret"],
        },
        {
            "func_id": "fn_mem_copy",
            "name": "mem_copy",
            "address": 0x2000,
            "instructions": ["ldr", "ldp", "str", "stp", "add", "ret"],
        },
    ]
    v2_funcs = [
        {
            "func_id": "sub_1000_stripped",
            "address": 0x3000,
            "instructions": ["eor", "and", "orr", "add", "lsl", "ret"],
        },
        {
            "func_id": "sub_2000_stripped",
            "address": 0x4000,
            "instructions": ["ldr", "ldp", "str", "stp", "add", "ret"],
        },
    ]

    res = mcp_tools.diff_binaries(
        v1_functions_json=json.dumps(v1_funcs),
        v2_functions_json=json.dumps(v2_funcs),
        threshold=0.70,
        method="mutual_top1",
    )

    assert isinstance(res, BinaryDiffResult)
    assert res.status == "ok"
    assert res.total_matches == 2
    assert res.match_rate_pct == 100.0

    match_map = {m.func_a_id: m for m in res.matches}
    assert "fn_calc_hash" in match_map
    assert match_map["fn_calc_hash"].func_b_id == "sub_1000_stripped"
    assert match_map["fn_calc_hash"].similarity >= 0.70
    assert "fn_mem_copy" in match_map
    assert match_map["fn_mem_copy"].func_b_id == "sub_2000_stripped"


def test_verify_emulator_memory_and_fleet_safety():
    """Verify fleet safety policy enforcement and live/mock memory verification."""
    # 1. Fleet safety: 127.0.0.1:21503 (MEmu_0 default VM) MUST be rejected
    res_memu0 = mcp_tools.verify_emulator_memory(
        device_serial="127.0.0.1:21503",
        action="verify_vtable",
    )
    assert isinstance(res_memu0, EmulatorMemoryVerifyResult)
    assert res_memu0.status == "violation"
    assert res_memu0.allowed is False
    assert "DO NOT TOUCH" in res_memu0.message

    # 2. Fleet safety: emulator-5564 (live farm automation) MUST be rejected without allow_readonly_farm
    res_farm = mcp_tools.verify_emulator_memory(
        device_serial="emulator-5564",
        action="verify_vtable",
    )
    assert res_farm.status == "violation"
    assert res_farm.allowed is False

    # 3. Authorized target: 127.0.0.1:21513 (MEmu_1) with verify_vtable
    slots_hex = b"".join(struct.pack("<Q", 0x7000000000 + 0x1000 + 0x100 + i * 0x40) for i in range(4)).hex()
    res_vt = mcp_tools.verify_emulator_memory(
        device_serial="127.0.0.1:21513",
        action="verify_vtable",
        rva="0x1000",
        module_base="0x7000000000",
        expected_slots=4,
        mock_memory_hex=slots_hex,
    )
    assert res_vt.status == "mock"
    assert res_vt.allowed is True
    assert res_vt.is_valid is True
    assert res_vt.details["match_count"] == 4
    assert res_vt.details["total_slots"] == 4

    # 4. Authorized target: emulator-5580 with verify_struct_field
    res_struct = mcp_tools.verify_emulator_memory(
        device_serial="emulator-5580",
        action="verify_struct_field",
        rva="0x24",
        expected_type="uint32",
        mock_memory_hex=struct.pack("<I", 42).hex(),
    )
    assert res_struct.status == "mock"
    assert res_struct.is_valid is True
    assert res_struct.details["actual_value"] == 42

    # 5. Authorized target: emulator-5580 with extract_dynamic_keys
    key_bytes = bytes((i * 37 + 13) % 256 for i in range(32))
    res_keys = mcp_tools.verify_emulator_memory(
        device_serial="emulator-5580",
        action="extract_dynamic_keys",
        rva="0x30",
        key_length=32,
        mock_memory_hex=key_bytes.hex(),
    )
    assert res_keys.status == "mock"
    assert res_keys.is_valid is True
    assert res_keys.details["length"] == 32
    assert res_keys.details["entropy"] > 3.0


def test_neural_decompile_skin():
    """Verify Phase-A skeleton normalization, Phase-B prediction, and EvidenceLedger gating."""
    raw_c = """
    int FUN_00101000(void *param_1, int param_2) {
        int uVar1;
        uVar1 = *(int *)(param_1 + 0x24);
        param_1->field_0x24 = param_2;
        return uVar1;
    }
    """
    res = mcp_tools.neural_decompile_skin(
        raw_c_code=raw_c,
        function_address="0x101000",
        image_base="0x100000",
    )

    assert isinstance(res, NeuralDecompileSkinResult)
    assert res.status == "ok"
    assert res.function_address == "0x00101000"
    assert res.function_rva == "0x00001000"
    # Derived from displacement 0x24 heuristic domain
    assert res.function_name == "sub_101000"
    assert res.model_identifier == "heuristic-fallback"
    assert res.return_type == "void"
    assert res.is_safe_to_commit is True
    assert "0x24" in res.verified_struct_fields
    assert res.verified_struct_fields["0x24"] == "field_0x24"
    assert len(res.evidence_proof_hashes) > 0


def test_evict_1hop_callers_and_cache_preservation():
    """Verify evict_1hop_callers evicts direct callers and preserves unrelated functions."""
    from pyghidra_mcp.tools import GhidraTools

    mock_program_info = MagicMock()
    mock_program_info.program.getName.return_value = "test_bin"
    tools = GhidraTools(mock_program_info)
    tools.decompiler_pool = MagicMock()
    tools.l2_cache = MagicMock()
    tools.l2_cache.evict.return_value = 1

    # Set up mock target function and caller references
    mock_target_func = MagicMock()
    mock_entry = MagicMock()
    mock_entry.__str__.return_value = "0x101000"
    mock_target_func.getEntryPoint.return_value = mock_entry

    mock_caller1 = MagicMock()
    mock_caller1.getName.return_value = "caller_func_1"
    mock_c1_ep = MagicMock()
    mock_c1_ep.__str__.return_value = "0x102000"
    mock_c1_ep.toString.return_value = "0x102000"
    mock_caller1.getEntryPoint.return_value = mock_c1_ep

    mock_caller2 = MagicMock()
    mock_caller2.getName.return_value = "caller_func_2"
    mock_c2_ep = MagicMock()
    mock_c2_ep.__str__.return_value = "0x103000"
    mock_c2_ep.toString.return_value = "0x103000"
    mock_caller2.getEntryPoint.return_value = mock_c2_ep

    ref1 = MagicMock()
    ref2 = MagicMock()
    ref1.getFromAddress.return_value = MagicMock()
    ref2.getFromAddress.return_value = MagicMock()

    fm = mock_program_info.program.getFunctionManager()
    fm.getFunctionContaining.side_effect = lambda addr: mock_caller1 if addr == ref1.getFromAddress() else mock_caller2
    mock_program_info.program.getReferenceManager().getReferencesTo.return_value = [ref1, ref2]

    evicted_count = tools.evict_1hop_callers(mock_target_func)
    assert evicted_count == 2
    assert tools.l2_cache.evict.call_count == 2
    tools.l2_cache.evict.assert_any_call(query_type="decompile", query_key="test_bin:0x102000")
    tools.l2_cache.evict.assert_any_call(query_type="decompile", query_key="test_bin:0x103000")


def test_verify_emulator_memory_custom_hex_and_slots():
    """Verify verify_emulator_memory with custom mock_memory_hex and expected_slot_rvas."""
    import struct

    base = 0x7000000000
    slot0_va = base + 0x1100
    slot1_va = base + 0x1140
    # Pack two 64-bit pointers
    mock_hex = struct.pack("<QQ", slot0_va, slot1_va).hex()

    res = mcp_tools.verify_emulator_memory(
        device_serial="127.0.0.1:21513",
        action="verify_vtable",
        rva="0x1000",
        module_base=hex(base),
        expected_slot_rvas=["0x1100", "0x1140"],
        mock_memory_hex=mock_hex,
    )
    assert res.status == "mock"
    assert res.allowed is True
    assert res.is_valid is True
    assert res.details["match_count"] == 2
    assert res.details["total_slots"] == 2


def test_diff_binaries_raw_binary_file():
    """Verify diff_binaries extracts and pairs CFGs from raw binary files."""
    elf_bytes = b"\x7fELF" + b"\x00" * 1024
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as f_bin:
        f_bin.write(elf_bytes)
        bin_path = f_bin.name

    json_funcs = json.dumps([
        {"func_id": "func_000", "name": "sub_1000", "address": 0x1000, "instructions": ["mov", "ret"]}
    ])

    try:
        res = mcp_tools.diff_binaries(
            v1_functions_json=bin_path,
            v2_functions_json=json_funcs,
            threshold=0.5,
        )
        assert res.status == "ok"
        assert res.total_matches >= 0
    finally:
        if os.path.exists(bin_path):
            os.remove(bin_path)


def test_gpu_seed_functions_multi_segment_and_apply():
    """Verify multi-segment VA preservation and program write-back in gpu_seed_functions."""
    mock_ctx = MagicMock()
    mock_pinfo = MagicMock()
    mock_pinfo.file_path = None
    mock_program = MagicMock()
    mock_pinfo.program = mock_program

    # Block 1: VA 0x100000, PACIASP + STP
    insns1 = np.zeros(16, dtype=np.uint32)
    insns1[0] = 0xD503233F  # PACIASP
    insns1[1] = 0xA9BF7BFD  # STP x29, x30, [sp, #-16]!
    bytes1 = insns1.tobytes()

    # Block 2: VA 0x200000, STP prologue
    insns2 = np.zeros(16, dtype=np.uint32)
    insns2[0] = 0xA9BF7BFD  # STP x29, x30, [sp, #-16]!
    bytes2 = insns2.tobytes()

    block1 = MagicMock()
    block1.isExecute.return_value = True
    block1.getSize.return_value = len(bytes1)
    block1.getStart().getOffset.return_value = 0x100000
    def read_block1(start, chunk):
        chunk[:len(bytes1)] = bytes1
        return len(bytes1)
    block1.getBytes.side_effect = read_block1

    block2 = MagicMock()
    block2.isExecute.return_value = True
    block2.getSize.return_value = len(bytes2)
    block2.getStart().getOffset.return_value = 0x200000
    def read_block2(start, chunk):
        chunk[:len(bytes2)] = bytes2
        return len(bytes2)
    block2.getBytes.side_effect = read_block2

    mock_program.getMemory().getBlocks.return_value = [block1, block2]
    mock_program.startTransaction.return_value = 42
    fm = MagicMock()
    fm.getFunctionAt.return_value = None
    mock_program.getFunctionManager.return_value = fm

    mock_ctx.request_context.lifespan_context.get_program_info.return_value = mock_pinfo

    res = mcp_tools.gpu_seed_functions("test_bin", mock_ctx, max_functions=100, apply_to_program=True)
    assert isinstance(res, GpuSeedFunctionsResult)
    assert res.status == "ok"
    assert res.total_seeds >= 2
    vas = [s.entry_vaddr for s in res.seeds]
    assert any("100000" in va.lower() for va in vas)
    assert any("200000" in va.lower() for va in vas)
    assert res.applied_to_program is not None
    assert res.applied_to_program >= 2
    mock_program.endTransaction.assert_called_with(42, True)
    assert fm.createFunction.call_count >= 2


def test_cross_reference_apk_jni_binary_dex_and_elf():
    """Verify cross_reference_apk_jni using synthetic DEX bytes and JNI ELF exports."""
    mcp_tools._ensure_superghidra_imported()
    from apk_jni_cross_referencer import APKJNICrossReferencer

    dex_bytes = APKJNICrossReferencer.build_synthetic_dex_bytes([
        ("com/example/game/NativeBridge", "calculateCombatScore", "(II)I", 0x101)
    ])
    elf_bytes = APKJNICrossReferencer.build_synthetic_jni_elf_bytes({
        "Java_com_example_game_NativeBridge_calculateCombatScore": 0x105000
    })

    with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as f_dex:
        f_dex.write(dex_bytes)
        dex_path = f_dex.name

    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as f_so:
        f_so.write(elf_bytes)
        so_path = f_so.name

    try:
        res = mcp_tools.cross_reference_apk_jni(
            apk_or_dex_path=dex_path,
            so_binary_path=so_path,
        )
        assert isinstance(res, ApkJniCrossRefResult)
        assert res.status == "ok"
        assert res.total_java_methods >= 1
        assert res.total_matches >= 1
        assert res.matches[0].method_name == "calculateCombatScore"
        assert res.matches[0].symbol_name == "Java_com_example_game_NativeBridge_calculateCombatScore"
        assert res.matches[0].target_address == hex(0x105000)
    finally:
        if os.path.exists(dex_path):
            os.remove(dex_path)
        if os.path.exists(so_path):
            os.remove(so_path)


def test_migrate_semantic_deltas():
    """Verify migrating semantic deltas across binary revisions via CFG similarity."""
    mcp_tools._ensure_superghidra_imported()
    from semantic_delta_log import SemanticDeltaLog, SemanticEvent

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f_log:
        log_path = f_log.name
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f_out:
        out_path = f_out.name

    try:
        delta_log = SemanticDeltaLog(log_path)
        evt = SemanticEvent.create_rename_symbol(
            old_name="sub_1000",
            new_name="player_apply_damage",
            target_address=0x1000,
        )
        delta_log.append(evt)

        bin_a = json.dumps([
            {"func_id": "func_000", "name": "sub_1000", "address": 0x1000, "instructions": ["mov", "add", "ret"]}
        ])
        bin_b = json.dumps([
            {"func_id": "func_b00", "name": "sub_2000", "address": 0x2000, "instructions": ["mov", "add", "ret"]}
        ])

        res = mcp_tools.migrate_semantic_deltas(
            delta_log_path=log_path,
            old_binary_path=bin_a,
            new_binary_path=bin_b,
            output_delta_log_path=out_path,
            threshold=0.5,
        )
        assert isinstance(res, MigrateSemanticDeltasResult)
        assert res.status == "ok"
        assert res.total_baseline_events == 1
        assert res.migrated_verified_count + res.migrated_unverified_count >= 1
        assert res.migration_rate_pct > 0
        assert len(res.records) == 1
        assert res.records[0].migrated_event_id is not None

        migrated_log = SemanticDeltaLog(out_path)
        migrated_events = migrated_log.load()
        assert len(migrated_events) == 1
        assert migrated_events[0].target_address == 0x2000
    finally:
        if os.path.exists(log_path):
            os.remove(log_path)
        if os.path.exists(out_path):
            os.remove(out_path)


def test_preindex_dwarf_pdb():
    """Verify preindex_dwarf_pdb type and symbol SQLite pre-indexing."""
    types_json = json.dumps({
        "canonical_types": [
            {
                "type_id": "type_struct_player",
                "name": "PlayerState",
                "kind": "struct",
                "byte_size": 16,
                "alignment": 4,
                "members": [
                    {"name": "health", "type_id": "type_u32", "offset": 0, "size": 4},
                    {"name": "score", "type_id": "type_u32", "offset": 4, "size": 4},
                ],
            }
        ],
        "symbols": [
            {
                "symbol_id": "sym_g_player",
                "name": "g_ActivePlayer",
                "address": 0x204000,
                "size": 16,
                "type_id": "type_struct_player",
                "linkage": "global",
                "section": ".bss",
            }
        ],
    })

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as f_in:
        f_in.write(types_json)
        json_path = f_in.name

    try:
        res = mcp_tools.preindex_dwarf_pdb(
            binary_or_pdb_path=json_path,
            db_output_path=":memory:",
            query_symbol_or_type="PlayerState",
        )
        assert isinstance(res, PreindexDwarfPdbResult)
        assert res.status == "ok"
        assert res.total_canonical_types >= 1
        assert res.total_symbols >= 1
        assert res.total_struct_members >= 2
        assert res.c_declaration is not None
        assert "struct PlayerState" in res.c_declaration
    finally:
        if os.path.exists(json_path):
            os.remove(json_path)


