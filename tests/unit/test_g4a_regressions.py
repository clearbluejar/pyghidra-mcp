"""
test_g4a_regressions.py
=======================
Regression test suite for verified bugs 1-7 in pyghidra_mcp:
1. verify_smt_equivalence error on unknown target_reg and real SMT status in message
2. verify_emulator_memory error on missing reader and status='mock' on mock_memory_hex
3. ReconstructionObligationLedger default path outside SuperGhidra repo
4. _resolve_safe_path rejects missing read files and C:\\Windows writes
5. cross_reference_apk_jni parses all Java sources in loop
6. _parse_functions_for_diff labels heuristic disassembly in response
7. gpu_adrp_scan transaction error rolls back (commit=False) and returns status='error'
"""

from __future__ import annotations

import json
import os
import struct
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pyghidra_mcp import mcp_tools
from pyghidra_mcp.models import (
    ApkJniCrossRefResult,
    BinaryDiffResult,
    EmulatorMemoryVerifyResult,
    GpuAdrpScanResult,
    SmtVerificationResult,
)


def test_1_verify_smt_equivalence_unknown_target_reg():
    """Bug 1: verify_smt_equivalence must return status='error' for unknown target_reg."""
    res = mcp_tools.verify_smt_equivalence(
        pcode_or_hex="00 00 80 52",
        c_code="return 0;",
        target_reg="non_existent_reg_99",
    )
    assert isinstance(res, SmtVerificationResult)
    assert res.status == "error"
    assert res.equivalent is False
    assert res.smt_status == "ERROR"
    assert "non_existent_reg_99" in res.message


def test_2_emulator_memory_no_reader_error_and_mock_status():
    """Bug 2: verify_emulator_memory errors if no reader/mock configured, returns 'mock' if mock_hex supplied."""
    # A) No live reader and no mock_memory_hex -> status='error'
    res_err = mcp_tools.verify_emulator_memory(
        device_serial="emulator-5580",
        action="verify_vtable",
    )
    assert isinstance(res_err, EmulatorMemoryVerifyResult)
    assert res_err.status == "error"
    assert "no live reader configured" in res_err.message.lower()

    # B) Win32 reader failure to open -> status='error'
    res_win32_fail = mcp_tools.verify_emulator_memory(
        device_serial="emulator-5580",
        pid=99999999,
    )
    assert res_win32_fail.status == "error"
    assert "Failed to open Win32ProcessMemoryReader" in res_win32_fail.message

    # C) Mock hex provided -> status='mock'
    key_bytes = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    res_mock = mcp_tools.verify_emulator_memory(
        device_serial="emulator-5580",
        action="extract_dynamic_keys",
        rva="0x20",
        key_length=4,
        mock_memory_hex=key_bytes.hex(),
    )
    assert res_mock.status == "mock"
    assert res_mock.allowed is True


def test_3_ledger_default_path_not_inside_superghidra_repo():
    """Bug 3: Default ledger path must resolve to user data dir, not inside SuperGhidra repo."""
    default_path = mcp_tools._get_default_ledger_path()
    norm_path = os.path.normpath(default_path).lower()
    norm_super = os.path.normpath(r"E:\02_Projects\SuperGhidra").lower()

    # Default path must NOT be directly inside the SuperGhidra code repository
    assert not norm_path.startswith(norm_super)
    assert norm_path.endswith("evidence_ledger.json")


def test_4_path_validation_rejects_missing_read_and_system_write():
    """Bug 4: Path validation helper refuses non-existent reads and protected system writes."""
    # Reads: missing file -> ValueError
    with pytest.raises(ValueError, match="does not exist"):
        mcp_tools._resolve_safe_path(
            r"E:\02_Projects\pyghidra-mcp\tests\non_existent_file_98765.txt",
            must_exist=True,
            for_write=False,
        )

    # Writes: system directory -> ValueError
    with pytest.raises(ValueError, match="protected system directory"):
        mcp_tools._resolve_safe_path(
            r"C:\Windows\System32\injected_payload.dll",
            must_exist=False,
            for_write=True,
        )

    # preindex_dwarf_pdb rejects non-existent path
    with pytest.raises(Exception):
        mcp_tools.preindex_dwarf_pdb(r"E:\02_Projects\pyghidra-mcp\tests\missing_sample.pdb")


def test_5_jni_cross_reference_parses_all_sources():
    """Bug 5: APK JNI cross referencer must parse every source file in java_sources dict."""
    src1 = """
    package com.antigravity.test;
    public class ActivityOne {
        public native int computeChecksum(byte[] data);
    }
    """
    src2 = """
    package com.antigravity.test;
    public class ActivityTwo {
        public native void initializeSecurity(String token);
    }
    """
    res = mcp_tools.cross_reference_apk_jni(
        java_sources={
            "ActivityOne.java": src1,
            "ActivityTwo.java": src2,
        }
    )
    assert isinstance(res, ApkJniCrossRefResult)
    assert res.status == "ok"
    assert res.total_java_methods == 2


def test_6_diff_binaries_heuristic_labeling():
    """Bug 6: Raw binary byte disassembly must be labeled heuristic in response."""
    mcp_tools._ensure_superghidra_imported()
    import binary_diff_engine

    raw_elf = b"\x7fELF" + bytes([0x80, 0x40, 0x20, 0x04]) * 64
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f1:
        f1.write(raw_elf)
        p1 = f1.name
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f2:
        f2.write(raw_elf)
        p2 = f2.name

    orig_fn = getattr(binary_diff_engine, "extract_cfgs_from_binary", None)
    try:
        if hasattr(binary_diff_engine, "extract_cfgs_from_binary"):
            delattr(binary_diff_engine, "extract_cfgs_from_binary")

        res = mcp_tools.diff_binaries(
            v1_functions_json=p1,
            v2_functions_json=p2,
            threshold=0.5,
        )
        assert isinstance(res, BinaryDiffResult)
        assert res.status == "ok"
        assert "[heuristic]" in res.message or any(m.match_type == "heuristic" for m in res.matches)
    finally:
        if orig_fn is not None:
            setattr(binary_diff_engine, "extract_cfgs_from_binary", orig_fn)
        for p in (p1, p2):
            if os.path.exists(p):
                os.remove(p)


def test_7_gpu_adrp_scan_error_path_rolls_back_and_returns_error():
    """Bug 7: gpu_adrp_scan must abort transaction (commit=False) and return status='error' on failure."""
    mcp_tools._ensure_superghidra_imported()
    mock_ctx = MagicMock()
    mock_pinfo = MagicMock()
    mock_program = MagicMock()
    mock_pinfo.program = mock_program
    mock_ctx.request_context.lifespan_context.get_program_info.return_value = mock_pinfo

    mock_program.startTransaction.return_value = 123
    mock_rm = MagicMock()
    mock_rm.addMemoryReference.side_effect = RuntimeError("Hardware database write failure")
    mock_program.getReferenceManager.return_value = mock_rm

    with patch("gpu_adrp_scanner.GPUAdrpScanner") as mock_scanner_cls:
        mock_scanner = MagicMock()
        mock_match = MagicMock()
        mock_match.to_dict.return_value = {
            "adrp_index": 0,
            "adrp_offset": "0x0",
            "adrp_pc": "0x1000",
            "adrp_insn": "adrp x0, #0x2000",
            "adrp_rd": "x0",
            "paired_index": 1,
            "paired_offset": "0x10",
            "paired_pc": "0x1004",
            "paired_insn": "ldr x0, [x0, #0x10]",
            "paired_type": "ldr",
            "paired_rn": "x0",
            "paired_rt": "x0",
            "immediate": "0x10",
            "resolved_target": "0x2010",
            "register_matched": True,
        }
        mock_scanner.scan_matches.return_value = [mock_match]
        mock_scanner.active_backend = "mock_gpu"
        mock_scanner_cls.return_value = mock_scanner

        mock_pinfo.file_path = None
        mock_memory = MagicMock()
        mock_block = MagicMock()
        mock_block.isExecute.return_value = True
        mock_block.getSize.return_value = 32
        def read_block(start, chunk):
            chunk[:32] = b"\x00" * 32
            return 32
        mock_block.getBytes.side_effect = read_block
        mock_block.getStart().getOffset.return_value = 0x1000
        mock_memory.getBlocks.return_value = [mock_block]
        mock_program.getMemory.return_value = mock_memory

        res = mcp_tools.gpu_adrp_scan(
            binary_name="test_bin",
            ctx=mock_ctx,
            apply_xrefs=True,
        )

        assert isinstance(res, GpuAdrpScanResult)
        assert res.status == "error"
        assert "Hardware database write failure" in (res.message or "")
        # Transaction must have been closed with commit=False (not True!)
        mock_program.endTransaction.assert_called_with(123, False)
