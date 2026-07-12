import sys
import types
from unittest.mock import Mock

from pyghidra_mcp.context import PyGhidraContext


def _install_fake_program_modules(monkeypatch, *, should_ask_to_analyze: bool):
    ghidra_module = types.ModuleType("ghidra")
    program_module = types.ModuleType("ghidra.program")
    flatapi_module = types.ModuleType("ghidra.program.flatapi")
    util_module = types.ModuleType("ghidra.program.util")

    flat_api = Mock()
    flatapi_module.FlatProgramAPI = Mock(return_value=flat_api)
    analysis_util = Mock()
    analysis_util.shouldAskToAnalyze.return_value = should_ask_to_analyze
    util_module.GhidraProgramUtilities = analysis_util

    monkeypatch.setitem(sys.modules, "ghidra", ghidra_module)
    monkeypatch.setitem(sys.modules, "ghidra.program", program_module)
    monkeypatch.setitem(sys.modules, "ghidra.program.flatapi", flatapi_module)
    monkeypatch.setitem(sys.modules, "ghidra.program.util", util_module)
    return flat_api, analysis_util


def _new_context_and_program():
    context = PyGhidraContext.__new__(PyGhidraContext)
    context.get_metadata = Mock(return_value={"Executable Location": "/tmp/sample"})
    context._create_decompiler_pool = Mock(return_value="pool")
    program = Mock()
    program.name = "sample"
    return context, program


def test_init_program_info_restores_persisted_analysis_state(monkeypatch):
    flat_api, analysis_util = _install_fake_program_modules(
        monkeypatch, should_ask_to_analyze=False
    )
    context, program = _new_context_and_program()

    info = context._init_program_info(program)

    assert info.ghidra_analysis_complete is True
    assert info.flat_api is flat_api
    analysis_util.shouldAskToAnalyze.assert_called_once_with(program)


def test_init_program_info_keeps_unanalyzed_program_blocked(monkeypatch):
    _, analysis_util = _install_fake_program_modules(
        monkeypatch, should_ask_to_analyze=True
    )
    context, program = _new_context_and_program()

    info = context._init_program_info(program)

    assert info.ghidra_analysis_complete is False
    analysis_util.shouldAskToAnalyze.assert_called_once_with(program)
