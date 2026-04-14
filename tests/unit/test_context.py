import sys
import types
from unittest.mock import Mock, call

from pyghidra_mcp.context import PyGhidraContext


def test_init_project_programs_uses_domain_file_paths(monkeypatch):
    """Existing project programs should reopen via Ghidra domain paths, not pathlib."""
    ghidra_module = types.ModuleType("ghidra")
    program_module = types.ModuleType("ghidra.program")
    model_module = types.ModuleType("ghidra.program.model")
    listing_module = types.ModuleType("ghidra.program.model.listing")
    listing_module.Program = object

    monkeypatch.setitem(sys.modules, "ghidra", ghidra_module)
    monkeypatch.setitem(sys.modules, "ghidra.program", program_module)
    monkeypatch.setitem(sys.modules, "ghidra.program.model", model_module)
    monkeypatch.setitem(sys.modules, "ghidra.program.model.listing", listing_module)

    context = PyGhidraContext.__new__(PyGhidraContext)
    context.project = Mock()
    context.programs = {}

    root_parent = Mock()
    root_parent.pathname = "/"

    nested_parent = Mock()
    nested_parent.pathname = "/bin/tools"

    root_domain_file = Mock()
    root_domain_file.pathname = "/ls-aa11bb"
    root_domain_file.getName.return_value = "ls-aa11bb"
    root_domain_file.getParent.return_value = root_parent

    nested_domain_file = Mock()
    nested_domain_file.pathname = "/bin/tools/libfoo-cc22dd"
    nested_domain_file.getName.return_value = "libfoo-cc22dd"
    nested_domain_file.getParent.return_value = nested_parent

    context.list_binary_domain_files = Mock(
        return_value=[root_domain_file, nested_domain_file]
    )
    context.project.openProgram.side_effect = ["root-program", "nested-program"]
    context._init_program_info = Mock(side_effect=["root-info", "nested-info"])

    context._init_project_programs()

    context.project.openProgram.assert_has_calls(
        [
            call("/", "ls-aa11bb", False),
            call("/bin/tools", "libfoo-cc22dd", False),
        ]
    )
    assert context.programs == {
        "/ls-aa11bb": "root-info",
        "/bin/tools/libfoo-cc22dd": "nested-info",
    }
