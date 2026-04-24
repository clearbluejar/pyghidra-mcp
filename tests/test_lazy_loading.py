import sys
from unittest.mock import MagicMock, patch
from pathlib import Path

# Mock ghidra modules globally BEFORE importing context
sys.modules["ghidra"] = MagicMock()
sys.modules["ghidra.app.decompiler"] = MagicMock()
sys.modules["ghidra.base.project"] = MagicMock()
sys.modules["ghidra.framework.model"] = MagicMock()
sys.modules["ghidra.program.flatapi"] = MagicMock()
sys.modules["ghidra.program.model.listing"] = MagicMock()
sys.modules["ghidra.program.model.data"] = MagicMock()
sys.modules["ghidra.program.model.symbol"] = MagicMock()
sys.modules["ghidra.util.task"] = MagicMock()
sys.modules["ghidra.app.script"] = MagicMock()
sys.modules["ghidra.program.util"] = MagicMock()
sys.modules["java.io"] = MagicMock()
sys.modules["java.util"] = MagicMock()
sys.modules["java.lang"] = MagicMock()
sys.modules["pyghidra"] = MagicMock()

# Mock chromadb
sys.modules["chromadb"] = MagicMock()
sys.modules["chromadb.config"] = MagicMock()

# Mock server dependencies
sys.modules["click"] = MagicMock()
sys.modules["click_option_group"] = MagicMock()
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.server.fastmcp"] = MagicMock()
sys.modules["mcp.shared"] = MagicMock()
sys.modules["mcp.shared.exceptions"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()

# Mock ghidrecomp
sys.modules["ghidrecomp"] = MagicMock()
sys.modules["ghidrecomp.callgraph"] = MagicMock()


# Ensure we can import from src
src_path = str(Path(__file__).parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Mock pyghidra_mcp.tools if needed (it imports ghidra)
# Since we mocked ghidra, importing tools should be fine.

from pyghidra_mcp.context import ProgramInfo, PyGhidraContext

def test_program_info_lazy_loading():
    print("Testing ProgramInfo lazy loading...")
    callback = MagicMock()
    
    info = ProgramInfo(
        name="test_bin",
        load_callback=callback,
        metadata={},
        ghidra_analysis_complete=False,
        domain_file_path="/mock/path"
    )
    
    # Accessing program should trigger callback
    # The callback is responsible for setting _program.
    def load_side_effect(name):
        info._program = "MOCK_PROGRAM"
        
    callback.side_effect = load_side_effect
    
    assert info._program is None
    prog = info.program
    assert prog == "MOCK_PROGRAM"
    callback.assert_called_with("test_bin")
    
    # Accessing again should NOT trigger callback
    callback.reset_mock()
    prog2 = info.program
    assert prog2 == "MOCK_PROGRAM"
    callback.assert_not_called()
    print("PASS")

def test_lru_eviction():
    print("Testing LRU eviction...")
    # Setup Context with mocked dependencies
    with patch("pyghidra_mcp.context.PyGhidraContext._get_or_create_project"), \
         patch("pyghidra_mcp.context.PyGhidraContext._init_project_programs"), \
         patch("pyghidra_mcp.context.PyGhidraContext.list_binaries", return_value=[]):
        
        ctx = PyGhidraContext("test_proj", "/tmp")
        ctx.cache_size = 2 # Small cache for testing
        
        # Mock methods called during load
        ctx.project = MagicMock()
        ctx.project.openProgram.side_effect = lambda path, name, _: f"PROG_{name}"
        ctx.setup_decompiler = MagicMock()
        ctx.setup_decompiler.return_value = "MOCK_DECOMPILER"
        
        # Create ProgramInfos manually (as if by _init_project_programs)
        # Note: We must ensure ctx.programs is populated so _ensure_program_loaded can find them
        p1 = ProgramInfo("p1", ctx._ensure_program_loaded, {}, False, domain_file_path="/bin/p1")
        p2 = ProgramInfo("p2", ctx._ensure_program_loaded, {}, False, domain_file_path="/bin/p2")
        p3 = ProgramInfo("p3", ctx._ensure_program_loaded, {}, False, domain_file_path="/bin/p3")
        
        ctx.programs["p1"] = p1
        ctx.programs["p2"] = p2
        ctx.programs["p3"] = p3
        
        # Trigger load p1
        print("Loading p1...")
        assert p1.program == "PROG_p1"
        assert ctx.lru_cache == ["p1"]
        
        # Trigger load p2
        print("Loading p2...")
        assert p2.program == "PROG_p2"
        assert ctx.lru_cache == ["p1", "p2"]
        
        # Trigger load p3 -> Should evict p1
        print("Loading p3 (expecting p1 eviction)...")
        assert p3.program == "PROG_p3"
        # Since p1 was index 0, it should be popped.
        # Cache should be [p2, p3]
        assert ctx.lru_cache == ["p2", "p3"]
        assert p1._program is None # Evicted
        assert p2._program == "PROG_p2" # Kept
        
        # Access p2 -> Should become MRU
        print("Accessing p2 (expecting update to MRU)...")
        _ = p2.program
        assert ctx.lru_cache == ["p3", "p2"]
        
        # Reload p1 -> Should evict p3 (LRU)
        print("Reloading p1 (expecting p3 eviction)...")
        assert p1.program == "PROG_p1"
        assert ctx.lru_cache == ["p2", "p1"]
        assert p3._program is None
        assert p1._program == "PROG_p1"
        
        # Test Property Access triggers load
        p3._program = None
        # flat_api access should trigger load
        print("Accessing p3.flat_api (expecting reload)...")
        # Ensure domain file path is present or it fails
        # It is present from init.
        # But wait, p3 is currently unloaded.
        # Calling flat_api -> program property -> callback -> load
        # This will evict p2 (since cache is [p2, p1] -> p2 is LRU)
        _api = p3.flat_api
        assert ctx.lru_cache == ["p1", "p3"]
        assert p2._program is None
        assert p3._program == "PROG_p3"
    print("PASS")

if __name__ == "__main__":
    try:
        test_program_info_lazy_loading()
        test_lru_eviction()
        print("All tests passed!")
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
