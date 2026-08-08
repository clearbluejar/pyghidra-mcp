"""Unit tests for the chromadb code-index completeness gate.

The gate decides whether an existing collection can be reused on restart or must
be rebuilt. A collection left behind by an interrupted index (created but never
marked complete) must NOT be reused, otherwise the binary is treated as fully
indexed forever with missing/zero functions.

These tests exercise the gate against a real PersistentClient (no Ghidra runtime
needed), reopening the client between steps to prove the marker is durable.
"""

import sys
import types
from unittest.mock import Mock

from pyghidra_mcp.indexing_mixin import COLLECTION_COMPLETE_KEY, IndexingMixin
from pyghidra_mcp.tools import DEFAULT_DECOMPILE_TIMEOUT_SECONDS


class _Probe(IndexingMixin):
    """Minimal IndexingMixin host exposing only the chroma client."""

    def __init__(self, path):
        self._init_indexing_state(path, threaded=False)


def _reopen(path):
    """Return a probe backed by a fresh client to prove on-disk persistence."""
    return _Probe(path)


def test_open_complete_collection_returns_none_when_missing(tmp_path):
    probe = _Probe(tmp_path)
    assert probe._open_complete_collection("bin_missing") is None


def test_incomplete_collection_is_deleted_and_rebuilt(tmp_path):
    # Simulate an interrupted index: collection created + partially populated,
    # but never marked complete.
    probe = _Probe(tmp_path)
    collection = probe.chroma_client.create_collection(
        name="bin_partial", metadata={COLLECTION_COMPLETE_KEY: False}
    )
    collection.add(documents=["partial"], ids=["1"])

    # Reopen from disk: the gate must reject and delete the partial collection.
    probe2 = _reopen(tmp_path)
    assert probe2._open_complete_collection("bin_partial") is None

    # It must actually be gone so the next run rebuilds from scratch.
    probe3 = _reopen(tmp_path)
    assert "bin_partial" not in [c.name for c in probe3.chroma_client.list_collections()]


def test_complete_collection_is_reused(tmp_path):
    probe = _Probe(tmp_path)
    collection = probe.chroma_client.create_collection(
        name="bin_complete", metadata={COLLECTION_COMPLETE_KEY: False}
    )
    collection.add(documents=["a", "b"], ids=["1", "2"])
    probe._mark_collection_complete(collection, function_count=2)

    # Reopen from disk: a properly finalized collection is reused, data intact.
    probe2 = _reopen(tmp_path)
    reused = probe2._open_complete_collection("bin_complete")
    assert reused is not None
    assert reused.count() == 2
    assert reused.metadata[COLLECTION_COMPLETE_KEY] is True


def test_collection_without_marker_is_treated_as_incomplete(tmp_path):
    # A legacy collection from before this change has no completeness marker at
    # all; it must be rebuilt rather than trusted.
    probe = _Probe(tmp_path)
    probe.chroma_client.create_collection(name="bin_legacy")

    probe2 = _reopen(tmp_path)
    assert probe2._open_complete_collection("bin_legacy") is None


def test_code_indexing_uses_a_finite_decompile_timeout(monkeypatch):
    ghidra_module = types.ModuleType("ghidra")
    program_module = types.ModuleType("ghidra.program")
    model_module = types.ModuleType("ghidra.program.model")
    listing_module = types.ModuleType("ghidra.program.model.listing")
    listing_module.Function = object
    monkeypatch.setitem(sys.modules, "ghidra", ghidra_module)
    monkeypatch.setitem(sys.modules, "ghidra.program", program_module)
    monkeypatch.setitem(sys.modules, "ghidra.program.model", model_module)
    monkeypatch.setitem(sys.modules, "ghidra.program.model.listing", listing_module)

    function = Mock()
    function.getEntryPoint.return_value = "1000"
    decompiled = Mock(code="int entry(void) { return 0; }")
    decompiled.name = "entry-1000"
    tools = Mock()
    tools.get_all_functions.return_value = [function]
    tools.decompile_function.return_value = decompiled
    monkeypatch.setattr("pyghidra_mcp.indexing_mixin.GhidraTools", Mock(return_value=tools))

    probe = IndexingMixin.__new__(IndexingMixin)
    probe._open_complete_collection = Mock(return_value=None)
    probe._mark_collection_complete = Mock()
    collection = Mock()
    probe.chroma_client = Mock()
    probe.chroma_client.create_collection.return_value = collection
    program_info = Mock(name="sample", code_collection=None)
    program_info.name = "sample"

    probe._init_chroma_code_collection_for_program(program_info)

    tools.decompile_function.assert_called_once_with(
        function, timeout=DEFAULT_DECOMPILE_TIMEOUT_SECONDS
    )
    collection.add.assert_called_once_with(
        documents=["int entry(void) { return 0; }"],
        metadatas=[{"function_name": "entry-1000", "entry_point": "1000"}],
        ids=["entry-1000"],
    )
