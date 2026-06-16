"""Unit tests for the chromadb code-index completeness gate.

The gate decides whether an existing collection can be reused on restart or must
be rebuilt. A collection left behind by an interrupted index (created but never
marked complete) must NOT be reused, otherwise the binary is treated as fully
indexed forever with missing/zero functions.

These tests exercise the gate against a real PersistentClient (no Ghidra runtime
needed), reopening the client between steps to prove the marker is durable.
"""

import chromadb
from chromadb.config import Settings

from pyghidra_mcp.indexing_mixin import COLLECTION_COMPLETE_KEY, IndexingMixin


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
