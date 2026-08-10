from unittest.mock import Mock

from pyghidra_mcp.models import SearchMode
from pyghidra_mcp.tools import GhidraTools


class _FakeCodeCollection:
    def __init__(self, documents, query_results=None):
        self.documents = documents
        self.query_results = query_results or documents
        self.count_calls = 0
        self.get_calls = []
        self.query_calls = []

    def count(self):
        self.count_calls += 1
        return len(self.documents)

    def get(self, where_document=None, include=None, limit=None, offset=None):
        self.get_calls.append(
            {
                "where_document": where_document,
                "include": include,
                "limit": limit,
                "offset": offset,
            }
        )
        query = (where_document or {}).get("$contains")
        matches = [
            row for row in self.documents if query is None or query in row["document"]
        ]
        page_offset = offset or 0
        page = (
            matches[page_offset:]
            if limit is None
            else matches[page_offset : page_offset + limit]
        )

        result = {"ids": [row["id"] for row in page]}
        if include != []:
            result["documents"] = [row["document"] for row in page]
            result["metadatas"] = [row["metadata"] for row in page]
        return result

    def query(self, query_texts, n_results):
        self.query_calls.append({"query_texts": query_texts, "n_results": n_results})
        page = self.query_results[:n_results]
        return {
            "documents": [[row["document"] for row in page]],
            "metadatas": [[row["metadata"] for row in page]],
            "distances": [[row.get("distance", 0.0) for row in page]],
        }


def _make_tools(code_collection):
    program_info = Mock()
    program_info.code_collection = code_collection
    tools = GhidraTools.__new__(GhidraTools)
    tools.program_info = program_info
    tools.program = program_info.program
    tools.decompiler_pool = Mock()
    return tools


def test_search_code_semantic_uses_literal_id_count_without_literal_page_fetch():
    code_collection = _FakeCodeCollection(
        documents=[
            {
                "id": "func1",
                "document": "printf alpha branch with extra text",
                "metadata": {"function_name": "func1"},
            },
            {
                "id": "func2",
                "document": "printf beta branch with extra text",
                "metadata": {"function_name": "func2"},
            },
            {
                "id": "func3",
                "document": "gamma branch without literal match",
                "metadata": {"function_name": "func3"},
            },
        ],
        query_results=[
            {
                "id": "func1",
                "document": "printf alpha branch with extra text",
                "metadata": {"function_name": "func1"},
                "distance": 0.0,
            },
            {
                "id": "func2",
                "document": "printf beta branch with extra text",
                "metadata": {"function_name": "func2"},
                "distance": 1.0,
            },
        ],
    )
    tools = _make_tools(code_collection)

    results = tools.search_code(
        query="printf",
        limit=1,
        offset=1,
        search_mode=SearchMode.SEMANTIC,
        include_full_code=False,
        preview_length=10,
    )

    assert code_collection.count_calls == 1
    assert code_collection.get_calls == [
        {
            "where_document": {"$contains": "printf"},
            "include": [],
            "limit": None,
            "offset": None,
        }
    ]
    assert code_collection.query_calls == [
        {"query_texts": ["printf"], "n_results": 2}
    ]
    assert results.literal_total == 2
    assert results.total_functions == 3
    assert results.returned_count == 1
    assert results.results[0].function_name == "func2"
    assert results.results[0].code == "printf bet..."


def test_search_code_literal_fetches_only_requested_page():
    code_collection = _FakeCodeCollection(
        documents=[
            {
                "id": "func1",
                "document": "printf alpha branch with extra text",
                "metadata": {"function_name": "func1"},
            },
            {
                "id": "func2",
                "document": "printf beta branch with extra text",
                "metadata": {"function_name": "func2"},
            },
            {
                "id": "func3",
                "document": "gamma branch without literal match",
                "metadata": {"function_name": "func3"},
            },
        ]
    )
    tools = _make_tools(code_collection)

    results = tools.search_code(
        query="printf",
        limit=1,
        offset=1,
        search_mode=SearchMode.LITERAL,
        include_full_code=False,
        preview_length=6,
    )

    assert code_collection.count_calls == 1
    assert code_collection.get_calls == [
        {
            "where_document": {"$contains": "printf"},
            "include": [],
            "limit": None,
            "offset": None,
        },
        {
            "where_document": {"$contains": "printf"},
            "include": ["documents", "metadatas"],
            "limit": 1,
            "offset": 1,
        },
    ]
    assert code_collection.query_calls == []
    assert results.literal_total == 2
    assert results.semantic_total == 3
    assert results.total_functions == 3
    assert results.returned_count == 1
    assert results.results[0].function_name == "func2"
    assert results.results[0].preview == "printf..."
    assert results.results[0].code == "printf..."
