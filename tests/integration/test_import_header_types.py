import json

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client


@pytest.mark.asyncio
async def test_import_header_types_creates_types_and_allows_prototype_use(
    server_params_shared_object,
    tmp_path,
    func_prefix,
):
    header_path = tmp_path / "reviewed_types.h"
    header_path.write_text(
        """
        #pragma once
        #include <stdint.h>

        typedef uint32_t Word;

        /* size=0x10 */
        typedef struct Node {
            /* 0x000 */ struct Node *next;
            /* 0x008 */ Word value;
        } Node;
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    async with stdio_client(server_params_shared_object) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_response = await session.call_tool("list_project_binaries", {})
            programs = json.loads(binary_response.content[0].text)["programs"]
            binary_name = programs[0]["name"]

            content_validate_response = await session.call_tool(
                "import_header_types",
                {
                    "binary_name": binary_name,
                    "header_name": "api_types.h",
                    "header_content": "#include <stdint.h>\ntypedef uint32_t ApiWord;\n/* size=0x8 */ typedef struct ApiNode { /* 0x000 */ ApiWord value; } ApiNode;",
                    "validate_only": True,
                },
            )
            content_validate_payload = json.loads(content_validate_response.content[0].text)
            assert content_validate_payload["header_path"] == "api_types.h"
            assert content_validate_payload["validate_only"] is True
            assert content_validate_payload["diagnostics"] == []

            import_response = await session.call_tool(
                "import_header_types",
                {
                    "binary_name": binary_name,
                    "header_path": str(header_path),
                },
            )
            import_payload = json.loads(import_response.content[0].text)

            assert import_payload["binary_name"] == binary_name
            assert import_payload["category_root"] == "/pyghidra_mcp/imported_headers"
            assert "Node" in import_payload["created_types"] or "Node" in import_payload["updated_types"]
            assert "Word" in import_payload["created_types"] or "Word" in import_payload["updated_types"]
            assert import_payload["diagnostics"] == []
            type_refs = import_payload["created_type_refs"] + import_payload["updated_type_refs"]
            node_path = next(ref["path"] for ref in type_refs if ref["name"] == "Node")
            word_path = next(ref["path"] for ref in type_refs if ref["name"] == "Word")
            assert node_path == "/pyghidra_mcp/imported_headers/Node"

            list_response = await session.call_tool(
                "list_data_types",
                {
                    "binary_name": binary_name,
                    "query": "Node",
                    "category_path": "/pyghidra_mcp/imported_headers",
                },
            )
            list_payload = json.loads(list_response.content[0].text)
            assert any(ref["path"] == node_path for ref in list_payload["data_types"])

            node_response = await session.call_tool(
                "describe_data_type",
                {
                    "binary_name": binary_name,
                    "data_type_name_or_path": "Node",
                },
            )
            node_payload = json.loads(node_response.content[0].text)
            assert node_payload["binary_name"] == binary_name
            assert node_payload["path"] == "/pyghidra_mcp/imported_headers/Node"
            assert node_payload["kind"] == "structure"
            assert node_payload["fields"][0]["field_name"] == "next"
            assert node_payload["fields"][0]["offset"] == 0
            assert node_payload["fields"][1]["field_name"] == "value"
            assert node_payload["fields"][1]["offset"] == 8

            word_response = await session.call_tool(
                "describe_data_type",
                {
                    "binary_name": binary_name,
                    "data_type_name_or_path": "Word",
                },
            )
            word_payload = json.loads(word_response.content[0].text)
            assert word_payload["path"] == "/pyghidra_mcp/imported_headers/Word"
            assert word_payload["fields"] == []

            node_path_response = await session.call_tool(
                "describe_data_type",
                {
                    "binary_name": binary_name,
                    "data_type_name_or_path": node_path,
                },
            )
            node_path_payload = json.loads(node_path_response.content[0].text)
            assert node_path_payload["path"] == node_path

            function_name = f"{func_prefix}shared_func_two"
            prototype_response = await session.call_tool(
                "set_function_prototype",
                {
                    "binary_name": binary_name,
                    "function_name_or_address": function_name,
                    "prototype": f"void {function_name}(Node *node)",
                },
            )
            prototype_payload = json.loads(prototype_response.content[0].text)
            assert "Node * node" in prototype_payload["new_prototype"]

            variable_type_response = await session.call_tool(
                "set_variable_type",
                {
                    "binary_name": binary_name,
                    "function_name_or_address": function_name,
                    "variable_name": "node",
                    "type_name": node_path,
                    "variable_kind": "parameter",
                },
            )
            variable_type_payload = json.loads(variable_type_response.content[0].text)
            assert variable_type_payload["new_type_path"] == node_path

            return_type_response = await session.call_tool(
                "set_function_return_type",
                {
                    "binary_name": binary_name,
                    "function_name_or_address": function_name,
                    "type_name_or_path": word_path,
                },
            )
            return_type_payload = json.loads(return_type_response.content[0].text)
            assert return_type_payload["new_return_type_path"] == word_path
