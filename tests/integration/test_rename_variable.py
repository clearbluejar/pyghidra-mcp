import json
import os
import tempfile

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext


@pytest.fixture(scope="module")
def variable_test_binary():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

int helper(int count) {
    int total = count + 1;
    printf("%d\\n", total);
    return total;
}

int main(void) {
    return helper(3);
}
"""
        )
        c_file = f.name

    bin_file = c_file.replace(".c", "")
    os.system(f"gcc -g -O0 -o {bin_file} {c_file}")

    yield bin_file

    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def variable_server_params(variable_test_binary, ghidra_env, isolated_project_root):
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            "--project-path",
            str(isolated_project_root / "variable_server_params"),
            "--project-name",
            "variable_server_params_project",
            "--wait-for-analysis",
            variable_test_binary,
        ],
        env=ghidra_env,
    )


@pytest.mark.asyncio
async def test_rename_variable_tool(variable_server_params, variable_test_binary):
    async with stdio_client(variable_server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(variable_test_binary)
            symbols_result = await session.call_tool(
                "search_symbols_by_name",
                {
                    "binary_name": binary_name,
                    "query": "^helper$",
                    "functions_only": True,
                },
            )
            symbols_payload = json.loads(symbols_result.content[0].text)
            helper_name = symbols_payload["symbols"][0]["name"]

            rename_result = await session.call_tool(
                "rename_variable",
                {
                    "binary_name": binary_name,
                    "function_name_or_address": helper_name,
                    "variable_name": "count",
                    "new_name": "item_count",
                },
            )
            rename_payload = json.loads(rename_result.content[0].text)
            assert rename_payload["function_name"] == helper_name
            assert rename_payload["variable_kind"] == "parameter"
            assert rename_payload["old_name"] == "count"
            assert rename_payload["new_name"] == "item_count"

            decompile_result = await session.call_tool(
                "decompile_function",
                {
                    "binary_name": binary_name,
                    "name_or_address": helper_name,
                },
            )
            decompile_payload = json.loads(decompile_result.content[0].text)
            assert "item_count" in decompile_payload["code"]


@pytest.mark.asyncio
async def test_set_variable_type_tool(variable_server_params, variable_test_binary):
    async with stdio_client(variable_server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(variable_test_binary)
            symbols_result = await session.call_tool(
                "search_symbols_by_name",
                {
                    "binary_name": binary_name,
                    "query": "^helper$",
                    "functions_only": True,
                },
            )
            symbols_payload = json.loads(symbols_result.content[0].text)
            helper_name = symbols_payload["symbols"][0]["name"]

            type_result = await session.call_tool(
                "set_variable_type",
                {
                    "binary_name": binary_name,
                    "function_name_or_address": helper_name,
                    "variable_name": "count",
                    "type_name": "long",
                },
            )
            type_payload = json.loads(type_result.content[0].text)
            assert type_payload["function_name"] == helper_name
            assert type_payload["variable_kind"] == "parameter"
            assert type_payload["variable_name"] == "count"
            assert type_payload["old_type"] == "int"
            assert type_payload["new_type"] == "long"

            decompile_result = await session.call_tool(
                "decompile_function",
                {
                    "binary_name": binary_name,
                    "name_or_address": helper_name,
                },
            )
            decompile_payload = json.loads(decompile_result.content[0].text)
            assert "long count" in decompile_payload["code"]
