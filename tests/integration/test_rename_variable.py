import json
import os
import tempfile

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext


def _callee_name(callee):
    if isinstance(callee, dict):
        return callee.get("name", "")
    return str(callee)


def _find_function_one_name(callees) -> str:
    return next(
        name for name in (_callee_name(c) for c in callees) if name.endswith("function_one")
    )


async def _resolve_function_one_name(session: ClientSession, binary_name: str) -> str:
    for target in ("main", "_main", "entry"):
        try:
            decompile_result = await session.call_tool(
                "decompile_function",
                {
                    "binary_name": binary_name,
                    "name_or_address": target,
                    "include_callees": True,
                },
            )
            decompile_payload = json.loads(decompile_result.content[0].text)
            callees = decompile_payload.get("callees") or []
            return _find_function_one_name(callees)
        except Exception:
            pass

    raise AssertionError("Unable to resolve function_one from entry/main callees")


@pytest.fixture(scope="module")
def variable_test_binary():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

__attribute__((noinline)) int function_one(int count) {
    int total = count + 1;
    printf("Function One");
    return total;
}

__attribute__((noinline)) void function_two(void) {
    printf("Function Two");
}

int main(void) {
    function_two();
    return function_one(3);
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
            function_name = await _resolve_function_one_name(session, binary_name)

            rename_result = await session.call_tool(
                "rename_variable",
                {
                    "binary_name": binary_name,
                    "function_name_or_address": function_name,
                    "variable_name": "count",
                    "new_name": "item_count",
                },
            )
            rename_payload = json.loads(rename_result.content[0].text)
            assert rename_payload["function_name"] == function_name
            assert rename_payload["variable_kind"] == "parameter"
            assert rename_payload["old_name"] == "count"
            assert rename_payload["new_name"] == "item_count"

            type_result = await session.call_tool(
                "set_variable_type",
                {
                    "binary_name": binary_name,
                    "function_name_or_address": function_name,
                    "variable_name": "item_count",
                    "type_name": "long",
                },
            )
            type_payload = json.loads(type_result.content[0].text)
            assert type_payload["function_name"] == function_name
            assert type_payload["variable_name"] == "item_count"
            assert type_payload["old_type"] == "int"
            assert type_payload["new_type"] == "long"


@pytest.mark.asyncio
async def test_set_variable_type_tool(variable_server_params, variable_test_binary):
    async with stdio_client(variable_server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = PyGhidraContext._gen_unique_bin_name(variable_test_binary)
            function_name = await _resolve_function_one_name(session, binary_name)

            type_result = await session.call_tool(
                "set_variable_type",
                {
                    "binary_name": binary_name,
                    "function_name_or_address": function_name,
                    "variable_name": "count",
                    "type_name": "long",
                },
            )
            type_payload = json.loads(type_result.content[0].text)
            assert type_payload["function_name"] == function_name
            assert type_payload["variable_kind"] == "parameter"
            assert type_payload["variable_name"] == "count"
            assert type_payload["old_type"] == "int"
            assert type_payload["new_type"] == "long"

            reset_result = await session.call_tool(
                "set_variable_type",
                {
                    "binary_name": binary_name,
                    "function_name_or_address": function_name,
                    "variable_name": "count",
                    "type_name": "int",
                },
            )
            reset_payload = json.loads(reset_result.content[0].text)
            assert reset_payload["function_name"] == function_name
            assert reset_payload["variable_name"] == "count"
            assert reset_payload["old_type"] == "long"
            assert reset_payload["new_type"] == "int"
