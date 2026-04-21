import json
import os
import sys
import tempfile

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _callee_name(callee):
    if isinstance(callee, dict):
        return callee.get("name", "")
    return str(callee)


def _find_function_one_name(callees) -> str:
    return next(
        name for name in (_callee_name(c) for c in callees) if name.endswith("function_one")
    )


async def _resolve_function_one_name(session: ClientSession, binary_name: str) -> str:
    symbols_result = await session.call_tool(
        "search_symbols_by_name",
        {
            "binary_name": binary_name,
            "query": "function_one",
            "functions_only": True,
        },
    )
    symbols_payload = json.loads(symbols_result.content[0].text)
    symbols = symbols_payload.get("symbols") or []
    try:
        return next(
            symbol["name"]
            for symbol in symbols
            if isinstance(symbol, dict) and str(symbol.get("name", "")).endswith("function_one")
        )
    except StopIteration as exc:
        raise AssertionError("Unable to resolve function_one by symbol search") from exc


async def _resolve_binary_name(session: ClientSession) -> str:
    binaries_result = await session.call_tool("list_project_binaries", {})
    binaries_payload = json.loads(binaries_result.content[0].text)
    programs = binaries_payload.get("programs") or []
    if len(programs) != 1:
        raise AssertionError(f"Expected exactly one imported binary, got {programs}")
    return programs[0]["name"]


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
        command=sys.executable,
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
            binary_name = await _resolve_binary_name(session)
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
            binary_name = await _resolve_binary_name(session)
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


@pytest.mark.asyncio
async def test_set_function_prototype_tool(variable_server_params, variable_test_binary):
    async with stdio_client(variable_server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = await _resolve_binary_name(session)
            function_name = await _resolve_function_one_name(session, binary_name)

            prototype_result = await session.call_tool(
                "set_function_prototype",
                {
                    "binary_name": binary_name,
                    "function_name_or_address": function_name,
                    "prototype": "long function_one(long count)",
                },
            )
            prototype_payload = json.loads(prototype_result.content[0].text)
            assert prototype_payload["function_name"] == function_name
            assert prototype_payload["old_prototype"].endswith("function_one(int count)")
            assert prototype_payload["new_prototype"].endswith("function_one(long count)")
            assert prototype_payload["old_prototype"].startswith("int ")
            assert prototype_payload["new_prototype"].startswith("long ")

            decompile_result = await session.call_tool(
                "decompile_function",
                {
                    "binary_name": binary_name,
                    "name_or_address": function_name,
                },
            )
            decompile_payload = json.loads(decompile_result.content[0].text)
            assert "long function_one(long count)" in decompile_payload["signature"]


@pytest.mark.asyncio
async def test_set_function_prototype_surfaces_parser_errors(
    variable_server_params, variable_test_binary
):
    async with stdio_client(variable_server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            binary_name = await _resolve_binary_name(session)
            function_name = await _resolve_function_one_name(session, binary_name)
            result = await session.call_tool(
                "set_function_prototype",
                {
                    "binary_name": binary_name,
                    "function_name_or_address": function_name,
                    "prototype": "long function_one(size_t count)",
                },
            )

            assert result.isError is True
            assert "Can't resolve datatype: size_t" in result.content[0].text
