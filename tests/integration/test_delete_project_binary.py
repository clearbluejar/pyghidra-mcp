import asyncio
import json
import os
import sys
import tempfile

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import (
    ProgramInfos,
)


@pytest.mark.asyncio
async def test_delete_project_binary(shared_mcp_session):
    """Test the delete_project_binary tool."""

    # Use shared MCP session
    session = shared_mcp_session

    # Create a temporary binary to delete (don't use the pre-imported demo binary)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

void temp_function() {
    printf("Temporary function");
}

int main() {
    printf("Temporary binary");
    return 0;
}
"""
        )
        c_file = f.name

    # Compile temporary binary
    bin_ext = ".exe" if sys.platform == "win32" else ""
    bin_file = c_file.replace(".c", bin_ext)
    ret = os.system(f"gcc -o {bin_file} {c_file}")

    if ret != 0:
        pytest.skip(f"Failed to compile temporary binary: {bin_file}")

    try:
        # Import temporary binary
        await session.call_tool("import_binary", {"binary_path": bin_file})

        # Wait for import to complete
        temp_binary_name = PyGhidraContext._gen_unique_bin_name(bin_file)
        timeout_seconds = 60
        start_time = asyncio.get_event_loop().time()
        imported = False

        while (asyncio.get_event_loop().time() - start_time) < timeout_seconds:
            await asyncio.sleep(1)

            tool_resp = await session.call_tool("list_project_binaries", {})
            program_infos_result = json.loads(tool_resp.content[0].text)
            program_infos = ProgramInfos(**program_infos_result)

            names = [b.name for b in program_infos.programs]
            if temp_binary_name in names:
                imported = True
                break

        if not imported:
            pytest.skip(f"Temporary binary not imported within {timeout_seconds}s")

        # Delete the binary
        tool_resp = await session.call_tool(
            "delete_project_binary", {"binary_name": temp_binary_name}
        )
        assert tool_resp is not None
        delete_result = tool_resp.content[0].text
        assert "Successfully deleted binary" in delete_result

        # Verify that the binary is deleted
        tool_resp = await session.call_tool("list_project_binaries", {})
        program_infos_result = json.loads(tool_resp.content[0].text)
        program_infos = ProgramInfos(**program_infos_result)

        assert program_infos is not None
        names = [b.name for b in program_infos.programs]
        assert temp_binary_name not in names

    finally:
        # Clean up temporary files
        try:
            os.unlink(c_file)
            os.unlink(bin_file)
        except:
            pass
