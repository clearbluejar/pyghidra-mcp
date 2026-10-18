"""Synchronize pyghidra-mcp source to E:\\03_Devops\\PyGhidraMCP and export all 36 MCP tool schemas."""

from __future__ import annotations

import json
import shutil
from pathlib import Path


PROJECT_SRC = Path(r"E:\02_Projects\pyghidra-mcp\src\pyghidra_mcp")
DEVOPS_PKG = Path(r"E:\03_Devops\PyGhidraMCP\Lib\site-packages\pyghidra_mcp")
DEVOPS_PTH = Path(r"E:\03_Devops\PyGhidraMCP\Lib\site-packages\superghidra.pth")
MCP_DIRS = [
    Path(r"C:\Users\X\.gemini\antigravity-cli\mcp\SuperghidraMCP"),
    Path(r"C:\Users\X\.gemini\antigravity-cli\mcp\pyghidra"),
]


def sync_package_and_schemas() -> None:
    if DEVOPS_PKG.exists():
        for src_file in PROJECT_SRC.glob("*.py"):
            shutil.copy2(src_file, DEVOPS_PKG / src_file.name)

    DEVOPS_PTH.write_text(
        "E:\\02_Projects\\pyghidra-mcp\\src\n"
        "E:\\02_Projects\\SuperGhidra\n"
        "E:\\02_Projects\n",
        encoding="ascii",
    )

    from pyghidra_mcp import server

    tools = server.mcp._tool_manager.list_tools()
    for mcp_dir in MCP_DIRS:
        mcp_dir.mkdir(parents=True, exist_ok=True)
        for tool in tools:
            schema_payload = {
                "name": tool.name,
                "description": tool.description or "",
                "parameters": tool.parameters,
            }
            out_path = mcp_dir / f"{tool.name}.json"
            out_path.write_text(
                json.dumps(schema_payload, separators=(",", ":")),
                encoding="utf-8",
            )

    print(f"Synced {len(tools)} MCP tools to {DEVOPS_PKG} and {[str(d) for d in MCP_DIRS]}")


if __name__ == "__main__":
    sync_package_and_schemas()
