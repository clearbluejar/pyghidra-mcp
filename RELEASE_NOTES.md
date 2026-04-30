# pyghidra-mcp v0.2.0 Release Draft

## Highlights

- Adds GUI-backed mode with `pyghidra-mcp --gui`, letting MCP tools drive a live Ghidra CodeBrowser while sharing the same project and open programs.
- Adds GUI tools for opening programs, changing the active program, and navigating to functions or addresses.
- Adds live edit workflows for renaming functions and variables, setting comments, changing variable types, and setting function prototypes.
- Adds an optional `pyghidra-mcp-cli` package with grouped analysis, edit, and GUI commands for users who prefer a command-line client over direct MCP calls.
- Improves agent-facing tool output by keeping descriptions concise, resolving comment targets more flexibly, and surfacing thunk metadata in symbol search results.
- Improves decompilation and analysis stability with serialized Ghidra bundle-host setup, decompiler cleanup, CI timeouts, and macOS GUI smoke coverage.
- Adds setup diagrams and documentation for headless MCP, GUI-backed MCP, and CLI workflows.

## Compatibility

- Core package: `pyghidra-mcp==0.2.0`
- CLI package: `pyghidra-mcp-cli==0.2.0`
- The CLI development extra now requires `pyghidra-mcp>=0.2.0` so CLI commands match the server tool surface.
- GUI mode requires `--transport streamable-http`; stdio remains the default for headless workflows.

## Publish Checklist

- Verify the release prep PR is green on local repo Linux, CLI, and macOS smoke/compatibility workflows.
- Publish GitHub release `v0.2.0`.
- Confirm both release workflows publish:
  - `pyghidra-mcp` from the repository root.
  - `pyghidra-mcp-cli` from `cli/`.
- Recheck scheduled PyPI package workflows after publication; the current failures are expected against the older PyPI packages.
