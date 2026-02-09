# PyGhidra MCP CLI

A command-line client for the pyghidra-mcp server, providing a user-friendly interface to interact with Ghidra binary analysis.

## Installation

```bash
pip install pyghidra-mcp-cli
```

Or from source:

```bash
cd cli
pip install -e .
```

## Why HTTP Only?

This CLI connects to pyghidra-mcp **exclusively via HTTP** for the following reasons:

- **No startup overhead**: STDIO mode would spawn a new Java/Ghidra process for each CLI invocation, causing significant delays (10-60 seconds per command)
- **Better lifecycle management**: HTTP server stays running, allowing multiple CLI commands without repeated initialization
- **Clearer error handling**: Connection failures are distinct from Ghidra initialization errors
- **Resource efficiency**: One Ghidra instance serves multiple CLI calls
- **Simpler architecture**: CLI is purely a client, server handles all Ghidra lifecycle management

## Quick Start

### 1. Start the Server

First, start the pyghidra-mcp server in a separate terminal:

```bash
# Option A: Open existing Ghidra project
pyghidra-mcp --transport streamable-http --project-path /path/to/project.gpr

# Option B: Import and analyze a binary
pyghidra-mcp --transport streamable-http --wait-for-analysis /bin/ls

# Option C: Import multiple binaries
pyghidra-mcp --transport streamable-http --wait-for-analysis ./binary1 ./binary2
```

### 2. Use the CLI

Once the server is running, use the CLI to interact with it:

```bash
# List available binaries
pyghidra-mcp-cli list binaries

# Decompile a function
pyghidra-mcp-cli decompile --binary my_binary.dylib main

# Search for symbols
pyghidra-mcp-cli search symbols --binary my_binary.so malloc -l 20
```

## Commands

```bash
pyghidra-mcp-cli [OPTIONS] COMMAND [ARGS...]

Options:
  --host TEXT              Server host (default: 127.0.0.1)
  --port INTEGER           Server port (default: 8000)
  -v, --verbose            Verbose output
  -f, --format             Output: json|table|text (default: text)

Commands:
  decompile    Decompile a function
  search       Search symbols, code, strings
  list         List binaries, imports, exports
  xref         List cross-references
  read         Read memory bytes
  callgraph    Generate call graphs
  import       Import a binary
  delete       Delete a binary
  metadata     Show binary metadata
```

## Command Reference

### decompile

Decompile a function in a binary.

```bash
pyghidra-mcp-cli decompile --binary <binary_name> <function_name_or_address>
```

### search

Search within binaries.

**Search for symbols:**
```bash
pyghidra-mcp-cli search symbols --binary <binary_name> <query> [options]

Options:
  -o, --offset INTEGER    Offset for pagination (default: 0)
  -l, --limit INTEGER     Maximum results (default: 25)
```

**Search for code patterns:**
```bash
pyghidra-mcp-cli search code --binary <binary_name> <query> [options]

Options:
  -l, --limit INTEGER           Maximum results (default: 5)
  -o, --offset INTEGER          Offset for pagination (default: 0)
  -m, --mode [semantic|literal] Search mode (default: semantic)
  --full-code / --preview       Show full code or preview only
  -p, --preview-length INTEGER  Preview length in chars (default: 500)
  -t, --similarity-threshold FLOAT  Minimum similarity 0.0-1.0 (default: 0.0)
```

**Search for strings:**
```bash
pyghidra-mcp-cli search strings --binary <binary_name> <query> [options]

Options:
  -l, --limit INTEGER     Maximum results (default: 100)
```

### list

List information about binaries.

**List all binaries:**
```bash
pyghidra-mcp-cli list binaries
```

**List imports:**
```bash
pyghidra-mcp-cli list imports --binary <binary_name> [options]

Options:
  -q, --query TEXT        Filter by regex pattern (default: .*)
  -o, --offset INTEGER    Offset for pagination (default: 0)
  -l, --limit INTEGER     Maximum results (default: 25)
```

**List exports:**
```bash
pyghidra-mcp-cli list exports --binary <binary_name> [options]

Options:
  -q, --query TEXT        Filter by regex pattern (default: .*)
  -o, --offset INTEGER    Offset for pagination (default: 0)
  -l, --limit INTEGER     Maximum results (default: 25)
```

### xref

List cross-references to a symbol or address.

```bash
pyghidra-mcp-cli xref --binary <binary_name> <name_or_address>
```

### read

Read bytes from memory at an address.

```bash
pyghidra-mcp-cli read --binary <binary_name> <address> [options]

Options:
  -s, --size INTEGER      Number of bytes to read (default: 32)
```

### callgraph

Generate a call graph for a function.

```bash
pyghidra-mcp-cli callgraph --binary <binary_name> <function_name> [options]

Options:
  -d, --direction [calling|called]  Direction (default: calling)
  -t, --type [flow|flow_ends]       Display type (default: flow)
  --condense-threshold INTEGER      Max edges before condensation (default: 50)
  --top-layers INTEGER              Top layers in condensed graph (default: 3)
  --bottom-layers INTEGER           Bottom layers in condensed graph (default: 3)
  --max-run-time INTEGER            Maximum run time in seconds (default: 120)
```

### import

Import a binary into the project.

```bash
pyghidra-mcp-cli import <binary_path>
```

### delete

Delete a binary from the project.

```bash
pyghidra-mcp-cli delete --binary <binary_name>
```

### metadata

Show metadata for a binary.

```bash
pyghidra-mcp-cli metadata --binary <binary_name>
```

## Examples

### Basic Analysis Workflow

```bash
# Terminal 1: Start server with your binary
pyghidra-mcp --transport streamable-http ./malware_sample &

# Wait for analysis to complete (check logs or wait a bit)
sleep 30

# Terminal 2: List available binaries
pyghidra-mcp-cli list binaries

# Find interesting symbols
pyghidra-mcp-cli search symbols --binary malware_sample "crypto" -l 20

# Decompile a key function
pyghidra-mcp-cli decompile --binary malware_sample crypto_init

# List all imports to understand dependencies
pyghidra-mcp-cli list imports --binary malware_sample -l 50

# Check cross-references
pyghidra-mcp-cli xref --binary malware_sample 0x401000

# Generate a call graph
pyghidra-mcp-cli callgraph --binary malware_sample main -d calling

# Show binary metadata
pyghidra-mcp-cli metadata --binary malware_sample
```

### Complete Command Examples

```bash
# List all binaries in project
pyghidra-mcp-cli list binaries

# Search symbols with pagination
pyghidra-mcp-cli search symbols --binary test_binary function -o 0 -l 10

# Search code with semantic mode
pyghidra-mcp-cli search code --binary test_binary "function_one" -m semantic -l 5

# Search strings
pyghidra-mcp-cli search strings --binary test_binary "Hello" -l 10

# List imports with regex filter
pyghidra-mcp-cli list imports --binary test_binary -q ".*printf.*" -l 10

# List exports with regex filter
pyghidra-mcp-cli list exports --binary test_binary -q ".*function.*" -l 10

# Decompile function by name
pyghidra-mcp-cli decompile --binary test_binary main

# Decompile function by address
pyghidra-mcp-cli decompile --binary test_binary 0x401000

# List cross-references to symbol
pyghidra-mcp-cli xref --binary test_binary function_one

# List cross-references to address
pyghidra-mcp-cli xref --binary test_binary 0x401000

# Read bytes from memory
pyghidra-mcp-cli read --binary test_binary 0x100000 -s 32

# Generate call graph (functions called by main)
pyghidra-mcp-cli callgraph --binary test_binary main -d calling -t flow

# Generate call graph (functions that call main)
pyghidra-mcp-cli callgraph --binary test_binary main -d called -t flow_ends

# Import new binary
pyghidra-mcp-cli import /path/to/new_binary

# Delete binary from project
pyghidra-mcp-cli delete --binary test_binary

# Show binary metadata
pyghidra-mcp-cli metadata --binary test_binary
```

### Output Formats

```bash
# Text format (default)
pyghidra-mcp-cli search symbols --binary my_binary.so malloc -l 5

# JSON format for automation
pyghidra-mcp-cli --format json search symbols --binary my_binary.exe malloc | jq '.symbols[0].name'

# Table format for readable output
pyghidra-mcp-cli --format table list imports --binary my_binary.exe
```

### Advanced Search Examples

```bash
# Semantic code search with full code output
pyghidra-mcp-cli search code --binary test_binary "function_one" -m semantic --full-code -l 3

# Literal code search with custom preview
pyghidra-mcp-cli search code --binary test_binary "printf" -m literal -p 100 -l 5

# Code search with similarity threshold
pyghidra-mcp-cli search code --binary test_binary "error handling" -t 0.7 -l 10

# Symbol search with offset for pagination
pyghidra-mcp-cli search symbols --binary test_binary "func" -o 10 -l 20
```

### Call Graph Examples

```bash
# Simple call graph (functions called by main)
pyghidra-mcp-cli callgraph --binary test_binary main

# Reverse call graph (functions that call main)
pyghidra-mcp-cli callgraph --binary test_binary main -d called

# Call graph with flow_ends display type
pyghidra-mcp-cli callgraph --binary test_binary main -t flow_ends

# Call graph with custom condensation settings
pyghidra-mcp-cli callgraph --binary test_binary main --condense-threshold 100 --top-layers 5 --bottom-layers 5

# Call graph with time limit
pyghidra-mcp-cli callgraph --binary test_binary main --max-run-time 300
```

### Working with Different Server Configurations

```bash
# Connect to server on custom port
pyghidra-mcp-cli --port 8080 list binaries

# Connect to remote server
pyghidra-mcp-cli --host 192.168.1.100 --port 8000 list binaries
```

## Environment Variables

Set these for persistent configuration:

```bash
export GHIDRA_INSTALL_DIR="/path/to/ghidra/"
```

## Troubleshooting

### Server Not Running

If you see an error like "Cannot connect to pyghidra-mcp server", the server is not running. Start it first:

```bash
# Start server in background
pyghidra-mcp --transport streamable-http --project-path /path/to/project.gpr &

# Check if server is listening
curl http://localhost:8000/mcp
```

### Binary Not Found

List available binaries first:

```bash
pyghidra-mcp-cli list binaries
```

Then use the exact binary name from the list with the `--binary` flag.

### Connection Timeout

If you get a timeout error, ensure the server is running and accessible:

```bash
# Test connection
curl -m 5 http://localhost:8000/mcp

# Check if server is listening on the expected port
netstat -tlnp | grep 8000
```

## Best Practices for AI Tools and Automation

### Quick Reference for AI Agents

| Task | Command |
|------|---------|
| List binaries | `pyghidra-mcp-cli list binaries` |
| Search symbols | `pyghidra-mcp-cli search symbols --binary BINARY QUERY -l LIMIT` |
| Decompile function | `pyghidra-mcp-cli decompile --binary BINARY FUNCTION` |
| List imports | `pyghidra-mcp-cli list imports --binary BINARY -l LIMIT` |
| List exports | `pyghidra-mcp-cli list exports --binary BINARY -l LIMIT` |
| Generate call graph | `pyghidra-mcp-cli callgraph --binary BINARY FUNCTION -d DIRECTION` |
| Show metadata | `pyghidra-mcp-cli metadata --binary BINARY` |
| Delete binary | `pyghidra-mcp-cli delete --binary BINARY` |

### Scripting Example

```bash
#!/bin/bash

# Start server
pyghidra-mcp --transport streamable-http --wait-for-analysis /path/to/binary &
SERVER_PID=$!

# Wait for server to be ready
sleep 10

# Run analysis commands
pyghidra-mcp-cli list binaries
pyghidra-mcp-cli search symbols --binary my_binary.exe "main" -l 5
pyghidra-mcp-cli decompile --binary my_binary.exe main

# Clean up
kill $SERVER_PID
```

### Test-Driven Examples

The following examples are based on the integration tests in `cli/tests/integration/test_cli_commands.py`:

```bash
# Test binary creation (from test_cli_commands.py:27-51)
cat > test_binary.c << 'EOF'
#include <stdio.h>

void function_one(int x) {
    if (x > 0) {
        printf("Positive: %d", x);
    } else {
        printf("Non-positive: %d", x);
    }
}

void function_two(char* str) {
    printf("%s", str);
}

int main() {
    function_one(42);
    function_two("Hello, World!");
    return 0;
}
EOF

gcc -o test_binary test_binary.c

# Start server with test binary
pyghidra-mcp --transport streamable-http ./test_binary &

# Test all commands (from integration tests)
pyghidra-mcp-cli list binaries
pyghidra-mcp-cli decompile --binary test_binary main
pyghidra-mcp-cli search symbols --binary test_binary "function" -l 10
pyghidra-mcp-cli search code --binary test_binary "function_one" -l 5 --full-code
pyghidra-mcp-cli search strings --binary test_binary "Hello" -l 10
pyghidra-mcp-cli list imports --binary test_binary -q ".*printf.*" -l 10
pyghidra-mcp-cli list exports --binary test_binary -q ".*function.*" -l 10
pyghidra-mcp-cli xref --binary test_binary function_one
pyghidra-mcp-cli read --binary test_binary 100000 -s 32
pyghidra-mcp-cli callgraph --binary test_binary main -d calling -t flow
pyghidra-mcp-cli metadata --binary test_binary
```

### Error Handling

The CLI provides clear error messages when:
- The server is not running (with instructions to start it)
- A binary is not found (suggests listing binaries first)
- Connection times out (check server status)

## Development

```bash
cd cli
make dev-setup      # or create venv manually
pip install -e .

# Run tests
pytest

# Lint
ruff check .
```

## License

MIT - See LICENSE file.
