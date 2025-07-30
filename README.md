<p align="center">
  <img src="https://github.com/user-attachments/assets/f9a6756c-a1aa-402d-8e61-b7e384967836" width=60% >
</p>

<p align="center">
  <a href="https://semgrep.dev/docs/">
      <img src="https://img.shields.io/badge/PyGhidra-docs-2acfa6?style=flat-square" alt="Documentation" />
  </a>
  <img align="center" alt="GitHub Workflow Status (with event)" src="https://img.shields.io/github/actions/workflow/status/clearbluejar/ghidriff/pytest-devcontainer.yml?label=pytest&style=for-the-badge">
  <img align="center" alt="PyPI - Downloads" src="https://img.shields.io/pypi/dm/pyghidra-mcp?color=yellow&label=PyPI%20downloads&style=for-the-badge">
  <img align="center" src="https://img.shields.io/github/stars/clearbluejar/pyghidra-mcp?style=for-the-badge">
</p>

# PyGhidra-MCP - Ghidra Model Context Protocol Server

`pyghidra-mcp` provides a Model Context Protocol (MCP) server for interacting with Ghidra, a software reverse engineering (SRE) suite of tools. It leverages the power of Ghidra's ProgramAPI and [FlatProgramAPI](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html) through `pyghidra` and `jpype` as the Python to Java interface.

[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) is a standardized API for LLMs, Agents, and IDEs like Cursor, VS Code, Windsurf, or anything that supports MCP, to get specialized help, get context, and harness the power of tools. PyGhidra-MCP aims to expose Ghidra's powerful analysis capabilities to these intelligent agents.

> [!NOTE]
> This beta project is under active development. We would love your feedback, bug reports, feature requests, and code.

## Contents

- [PyGhidra-MCP - Ghidra Model Context Protocol Server](#pyghidra-mcp---ghidra-model-context-protocol-server)
  - [Contents](#contents)
  - [Getting started](#getting-started)
  - [Setup and Testing with uv](#setup-and-testing-with-uv)
    - [Setup](#setup)
    - [Testing](#testing)
  - [API](#api)
    - [Tools](#tools)
      - [Decompile Function](#decompile-function)
      - [Search Functions](#search-functions)
      - [Get Program Info](#get-program-info)
    - [Prompts](#prompts)
    - [Resources](#resources)
  - [Usage](#usage)
    - [Standard Input/Output (stdio)](#standard-inputoutput-stdio)
      - [Python](#python)
      - [Docker](#docker)
    - [Streamable HTTP](#streamable-http)
      - [Python](#python-1)
      - [Docker](#docker-1)
    - [Server-sent events (SSE)](#server-sent-events-sse)
      - [Python](#python-2)
      - [Docker](#docker-2)
  - [Integrations](#integrations)
  - [Contributing, community, and running from source](#contributing-community-and-running-from-source)

## Getting started

Run the [Python package](https://pypi.org/p/pyghidra-mcp) as a CLI command using [`uv`](https://docs.astral.sh/uv/guides/tools/):

```bash
uvx pyghidra-mcp # see --help for more options
```

Or, run as a [Docker container](https://ghcr.io/clearbluejar/pyghidra-mcp):

```bash
docker run -i --rm ghcr.io/clearbluejar/pyghidra-mcp -t stdio
```

## Setup and Testing with uv

This project uses `uv` for dependency management and testing.

### Setup

1.  **Install `uv`**: If you don't have `uv` installed, you can install it using pip:
    ```bash
    pip install uv
    ```
    Or, follow the official `uv` installation guide: [https://docs.astral.sh/uv/install/](https://docs.astral.sh/uv/install/)

2.  **Create a virtual environment and install dependencies**:
    ```bash
    uv venv
    source ./.venv/bin/activate
    uv pip install -e .
    ```

3.  **Set Ghidra Environment Variable**: Download and install Ghidra, then set the `GHIDRA_INSTALL_DIR` environment variable to your Ghidra installation directory.
    ```bash
    # For Linux / Mac
    export GHIDRA_INSTALL_DIR="/path/to/ghidra/"

    # For Windows PowerShell
    [System.Environment]::SetEnvironmentVariable('GHIDRA_INSTALL_DIR','C:\ghidra_10.2.3_PUBLIC_20230208\ghidra_10.2.3_PUBLIC')
    ```

### Testing

To run tests using `uv`:

```bash
uv run pytest
```

## API

### Tools

Enable LLMs to perform actions, make deterministic computations, and interact with external services.

#### Decompile Function

- `decompile_function`: Decompile a function from a given binary.

#### Search Functions

- `search_functions`: Search for functions within a binary based on various criteria.

#### Get Program Info

- `get_program_info`: Retrieve general information about the loaded Ghidra program.

### Prompts

Reusable prompts to standardize common LLM interactions.

- `write_ghidra_script`: Return a prompt to help write a Ghidra script.

### Resources

Expose data and content to LLMs

- `ghidra://program/{program_name}/function/{function_name}/decompiled`: Decompiled code of a specific function.

## Usage

This Python package is published to PyPI as [pyghidra-mcp](https://pypi.org/p/pyghidra-mcp) and can be installed and run with [pip](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/#install-a-package), [pipx](https://pipx.pypa.io/), [uv](https://docs.astral.sh/uv/), [poetry](https://python-poetry.org/), or any Python package manager.

```text
$ pipx install pyghidra-mcp
$ pyghidra-mcp --help

Usage: pyghidra-mcp [OPTIONS]

  Entry point for the MCP server

  Supports both stdio and sse transports. For stdio, it will read from stdin
  and write to stdout. For sse, it will start an HTTP server on port 8000.

Options:
  -v, --version                Show version and exit.
  -t, --transport [stdio|sse]  Transport protocol to use (stdio or sse)
  -h, --help                   Show this message and exit.
```

### Standard Input/Output (stdio)

The stdio transport enables communication through standard input and output streams. This is particularly useful for local integrations and command-line tools. See the [spec](https://modelcontextprotocol.io/docs/concepts/transports#built-in-transport-types) for more details.

#### Python

```bash
pyghidra-mcp
```

By default, the Python package will run in `stdio` mode. Because it's using the standard input and output streams, it will look like the tool is hanging without any output, but this is expected.

#### Docker

This server is published to Github's Container Registry ([ghcr.io/clearbluejar/pyghidra-mcp](http://ghcr.io/clearbluejar/pyghidra-mcp))

```
docker run -i --rm ghcr.io/clearbluejar/pyghidra-mcp -t stdio
```

By default, the Docker container is in `SSE` mode, so you will have to include `-t stdio` after the image name and run with `-i` to run in [interactive](https://docs.docker.com/reference/cli/docker/container/run/#interactive) mode.

### Streamable HTTP

Streamable HTTP enables streaming responses over JSON RPC via HTTP POST requests. See the [spec](https://modelcontextprotocol.io/specification/draft/basic/transports#streamable-http) for more details.

By default, the server listens on [127.0.0.1:8000/mcp](https://127.0.0.1/mcp) for client connections. To change any of this, set [FASTMCP\_\*](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/server/fastmcp/server.py#L78) environment variables. _The server must be running for clients to connect to it._

#### Python

```bash
pyghidra-mcp -t streamable-http
```

By default, the Python package will run in `stdio` mode, so you will have to include `-t streamable-http`.

#### Docker

```
docker run -p 8000:0000 ghcr.io/clearbluejar/pyghidra-mcp
```

### Server-sent events (SSE)

> [!WARNING]
> The MCP communiity considers this a legacy transport portcol and is really intended for backwards compatibility. [Streamable HTTP](#streamable-http) is the recommended replacement.

SSE transport enables server-to-client streaming with Server-Send Events for client-to-server and server-to-client communication. See the [spec](https://modelcontextprotocol.io/docs/concepts/transports#server-sent-events-sse) for more details.

By default, the server listens on [127.0.0.1:8000/sse](https://127.0.0.1/sse) for client connections. To change any of this, set [FASTMCP\_\*](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/server/fastmcp/server.py#L78) environment variables. _The server must be running for clients to connect to it._

#### Python

```bash
pyghidra-mcp -t sse
```

By default, the Python package will run in `stdio` mode, so you will have to include `-t sse`.

#### Docker

```
docker run -p 8000:0000 ghcr.io/clearbluejar/pyghidra-mcp -t sse
```

## Integrations

(To be filled with specific integration examples for Cursor, VS Code, etc., similar to semgrep's README)

## Contributing, community, and running from source

> [!NOTE]
> We love your feedback, bug reports, feature requests, and code. Join the community Slack channel! (Link to be added)

See [CONTRIBUTING.md](CONTRIBUTING.md) for more info and details on how to run from the MCP server from source code.

______________________________________________________________________

Made with ❤️ by the [PyGhidra-MCP Team](https://github.com/clearbluejar/pyghidra-mcp)
