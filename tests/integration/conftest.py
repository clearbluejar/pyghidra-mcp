import asyncio
import json
import os
import socket
import sys
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio
from dotenv import load_dotenv
from mcp import StdioServerParameters
from mcp import ClientSession


@pytest.fixture(scope="session", autouse=True)
def set_ghidra_env():
    """Ensure GHIDRA_INSTALL_DIR is set in os.environ for all subprocess calls."""
    # Load .env file from project root
    project_root = Path(__file__).parent.parent.parent
    load_dotenv(project_root / ".env", override=True)

    ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")
    if not ghidra_dir:
        pytest.skip(
            "GHIDRA_INSTALL_DIR environment variable not set. "
        )
    os.environ["GHIDRA_INSTALL_DIR"] = ghidra_dir


@pytest.fixture(scope="session")
def free_port():
    """Get a free port for HTTP server testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


@pytest.fixture(scope="session")
def base_url(free_port):
    """Get base URL for testing with dynamic port."""
    return f"http://127.0.0.1:{free_port}"


@pytest.fixture(scope="module")
def test_binary():
    """Create a simple test binary for testing."""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

void function_one() {
    printf("Function One");
}

void function_two() {
    printf("Function Two");
}

int main() {
    printf("Hello, World!");
    function_one();
    function_two();
    return 0;
}
"""
        )
        c_file = f.name

    # On Windows, gcc adds .exe extension automatically
    bin_ext = ".exe" if sys.platform == "win32" else ""
    bin_file = c_file.replace(".c", bin_ext)

    os.system(f"gcc -o {bin_file} {c_file}")

    yield bin_file

    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def test_shared_object():
    """
    Create a simple shared object for testing.
    """
    # 1. Write the C source to a temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

void function_one() {
    printf("Function One");
}

void function_two() {
    printf("Function Two");
}

// No main() needed for a shared library
"""
        )
        c_file = f.name

    # 2. Compile as a shared object (.so on Linux, .dll on Windows)
    shlib_ext = ".dll" if sys.platform == "win32" else ".so"
    so_file = c_file.replace(".c", shlib_ext)
    cmd = f"gcc -fPIC -shared -o {so_file} {c_file}"
    ret = os.system(cmd)
    if ret != 0:
        raise RuntimeError(f"Compilation failed: {cmd}")

    # 3. Yield path to .so/.dll for tests
    yield so_file

    # 4. Clean up
    os.unlink(c_file)
    os.unlink(so_file)


@pytest.fixture(scope="session")
def ghidra_install_dir():
    """Get the Ghidra installation directory from environment or use default."""
    return os.getenv("GHIDRA_INSTALL_DIR", "/ghidra")


@pytest_asyncio.fixture(scope="session")
async def shared_mcp_session(ghidra_install_dir):
    """
    Shared MCP client session for all integration tests.

    This fixture uses setup/teardown pattern:
    - SETUP: Start MCP server, initialize session, and pre-import demo binary once per test SESSION
    - YIELD: Provide the session and pre-imported binary name to all tests
    - TEARDOWN: Close session and cleanup after ALL tests complete

    Benefits:
    - Ghidra starts once for ALL tests (saves ~60s × number_of_modules)
    - Demo binary is pre-imported and analyzed (saves ~30s per test)
    - Tests run much faster after first test
    - Maintains test isolation (tests that need custom binaries can still import them)

    The pre-imported demo binary is available via the 'demo_binary_name' attribute
    of the returned session object.
    """
    from mcp.client.stdio import stdio_client
    from pyghidra_mcp.context import PyGhidraContext

    # SETUP: Start MCP server and initialize session
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "pyghidra_mcp"],  # Use lazy mode with threading
        env={"GHIDRA_INSTALL_DIR": ghidra_install_dir},
    )

    print("\n" + "="*70, flush=True)
    print("SETUP: Starting shared MCP server (this may take 30-60s on first run)", flush=True)
    print("="*70, flush=True)

    # Use MANUAL context management to prevent premature teardown
    # async with would exit after each test, but we want to keep it open for all tests
    stdio_ctx = stdio_client(server_params)
    read, write = await stdio_ctx.__aenter__()

    session_ctx = ClientSession(read, write)
    session = await session_ctx.__aenter__()
    await session.initialize()

    print("SETUP: MCP server ready and initialized", flush=True)

    # PRE-IMPORT: Create and import demo binary for all tests to use
    print("SETUP: Creating and importing demo binary...", flush=True)

    # Create test binary
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

void function_one() {
    printf("Function One");
}

void function_two() {
    printf("Function Two");
}

int main() {
    printf("Hello, World!");
    function_one();
    function_two();
    return 0;
}
"""
        )
        c_file = f.name

    # Compile test binary
    bin_ext = ".exe" if sys.platform == "win32" else ""
    bin_file = c_file.replace(".c", bin_ext)
    ret = os.system(f"gcc -o {bin_file} {c_file}")

    if ret != 0:
        pytest.skip(f"Failed to compile demo binary: {bin_file}")

    try:
        # Import binary and wait for analysis + code + strings
        demo_binary_name = PyGhidraContext._gen_unique_bin_name(bin_file)
        await session.call_tool("import_binary", {"binary_path": bin_file})

        print("SETUP: Demo binary import initiated, waiting for analysis...", flush=True)

        # Wait for binary to be fully analyzed and collections ready
        timeout_seconds = 240
        start_time = asyncio.get_event_loop().time()
        while (asyncio.get_event_loop().time() - start_time) < timeout_seconds:
            await asyncio.sleep(1)

            response = await session.call_tool("list_project_binaries", {})

            if not response.content:
                continue

            text_content = response.content[0].text

            if not text_content or not text_content.strip():
                continue

            try:
                program_infos = json.loads(text_content)["programs"]
            except (json.JSONDecodeError, KeyError):
                continue

            for program in program_infos:
                if demo_binary_name in program["name"]:
                    # Check if analysis and collections are complete
                    if (program.get("analysis_complete") and
                        program.get("code_collection") and
                        program.get("strings_collection")):
                        print(f"SETUP: Demo binary '{demo_binary_name}' ready for use", flush=True)
                        print("="*70 + "\n", flush=True)
                        break
            else:
                # Continue waiting
                continue
            break
        else:
            raise TimeoutError(
                f"Demo binary not ready after {timeout_seconds} seconds"
            )

        # Attach demo binary name to session for easy access
        session.demo_binary_name = demo_binary_name

        try:
            # YIELD: Provide session to tests (connection stays open)
            yield session
        finally:
            # TEARDOWN: Cleanup only after ALL tests in session complete
            print("\n" + "="*70, flush=True)
            print("TEARDOWN: Closing shared MCP session", flush=True)
            print("="*70, flush=True)

            try:
                await session_ctx.__aexit__(None, None, None)
                await stdio_ctx.__aexit__(None, None, None)
                print("TEARDOWN: MCP session closed successfully", flush=True)
            except Exception as e:
                print(f"TEARDOWN: Warning - error during cleanup: {e}", flush=True)

            print("="*70 + "\n", flush=True)

    finally:
        # Clean up demo binary files
        try:
            os.unlink(c_file)
            os.unlink(bin_file)
        except:
            pass


@pytest.fixture(scope="module")
def server_params_no_input(ghidra_install_dir):
    """Get server parameters with no test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--wait-for-analysis"],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": ghidra_install_dir},
    )


@pytest.fixture(scope="module")
def server_params(test_binary, ghidra_install_dir):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--wait-for-analysis", test_binary],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": ghidra_install_dir},
    )


@pytest.fixture(scope="module")
def server_params_no_thread(test_binary, ghidra_install_dir):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--no-threaded", test_binary],  # no-thread for chromadb_testing
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": ghidra_install_dir},
    )


@pytest.fixture(scope="module")
def server_params_shared_object(test_shared_object, ghidra_install_dir):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--wait-for-analysis", test_shared_object],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": ghidra_install_dir},
    )


@pytest.fixture()
def find_binary_in_list_response():
    """Return a helper that finds a binary by generated name in a list_project_binaries response."""

    def _finder(response, binary_name):
        text_content = response.content[0].text
        program_infos = json.loads(text_content)["programs"]

        for program in program_infos:
            if binary_name in program["name"]:
                return program

        return None

    return _finder


@pytest.fixture()
def import_binary_and_wait():
    """
    Async helper function that imports a binary and waits for specified conditions.
    This is needed for lazy initialization mode where binaries are not auto-imported.

    NOTE: This fixture is synchronous (returns an async function) because it
    just creates and returns the async helper. Tests will await the returned function.

    Usage:
        # Wait for analysis only (fastest - for tests that don't need search)
        await import_binary_and_wait(session, binary_path, wait_for_code=False, wait_for_strings=False)

        # Wait for analysis + code only (for search_code tests)
        await import_binary_and_wait(session, binary_path, wait_for_strings=False)

        # Wait for analysis + strings only (for search_strings tests)
        await import_binary_and_wait(session, binary_path, wait_for_code=False)

        # Wait for analysis + code + strings (default, slowest - for tests needing both)
        await import_binary_and_wait(session, binary_path)
    """

    async def _importer(
        session: ClientSession,
        binary_path: str,
        timeout_seconds: int = 240,
        wait_for_code: bool = True,
        wait_for_strings: bool = True,
    ):
        from pyghidra_mcp.context import PyGhidraContext

        binary_name = PyGhidraContext._gen_unique_bin_name(binary_path)

        # Import the binary
        response = await session.call_tool("import_binary", {"binary_path": binary_path})

        # Wait for analysis to complete AND collections to be ready (if requested)
        start_time = asyncio.get_event_loop().time()
        while (asyncio.get_event_loop().time() - start_time) < timeout_seconds:
            await asyncio.sleep(1)

            response = await session.call_tool("list_project_binaries", {})

            # Debug: Check response structure
            if not response.content:
                print(f"Warning: Empty response.content, retrying...")
                continue

            text_content = response.content[0].text

            # Handle empty or invalid responses
            if not text_content or not text_content.strip():
                print(f"Warning: Empty text_content (response.content length: {len(response.content)})")
                # Try to print all content items for debugging
                for i, c in enumerate(response.content):
                    print(f"  content[{i}]: type={type(c)}, has_text={hasattr(c, 'text')}")
                continue

            try:
                program_infos = json.loads(text_content)["programs"]
            except (json.JSONDecodeError, KeyError) as e:
                # Response might not be ready yet or server might have issues
                print(f"Warning: Failed to parse list_project_binaries response: {e}")
                print(f"Response content: {repr(text_content[:200])}")  # Print first 200 chars
                continue

            for program in program_infos:
                if binary_name in program["name"]:
                    # Check if analysis is complete (always required)
                    if not program.get("analysis_complete"):
                        continue

                    # Check if code collection is ready (only if requested)
                    if wait_for_code and not program.get("code_collection"):
                        continue

                    # Check if strings collection is ready (only if requested)
                    if wait_for_strings and not program.get("strings_collection"):
                        continue

                    # All conditions met
                    return binary_name

        raise TimeoutError(
            f"Binary {binary_name} not ready after {timeout_seconds} seconds "
            f"(analysis_complete={wait_for_code and 'code+' or ''}{wait_for_strings and 'strings' or ''})"
        )

    return _importer
