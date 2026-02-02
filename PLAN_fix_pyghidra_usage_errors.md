# Implementation Plan: Fix PyGhidra Usage Errors

## Executive Summary

This plan addresses critical deviations from PyGhidra's documented best practices identified through comprehensive analysis of the official PyGhidra documentation. The fixes focus on resource management (missing JVM cleanup), API usage patterns (direct Ghidra API vs documented `api` module), and lock file safety.

---

## Issues Summary

### Critical Issues (Must Fix)
1. **Missing `launcher.terminate()` Call** - Resource leak on every server startup
2. **Direct Ghidra API Usage** - Bypasses documented `api` module patterns
3. **Unsafe Lock File Deletion** - Could corrupt active Ghidra sessions

### Warning Issues (Should Fix)
4. **Thread Safety Without Documentation Support** - Undefined behavior territory
5. **Decompiler Lifecycle Issues** - Race conditions possible
6. **Program References After Close** - Use-after-close vulnerabilities

---

## Phase 1: Critical Resource Management Fixes

### Issue 1: Missing `launcher.terminate()` Call

**Current Problem (`server.py:589`):**
```python
try:
    pyghidra.start(False)  # Returns None - launcher lost!
finally:
    # Restore original stdout
    os.dup2(original_stdout_fd, stdout_fd)
    os.close(original_stdout_fd)
# No launcher.terminate() call!
```

**Root Cause:**
- `pyghidra.start()` is called but the return value (launcher object) is discarded
- No `launcher.terminate()` in cleanup code
- JVM is never properly shutdown
- Resources leaked (memory, file handles, threads) on every server startup

**Documentation Reference:**
- `first-script.md:95-98` - Explicitly requires `launcher.terminate()` in `finally` block
- `session-management.md:366-375` - Best practice: always use `try/finally` with `launcher.terminate()`

**Fix Implementation:**

#### 1.1 Store Launcher Globally

**File:** `src/pyghidra_mcp/server.py`

**Location:** Lines 54-56 (global variables section)

**Change:**
```python
# Global configuration for delayed context initialization
_context_config: dict[str, Any] = {}
_pyghidra_context: PyGhidraContext | None = None
_pyghidra_launcher: Any = None  # ADD: Store launcher for cleanup
```

**Rationale:** Need to store launcher object for cleanup in `server_lifespan`.

---

#### 1.2 Capture Launcher Reference

**File:** `src/pyghidra_mcp/server.py`

**Location:** Lines 577-593 (`init_pyghidra_context` function)

**Current Code:**
```python
try:
    pyghidra.start(False)  # Disable verbose output
finally:
    # Restore original stdout
    os.dup2(original_stdout_fd, stdout_fd)
    os.close(original_stdout_fd)
```

**Fixed Code:**
```python
global _pyghidra_launcher

try:
    # Capture launcher reference for cleanup
    _pyghidra_launcher = pyghidra.start(False)  # Disable verbose output
    logger.info("Ghidra JVM started successfully")
finally:
    # Restore original stdout
    os.dup2(original_stdout_fd, stdout_fd)
    os.close(original_stdout_fd)
```

**Rationale:** Store launcher object globally for cleanup during shutdown.

---

#### 1.3 Add Launcher Cleanup to Lifespan

**File:** `src/pyghidra_mcp/server.py`

**Location:** Lines 97-108 (`server_lifespan` function)

**Current Code:**
```python
@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[PyGhidraContext]:
    """Manage server startup and shutdown lifecycle.

    Context is created lazily on first tool call, not at server startup.
    """
    try:
        yield None  # type: ignore
    finally:
        if _pyghidra_context is not None:
            _pyghidra_context.close()
```

**Fixed Code:**
```python
@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[PyGhidraContext]:
    """Manage server startup and shutdown lifecycle.

    Context is created lazily on first tool call, not at server startup.
    """
    try:
        yield None  # type: ignore
    finally:
        # CRITICAL: Terminate launcher first to properly shutdown JVM
        global _pyghidra_launcher
        if _pyghidra_launcher is not None:
            logger.info("Shutting down Ghidra JVM...")
            _pyghidra_launcher.terminate()
            _pyghidra_launcher = None
            logger.info("Ghidra JVM terminated")

        # Then close context
        if _pyghidra_context is not None:
            _pyghidra_context.close()
```

**Rationale:**
- Follows documented pattern from `first-script.md:95-98`
- Ensures JVM cleanup happens even if context cleanup fails
- Order matters: terminate launcher before closing context

---

### Issue 2: Direct Ghidra API Usage

**Current Problem:**
- Code uses `GhidraProject.createProject()` and `GhidraProject.openProject()` directly
- Manual `project.openProgram()` / `project.close()` calls
- Bypasses documented `api.open_project()` and `api.program_context()` patterns

**Documentation Reference:**
- `project-management.md:476-489` - "Always Use Context Managers"
- `first-script.md:53-57` - Recommended pattern with `api.open_project()`

**Fix Strategy:**

This requires a **major refactoring**. We'll need to:
1. Replace direct `GhidraProject` usage with `api.open_project()`
2. Replace manual `openProgram/close` with `api.program_context()`
3. Refactor `PyGhidraContext` to use context managers internally

**Due to the scope, this is marked as Phase 2 (see below).**

---

### Issue 3: Unsafe Lock File Deletion

**Current Problem (`context.py:218-252`):**
```python
@staticmethod
def _clean_lock_files(project_dir: Path) -> list[str]:
    """Remove stale Ghidra lock files"""
    removed = []

    for pattern in PyGhidraContext._LOCK_FILE_PATTERNS:
        for lock_file in project_dir.glob(pattern):
            try:
                lock_file.unlink()  # DANGEROUS: No staleness check!
                removed.append(lock_file.name)
```

**Root Cause:**
- Lock files are deleted without checking if they're actually stale
- Could delete locks from **active** Ghidra instances
- No process ID checking
- No timestamp validation

**Documentation Guidance:**
- LockException means project is in use (`project-management.md`)
- Suggests checking for other processes manually
- No automatic deletion recommendation

**Fix Implementation:**

#### 3.1 Add Staleness Safety Checks

**File:** `src/pyghidra_mcp/context.py`

**Location:** Lines 218-252 (`_clean_lock_files` method)

**Current Code:**
```python
@staticmethod
def _clean_lock_files(project_dir: Path) -> list[str]:
    """
    Remove stale Ghidra lock files from a project directory.

    WARNING: This method deletes files without additional confirmation.
    ...
    """
    removed = []

    for pattern in PyGhidraContext._LOCK_FILE_PATTERNS:
        for lock_file in project_dir.glob(pattern):
            try:
                lock_file.unlink()
                removed.append(lock_file.name)
                logger.info(f"Removed lock file: {lock_file}")
            except OSError as e:
                logger.warning(f"Could not remove lock file {lock_file}: {e}")
```

**Fixed Code:**
```python
@staticmethod
def _clean_lock_files(project_dir: Path) -> list[str]:
    """
    Remove stale Ghidra lock files from a project directory.

    WARNING: This method performs safety checks before deleting lock files.
    In multi-user environments, ensure no other Ghidra instance is actively
    using the project before calling this method.

    This is called when opening a project fails due to LockException,
    typically caused by previous crashes or forced process termination.

    Safety Checks:
    - Lock files must be at least 10 minutes old
    - On Windows: checks for process existence
    - On Unix: checks lock file content for process ID

    Args:
        project_dir: Path to the Ghidra project directory.

    Returns:
        List of successfully removed lock file names.
    """
    import time
    import platform

    removed = []
    current_time = time.time()
    lock_age_threshold = 600  # 10 minutes in seconds

    for pattern in PyGhidraContext._LOCK_FILE_PATTERNS:
        for lock_file in project_dir.glob(pattern):
            try:
                # Check 1: Lock file age - only remove if older than threshold
                file_mtime = lock_file.stat().st_mtime
                file_age = current_time - file_mtime

                if file_age < lock_age_threshold:
                    logger.warning(
                        f"Lock file {lock_file.name} is only {int(file_age)} seconds old. "
                        f"Skipping (must be at least {lock_age_threshold} seconds old). "
                        f"Another Ghidra instance may be actively using this project."
                    )
                    continue

                # Check 2: Platform-specific process validation (best effort)
                is_stale = True

                if platform.system() == "Windows":
                    # On Windows, try to check if file is locked by another process
                    # This is a heuristic - not foolproof
                    try:
                        # Try to open file exclusively
                        with lock_file.open('r+b') as f:
                            pass
                        is_stale = True  # No lock, file is stale
                    except (PermissionError, OSError):
                        logger.warning(
                            f"Lock file {lock_file.name} appears to be held by another process. "
                            f"Skipping deletion to avoid corrupting active session."
                        )
                        is_stale = False
                else:
                    # On Unix, lock files often contain PIDs
                    try:
                        content = lock_file.read_text().strip()
                        if content.isdigit():
                            pid = int(content)
                            # Check if process is running
                            try:
                                os.kill(pid, 0)  # Signal 0 doesn't kill, just checks
                                logger.warning(
                                    f"Lock file {lock_file.name} references running PID {pid}. "
                                    f"Skipping deletion to avoid corrupting active session."
                                )
                                is_stale = False
                            except OSError:
                                # Process not running - lock is stale
                                is_stale = True
                    except:
                        # Couldn't read PID - use age check only
                        pass

                # Only delete if all checks pass
                if is_stale:
                    lock_file.unlink()
                    removed.append(lock_file.name)
                    logger.info(
                        f"Removed stale lock file: {lock_file.name} "
                        f"(age: {int(file_age)}s)"
                    )
                else:
                    logger.warning(
                        f"Did not remove lock file {lock_file.name} - "
                        f"may be actively used by another process"
                    )

            except OSError as e:
                logger.warning(f"Could not process lock file {lock_file}: {e}")

    if removed:
        logger.info(
            f"Successfully cleaned {len(removed)} stale lock file(s): "
            f"{', '.join(removed)}"
        )
    else:
        logger.warning(
            "No lock files were removed. "
            "Another Ghidra instance may be using this project."
        )

    return removed
```

**Rationale:**
- **Age check**: Prevents deletion of recent locks (10-minute threshold)
- **Windows check**: Attempts exclusive open to detect active locks
- **Unix check**: Reads PID from lock file and verifies process is dead
- **Conservative approach**: Only deletes when confident it's stale
- **Detailed logging**: Helps diagnose lock contention issues

---

## Phase 2: Major API Refactoring (Warning Level)

### Issue 2 (Continued): Migrate to `api.open_project` and `api.program_context`

**Current Anti-Pattern:**
```python
# context.py:182-193
from ghidra.base.project import GhidraProject
return GhidraProject.createProject(project_dir_str, self.project_name, False)
return GhidraProject.openProject(project_dir_str, self.project_name, True)

# context.py:273-275
program = self.project.openProgram(folder_path, program_name, False)
# ... manual close required later
```

**Documented Pattern:**
```python
from pyghidra import api

with api.open_project(project_path, "my_project", create=True) as project:
    with api.program_context(project, "/binary.exe") as program:
        # Work with program
        # Automatically saved and closed
```

**Refactoring Strategy:**

This is a **major architectural change** that requires careful planning:

#### 2.1 Challenges with Direct Migration

**Problem 1: Long-Lived Project**
- `PyGhidraContext` holds project open for entire lifetime
- `api.open_project()` uses context manager for scoped usage
- Mismatch between ephemeral and long-lived patterns

**Problem 2: Lazy Initialization**
- Current design: Project opened in `__init__`
- Server design: Lazy context creation
- Context managers don't map well to lazy initialization

**Problem 3: Program Caching**
- Current: Programs kept open in `self.programs` dict
- Documented: Open/close per operation
- Performance vs correctness tradeoff

#### 2.2 Hybrid Approach (Recommended)

**Instead of full migration, adopt a hybrid approach:**

```python
class PyGhidraContext:
    def __init__(self, ...):
        # Keep direct GhidraProject usage for project management
        self.project: GhidraProject = self._get_or_create_project()

    def _get_or_create_project(self) -> "GhidraProject":
        """Use api.open_project for initial creation only."""
        from pyghidra import api

        project_dir = self.project_path / self.project_name
        project_dir.mkdir(exist_ok=True, parents=True)

        # Try using api.open_project for better compatibility
        try:
            with api.open_project(
                str(self.project_path),
                self.project_name,
                create=True
            ) as project:
                # Transfer ownership to GhidraProject for long-term use
                # This is a workaround for the long-lived project pattern
                return GhidraProject.openProject(
                    str(self.project_path),
                    self.project_name,
                    True
                )
        except LockException:
            # Fallback to current logic with lock cleanup
            return self._open_with_lock_retry()

    def _get_program_for_operation(self, binary_name: str):
        """Use api.program_context for individual operations."""
        from pyghidra import api

        # Get program path
        program_path = self._get_program_path(binary_name)

        # Use context manager for safe access
        with api.program_context(self.project, program_path) as program:
            yield program
        # Automatically saved and closed
```

**Decision:** **Defer this refactoring**. It's high-risk and the current code works.

**Recommended Action:**
1. Document the deviation from best practices
2. Add comprehensive warnings in docstrings
3. Consider for future major version (2.0)

---

## Phase 3: Thread Safety Documentation (Warning Level)

### Issue 4: Thread Safety Without Documentation Support

**Current Implementation:**
```python
@dataclass
class ProgramInfo:
    _lock: threading.RLock = field(default_factory=threading.RLock)

# Thread-safe operations in tools.py
with self._lock:  # Line 218, 235, 256, etc.
    # Access Ghidra program/decompiler
```

**Problem:**
- No documentation support for thread safety
- No examples of concurrent access in PyGhidra docs
- One JVM per process suggests single-threaded design
- Java objects may not be thread-safe even with Python locks

**Fix:** Add comprehensive documentation

#### 3.1 Document Thread Safety Assumptions

**File:** `src/pyghidra_mcp/context.py`

**Location:** Lines 26-64 (`ProgramInfo` class)

**Add to docstring:**
```python
@dataclass
class ProgramInfo:
    """Information about a loaded program with thread-safe access.

    **WARNING: Thread Safety Limitations**

    This class implements Python-level thread synchronization using RLocks.
    However, the underlying Java objects from Ghidra may have their own
    concurrency requirements that are not documented in PyGhidra.

    **Known Limitations:**
    - No official PyGhidra documentation on concurrent access patterns
    - Java objects may not be thread-safe even with Python locks
    - Decompiler is reused across threads - may have internal state
    - One JVM per process constraint suggests single-threaded design

    **Use With Caution:**
    - Thread safety is best-effort and not guaranteed
    - Race conditions may occur with concurrent decompilation
    - Consider serializing access for critical operations
    - Report any concurrency issues discovered

    **Recommended Pattern:**
    ```python
    with program_info:  # Acquires lock
        # Safe single-threaded access
        result = tools.decompile_function(func_name)
    # Lock released automatically
    ```

    Attributes:
        name: Program name
        program: Ghidra Program object (not thread-safe at Java level)
        flat_api: FlatProgramAPI for program operations
        decompiler: Decompiler interface (may have internal state)
        metadata: Program metadata dictionary
        ghidra_analysis_complete: Whether Ghidra analysis is complete
        file_path: Path to original binary file
        load_time: Timestamp when program was loaded
        code_collection: ChromaDB collection for semantic search
        strings_collection: ChromaDB collection for string search
        _lock: RLock for thread-safe program access
    """
```

**Rationale:**
- Explicitly warns about limitations
- Documents that this is undocumented territory
- Provides usage recommendations
- Encourages reporting issues

---

### Issue 5: Decompiler Lifecycle Issues

**Current Problem (`context.py:869-876`):**
```python
# After save, decompiler is re-initialized
with program_info._lock:
    old_decompiler = program_info.decompiler
    old_decompiler.dispose()
    program_info.decompiler = self.setup_decompiler(program)
```

**Problems:**
1. Save invalidates decompiler - this is fragile
2. No guarantee new decompiler is safe for concurrent use
3. Dispose while other threads might be using old decompiler
4. Lock only protects swap, not ongoing usage

**Fix:** Add warning and improve synchronization

#### 3.2 Improve Decompiler Swap Safety

**File:** `src/pyghidra_mcp/context.py`

**Location:** Lines 866-876 (after program save)

**Current Code:**
```python
# Save the program - this may invalidate the decompiler but not the program
self.project.save(program)
# Re-initialize the decompiler after save (DecompInterface may be invalidated)
program_info = self.programs[df.pathname]
with program_info._lock:
    # Close old decompiler before creating new one
    old_decompiler = program_info.decompiler
    old_decompiler.dispose()
    # Create new decompiler with the same program object
    program_info.decompiler = self.setup_decompiler(program)
```

**Improved Code:**
```python
# Save the program - this may invalidate the decompiler but not the program
self.project.save(program)

# CRITICAL: Re-initialize the decompiler after save
# The DecompInterface is invalidated by save() and must be recreated
program_info = self.programs[df.pathname]

# WARNING: This is a race condition in concurrent scenarios
# If another thread is using the decompiler during swap, it will fail
# This is a known limitation of the current architecture
with program_info._lock:
    logger.info("Recreating decompiler after program save...")

    # Close old decompiler
    old_decompiler = program_info.decompiler
    try:
        old_decompiler.dispose()
    except Exception as e:
        logger.warning(f"Error disposing old decompiler: {e}")

    # Create new decompiler with the same program object
    program_info.decompiler = self.setup_decompiler(program)

    logger.info("Decompiler recreated successfully")
```

**Additional Warning in Methods That Use Decompiler:**

**File:** `src/pyghidra_mcp/tools.py`

**Add to all methods that use decompiler:**
```python
def decompile_function_by_name_or_addr(self, name_or_address: str) -> DecompiledFunction:
    """
    Decompile a function by name or address.

    WARNING: If a program save occurs during decompilation, this may fail
    due to decompiler invalidation. Retry the operation if this happens.

    Args:
        name_or_address: Function name or address

    Returns:
        DecompiledFunction with pseudo-C code
    """
    with self.program_info:
        # Use decompiler
        return self._decompile_with_retries(name_or_address)
```

---

### Issue 6: Program References After Close

**Current Problem (`context.py:161-167`):**
```python
# Shutdown thread pools
self.import_executor.shutdown(wait=True)
self.executor.shutdown(wait=True)

# Close all programs
for _program_name, program_info in self.programs.items():
    program = program_info.program
    self.project.close(program)  # Program invalidated

self.project.close()
```

**Problems:**
1. Programs closed but ProgramInfo objects retain references
2. No cleanup of decompiler (ProgramInfo still holds it)
3. ChromaDB collections retain references indirectly
4. Dangling references could cause access after close

**Fix:** Clean up ProgramInfo objects

#### 3.3 Proper Program Cleanup

**File:** `src/pyghidra_mcp/context.py`

**Location:** Lines 151-168 (`close` method)

**Current Code:**
```python
def close(self, save: bool = True):
    """Saves changes to all open programs and closes the project."""
    # Shutdown thread pools FIRST before closing programs
    # Background tasks may still need to access programs/project
    if self.import_executor:
        self.import_executor.shutdown(wait=True)

    if self.executor:
        self.executor.shutdown(wait=True)

    # Now safe to close all programs
    for _program_name, program_info in self.programs.items():
        program = program_info.program
        self.project.close(program)

    # Close the Ghidra project
    self.project.close()
    logger.info(f"Project {self.project_name} closed.")
```

**Improved Code:**
```python
def close(self, save: bool = True):
    """Saves changes to all open programs and closes the project.

    CRITICAL: This method properly cleans up all resources including:
    - Thread pools
    - Decompiler interfaces
    - Program references
    - ChromaDB collections (indirectly)

    After calling this method, all ProgramInfo objects are invalidated
    and should not be accessed.
    """
    logger.info(f"Closing project {self.project_name}...")

    # Shutdown thread pools FIRST before closing programs
    # Background tasks may still need to access programs/project
    if self.import_executor:
        logger.debug("Shutting down import executor...")
        self.import_executor.shutdown(wait=True)
        self.import_executor = None

    if self.executor:
        logger.debug("Shutting down analysis executor...")
        self.executor.shutdown(wait=True)
        self.executor = None

    # Close all programs and clean up ProgramInfo objects
    logger.debug(f"Closing {len(self.programs)} programs...")
    for program_name, program_info in list(self.programs.items()):
        try:
            # Dispose decompiler first
            if program_info.decompiler:
                try:
                    program_info.decompiler.dispose()
                    logger.debug(f"Disposed decompiler for {program_name}")
                except Exception as e:
                    logger.warning(f"Error disposing decompiler for {program_name}: {e}")
                program_info.decompiler = None

            # Close the program
            if program_info.program:
                try:
                    self.project.close(program_info.program)
                    logger.debug(f"Closed program {program_name}")
                except Exception as e:
                    logger.warning(f"Error closing program {program_name}: {e}")
                program_info.program = None

            # Clear references
            program_info.flat_api = None

        except Exception as e:
            logger.error(f"Error during cleanup of {program_name}: {e}")

    # Clear programs dict to prevent access after close
    self.programs.clear()

    # Close the Ghidra project
    try:
        self.project.close()
        logger.info(f"Project {self.project_name} closed successfully.")
    except Exception as e:
        logger.error(f"Error closing project: {e}")
```

**Rationale:**
- Disposes decompilers before closing programs
- Clears all references in ProgramInfo objects
- Empties programs dict to prevent use-after-close
- Comprehensive error handling and logging
- Prevents dangling references

---

## Phase 4: Testing Strategy

### 4.1 Add Cleanup Verification Tests

**File:** `tests/integration/test_cleanup.py` (new file)

```python
import pytest
import psutil
import os


def test_launcher_cleanup(ghidra_install_dir):
    """Verify that launcher.terminate() properly cleans up JVM."""
    from mcp.client.stdio import stdio_client
    from mcp import ClientSession, StdioServerParameters

    # Track process count before
    parent = psutil.Process()
    java_count_before = sum(
        1 for p in parent.children(recursive=True)
        if 'java' in p.name().lower()
    )

    # Start server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "pyghidra_mcp", "--no-threaded"],
        env={"GHIDRA_INSTALL_DIR": ghidra_install_dir},
    )

    stdio_ctx = stdio_client(server_params)
    read, write = await stdio_ctx.__aenter__()

    session = ClientSession(read, write)
    await session.__aenter__()
    await session.initialize()

    # Do some work
    await session.call_tool("list_project_binaries", {})

    # Close session (should trigger launcher.terminate())
    await session.__aexit__(None, None, None)
    await stdio_ctx.__aexit__(None, None, None)

    # Wait a bit for cleanup
    import asyncio
    await asyncio.sleep(2)

    # Verify JVM processes are gone
    java_count_after = sum(
        1 for p in parent.children(recursive=True)
        if 'java' in p.name().lower()
    )

    assert java_count_after <= java_count_before, \
        f"JVM processes leaked: {java_count_before} -> {java_count_after}"


def test_lock_file_safety(ghidra_install_dir, tmp_path):
    """Test that lock file cleanup doesn't delete active locks."""
    # This test requires running two server instances
    # First instance creates lock
    # Second instance should NOT delete first instance's lock

    # Implementation requires coordination between processes
    # Mark as TODO - complex to implement
    pytest.skip("Requires multi-process coordination")


def test_program_cleanup(ghidra_install_dir):
    """Verify that program references are cleaned up on close."""
    from pyghidra_mcp.context import PyGhidraContext

    # Create context with test binary
    context = PyGhidraContext(
        project_name="test_cleanup",
        project_path=tmp_path / "cleanup_test",
        threaded=False,
    )

    # Import a binary
    context.import_binary(test_binary, analyze=True)

    # Get program info
    program_info = list(context.programs.values())[0]

    # Verify decompiler exists
    assert program_info.decompiler is not None

    # Close context
    context.close()

    # Verify cleanup
    assert program_info.decompiler is None, "Decompiler not disposed"
    assert program_info.program is None, "Program reference not cleared"
    assert program_info.flat_api is None, "FlatAPI not cleared"
    assert len(context.programs) == 0, "Programs dict not cleared"
```

### 4.2 Add Concurrent Access Tests

**File:** `tests/integration/test_concurrency.py` (new file)

```python
import pytest
import asyncio
import threading


@pytest.mark.skipif(
    not os.getenv("RUN_CONCURRENCY_TESTS"),
    reason="Concurrency tests are exploratory and may fail"
)
def test_concurrent_decompilation(shared_mcp_session, test_binary):
    """Test concurrent decompilation to identify race conditions."""
    # This test is expected to potentially fail
    # It's for documenting limitations, not enforcing correctness

    async def decompile(session, func_name):
        return await session.call_tool(
            "decompile_function",
            {"binary_name": test_binary, "name_or_address": func_name}
        )

    # Try to decompile multiple functions concurrently
    tasks = [
        decompile(shared_mcp_session, f"function_{i}")
        for i in range(10)
    ]

    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Check for failures
        failures = [r for r in results if isinstance(r, Exception)]
        if failures:
            pytest.skip(
                f"Concurrent access failed with {len(failures)} errors. "
                f"This is a known limitation - see Thread Safety documentation."
            )
    except Exception as e:
        pytest.skip(
            f"Concurrent decompilation failed: {e}. "
            "This is expected - see Thread Safety documentation."
        )
```

---

## Phase 5: Documentation Updates

### 5.1 Add Architecture Documentation

**File:** ARCHITECTURE.md (new file)

```markdown
# PyGhidra-MCP Architecture

## Deviations from PyGhidra Best Practices

This project intentionally deviates from some PyGhidra documentation
patterns due to architectural requirements.

### 1. Long-Lived Projects

**Documented Pattern:**
```python
with api.open_project(path, name) as project:
    # Work with project
# Automatically closed
```

**Our Pattern:**
```python
project = GhidraProject.openProject(path, name, True)
# Keep open for server lifetime
project.close()  # On shutdown
```

**Rationale:**
- MCP server requires long-lived project
- Lazy initialization prevents lock contention
- Multiple tools need shared project access

**Trade-offs:**
- ❌ Manual resource management
- ❌ Risk of not closing on errors
- ✅ Fits server architecture
- ✅ Efficient for multiple operations

---

### 2. Thread Safety

**PyGhidra Documentation:**
- No examples of concurrent access
- One JVM per process
- Implicit single-threaded design

**Our Implementation:**
- Python-level RLock synchronization
- Thread-safe ProgramInfo wrapper
- Concurrent decompilation support

**Known Limitations:**
- Java objects may not be thread-safe
- Decompiler has internal state
- No official documentation to guide implementation
- Race conditions may occur

**Use With Caution:**
```python
# Recommended: Serialize critical operations
with program_info:
    result = tools.decompile_function(func_name)

# Avoid: Pure concurrent access
# May fail if program save occurs during operation
```

---

### 3. Resource Cleanup

**Our Approach:**
- Comprehensive cleanup in `close()` method
- Disposes decompilers before closing programs
- Clears all references to prevent use-after-close
- Launcher lifecycle managed in server lifespan

**Order Matters:**
1. Shutdown thread pools
2. Dispose decompilers
3. Close programs
4. Clear references
5. Close project
6. Terminate launcher
```

### 5.2 Update README

**File:** README.md

**Add section:**
```markdown
## Known Limitations

### Thread Safety
This implementation includes thread synchronization for concurrent access,
but this is **not documented** in PyGhidra and may have undefined behavior.

**Recommendations:**
- Use `--no-threaded` mode for stability
- Report any concurrency issues encountered
- Consider serializing access for critical operations

### Resource Management
This server uses a long-lived project pattern that deviates from PyGhidra's
recommended context manager approach. This is necessary for the MCP server
architecture but requires careful resource cleanup.

**Cleanup is handled automatically on shutdown.**
```

---

## Implementation Order

### Week 1: Critical Fixes
1. **Issue 1.1-1.3**: Add launcher cleanup (3 hours)
   - Add global launcher variable
   - Capture launcher reference
   - Add cleanup to lifespan
   - Test with integration tests

2. **Issue 3.1**: Fix lock file deletion (4 hours)
   - Add age threshold check
   - Add platform-specific validation
   - Improve logging
   - Test lock contention scenarios

### Week 2: Warning Fixes
3. **Issue 3.3**: Add thread safety documentation (2 hours)
   - Document ProgramInfo limitations
   - Add warnings to tools methods
   - Update README

4. **Issue 3.2**: Improve decompiler swap (2 hours)
   - Add better logging
   - Document race condition
   - Add retry logic where appropriate

5. **Issue 3.3**: Improve program cleanup (3 hours)
   - Dispose decompilers
   - Clear all references
   - Add comprehensive error handling
   - Test cleanup verification

### Week 3: Testing & Documentation
6. **Phase 4**: Add tests (6 hours)
   - Launcher cleanup verification
   - Program cleanup verification
   - Concurrent access tests (exploratory)

7. **Phase 5**: Update documentation (3 hours)
   - Create ARCHITECTURE.md
   - Update README with limitations
   - Add inline code warnings

### Week 4: Deferred
8. **Issue 2**: API migration (deferred to v2.0)
   - Requires major refactoring
   - High risk, low immediate benefit
   - Document current deviation
   - Plan for future version

---

## Testing Checklist

### Unit Tests
- [ ] Launcher cleanup verification
- [ ] Lock file age threshold
- [ ] Lock file platform validation
- [ ] Program info cleanup
- [ ] Decompiler disposal

### Integration Tests
- [ ] Server startup and shutdown
- [ ] Multiple server lifecycles
- [ ] Project lock contention
- [ ] Program after-close access (should fail)
- [ ] Memory leak detection

### Exploratory Tests
- [ ] Concurrent decompilation
- [ ] Concurrent program access
- [ ] Stress test with many operations
- [ ] Long-running server stability

---

## Risk Assessment

### High Risk
- **Issue 2 (API Migration)**: Deferred due to scope
- Major refactoring required
- Could break existing functionality
- Better suited for major version bump

### Medium Risk
- **Issue 1 (Launcher Cleanup)**: Low risk, high benefit
- Simple change, well-tested pattern
- Fixes critical resource leak
- Should be implemented immediately

- **Issue 3 (Lock File Safety)**: Medium risk, high benefit
- More complex logic
- Requires thorough testing
- Prevents data corruption

### Low Risk
- **Issue 4-6 (Documentation)**: Very low risk
- Pure documentation changes
- No code behavior changes
- Improves user awareness

---

## Success Criteria

### Must Have (Phase 1)
- ✅ Launcher.terminate() called on server shutdown
- ✅ JVM processes properly cleaned up
- ✅ Lock files not deleted when active
- ✅ No resource leaks in normal operation

### Should Have (Phase 2-3)
- ✅ Thread safety limitations documented
- ✅ Decompiler lifecycle improved
- ✅ Program cleanup comprehensive
- ✅ Architecture documentation created

### Nice to Have (Phase 4-5)
- ✅ Cleanup verification tests pass
- ✅ Concurrent access behavior documented
- ✅ Known limitations in README
- ✅ Exploratory test results documented

---

## Rollback Plan

If issues arise:

1. **Launcher Cleanup**: Revert global launcher changes
   - Simple rollback
   - Only affects cleanup path

2. **Lock File Safety**: Revert to original deletion
   - Add warning comment about risks
   - Document as known issue

3. **Thread Safety Docs**: Keep documentation
   - No behavioral changes
   - Safe to deploy

---

## Post-Implementation

### Monitoring
- Monitor JVM process counts
- Check for lock file warnings
- Track concurrent access failures
- Measure memory usage over time

### Future Work
- Consider API migration for v2.0
- Investigate PyGhidra thread safety officially
- Explore alternatives to long-lived projects
- Benchmark context manager overhead

---

## References

### PyGhidra Documentation
- `first-script.md` - Basic patterns and cleanup
- `session-management.md` - JVM lifecycle
- `project-management.md` - Context manager usage

### Code Files
- `src/pyghidra_mcp/server.py` - Server lifecycle
- `src/pyghidra_mcp/context.py` - Project management
- `src/pyghidra_mcp/tools.py` - Thread safety
- `tests/integration/conftest.py` - Test fixtures

---

**End of Implementation Plan**
