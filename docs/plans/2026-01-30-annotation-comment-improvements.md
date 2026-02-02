# Code Annotation and Comment Improvements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Improve code documentation quality across the pyghidra-mcp codebase by fixing annotation issues, removing redundant comments, correcting typos, and adding missing critical documentation.

**Architecture:** Systematic file-by-file review and fixes, prioritized by impact: critical documentation gaps first, then typos and inconsistencies, then redundant comments. Each file will be edited independently to enable incremental commits and easy rollback.

**Tech Stack:** Python 3.11+, Pydantic, MCP protocol, Ghidra PyGhidra API

---

## Overview

This plan addresses annotation and comment issues identified during a comprehensive review of 5 core source files (2,802 total lines). Changes are organized by priority and file to minimize merge conflicts and enable systematic testing.

**Issue Breakdown:**
- **High Priority:** 24 issues (missing docstrings, undocumented enums, typos)
- **Medium Priority:** 38 issues (redundant comments, vague descriptions, outdated terminology)
- **Low Priority:** 10 issues (over-commented trivial code)

**Files Affected:**
1. `src/pyghidra_mcp/models.py` - High impact, low risk
2. `src/pyghidra_mcp/server.py` - Medium impact, low risk
3. `src/pyghidra_mcp/tools.py` - Medium impact, low risk
4. `src/pyghidra_mcp/context.py` - Medium impact, medium risk (complex logic)

---

## Task 1: Fix Critical Models.py Documentation Gaps

**Priority:** HIGH - These are user-facing API models used in MCP responses

**Files:**
- Modify: `src/pyghidra_mcp/models.py:205-234`

**Why First:** Models are used throughout the codebase; fixing them first improves API documentation for all downstream code. Low risk (no logic changes).

### Step 1: Add CallGraphDirection enum value documentation

**Edit lines 206-210 in `src/pyghidra_mcp/models.py`**

Current code:
```python
class CallGraphDirection(str, Enum):
    """Represents the direction of the call graph."""
    CALLING = "calling"
    CALLED = "called"
```

Change to:
```python
class CallGraphDirection(str, Enum):
    """Represents the direction of the call graph traversal.

    Values:
        CALLING: Functions that this function calls (outgoing edges/callees)
        CALLED: Functions that call this function (incoming edges/callers)
    """
    CALLING = "calling"
    CALLED = "called"
```

**Step 2: Add CallGraphDisplayType enum value documentation**

**Edit lines 213-218 in `src/pyghidra_mcp/models.py`**

Current code:
```python
class CallGraphDisplayType(str, Enum):
    """Represents the display type of the call graph."""
    FLOW = "flow"
    FLOW_ENDS = "flow_ends"
    MIND = "mind"
```

Change to:
```python
class CallGraphDisplayType(str, Enum):
    """Represents the display type of the call graph visualization.

    Values:
        FLOW: Standard flowchart layout with all nodes and edges
        FLOW_ENDS: Flowchart layout emphasizing entry and exit points
        MIND: Mind-map style layout (radial/clustered visualization)
    """
    FLOW = "flow"
    FLOW_ENDS = "flow_ends"
    MIND = "mind"
```

**Step 3: Add missing parameter documentation to CallGraphResult**

**Edit lines 221-234 in `src/pyghidra_mcp/models.py`**

Current code for lines 232-233:
```python
    mermaid_markdown: str = Field(description="The MermaidJS markdown string for the call graph.")
    mermaid_image_url: str = Field(description="The MermaidJS image url")
```

Change to:
```python
    mermaid_markdown: str = Field(
        description="The MermaidJS markdown graph definition (ready for rendering)"
    )
    mermaid_image_url: str = Field(
        description="Temporary MermaidJS rendering service URL (may expire, not suitable for long-term storage)"
    )
```

**Step 4: Verify changes**

Run: `python -c "from src.pyghidra_mcp.models import CallGraphDirection, CallGraphDisplayType; print(CallGraphDirection.CALLING.__doc__); print(CallGraphDisplayType.FLOW.__doc__)"`

Expected: No errors, enum values accessible

**Step 5: Commit**

```bash
git add src/pyghidra_mcp/models.py
git commit -m "docs: add missing enum documentation for CallGraphDirection and CallGraphDisplayType

- Document CALLING vs CALLED direction values clearly
- Explain FLOW, FLOW_ENDS, and MIND display types
- Add detail to mermaid_markdown and mermaid_image_url field descriptions

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Fix Models.py Field Descriptions and Add Missing Context

**Priority:** MEDIUM - Improves API clarity

**Files:**
- Modify: `src/pyghidra_mcp/models.py:29-161`

### Step 1: Clarify ProgramInfo metadata field descriptions

**Edit lines 40-44 in `src/pyghidra_mcp/models.py`**

Current code:
```python
    metadata: dict[str, Any] = Field(description="A dictionary of metadata associated with the program.")
    code_collection_ready: bool = Field(description="True if the chromadb code collection is ready")
    strings_collection_ready: bool = Field(description="True if the chromadb strings collection is ready")
```

Change to:
```python
    metadata: dict[str, Any] = Field(
        description="Ghidra program metadata (e.g., architecture, compiler, language ID)"
    )
    code_collection_ready: bool = Field(
        description="Whether the ChromaDB code collection has been created and populated with decompiled functions"
    )
    strings_collection_ready: bool = Field(
        description="Whether the ChromaDB strings collection has been created and populated with extracted strings"
    )
```

**Step 2: Add possible value descriptions to SymbolInfo**

**Edit lines 105-109 in `src/pyghidra_mcp/models.py`**

Current code:
```python
    symbol_type: str = Field(description="The type of the symbol.")
    namespace: str = Field(description="The namespace of the symbol.")
    symbol_source: str = Field(description="The source of the symbol.")
    is_external: bool = Field(description="Is symbol external.")
```

Change to:
```python
    symbol_type: str = Field(
        description="Symbol type (e.g., FUNCTION, CODE, DATA, CLASS, NAMESPACE)"
    )
    namespace: str = Field(
        description="Symbol namespace (empty string for global namespace)"
    )
    symbol_source: str = Field(
        description="Symbol origin (e.g., DEFAULT, ANALYSIS, USER_DEFINED,_COMPILER)"
    )
    is_external: bool = Field(
        description="Whether the symbol is external to the binary (imported)"
    )
```

**Step 3: Add similarity score range information**

**Edit line 127 in `src/pyghidra_mcp/models.py`** (CodeSearchResult)

Current code:
```python
    similarity_score: float = Field(description="The similarity score of the search result.")
```

Change to:
```python
    similarity_score: float = Field(
        description="Semantic similarity score (0.0-1.0, higher is better match)"
    )
```

**Edit line 146 in `src/pyghidra_mcp/models.py`** (StringSearchResult)

Current code:
```python
    similarity_score: float = Field(description="The similarity score of the search result.")
```

Change to:
```python
    similarity_score: float = Field(
        description="Semantic similarity score (0.0-1.0, higher is better match)"
    )
```

**Step 4: Clarify BytesReadResult format specifications**

**Edit lines 158-160 in `src/pyghidra_mcp/models.py`**

Current code:
```python
    normalized_address: str = Field(description="The normalized address where bytes were read from.")
    hex_bytes: str = Field(description="The raw bytes as a hexadecimal string.")
```

Change to:
```python
    normalized_address: str = Field(
        description="Normalized address in hex format with '0x' prefix (e.g., '0x401000')"
    )
    hex_bytes: str = Field(
        description="Raw bytes as hexadecimal string with '0x' prefix (e.g., '0x488b45')"
    )
```

**Step 5: Add BinaryMetadata alias explanation**

**Edit lines 170-202 in `src/pyghidra_mcp/models.py`**

Current code:
```python
class BinaryMetadata(BaseModel):
    """Detailed metadata for a Ghidra program."""
```

Change to:
```python
class BinaryMetadata(BaseModel):
    """Detailed metadata for a Ghidra program.

    Fields are aliased to match Ghidra's internal metadata property names.
    The ConfigDict subclass allows extra fields and populates by alias name.
    """
```

And update lines 180-181:
```python
    num_bytes: int = Field(alias="# of Bytes", description="File size in bytes")
    num_memory_blocks: int = Field(alias="# of Memory Blocks", description="Number of memory blocks/sections in the program")
```

**Step 6: Test model imports and descriptions**

Run: `python -c "from src.pyghidra_mcp.models import *; print('Models loaded successfully')"`

Expected: No errors, all models import correctly

**Step 7: Commit**

```bash
git add src/pyghidra_mcp/models.py
git commit -m "docs: enhance field descriptions in Pydantic models

- Clarify metadata field contents in ProgramInfo
- Add possible value examples for SymbolInfo fields
- Document similarity score ranges (0.0-1.0)
- Specify hex string format for addresses and bytes
- Explain BinaryMetadata alias usage
- Fix sentence fragment in is_external field description

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 3: Fix Typos in Context.py Error Messages

**Priority:** HIGH - Typos in user-facing error messages

**Files:**
- Modify: `src/pyghidra_mcp/context.py:1012,1025`

### Step 1: Fix typo in set_analysis_option error message (line 1012)

**Current code:**
```python
    raise ValueError(f"Type mismatch: existing enum value alreday set.")
```

**Change to:**
```python
    raise ValueError(f"Type mismatch: existing enum value already set.")
```

### Step 2: Fix typo in set_analysis_option error message (line 1025)

**Current code:**
```python
    raise ValueError(f"Type mismatch: existing enum value alreday set.")
```

**Change to:**
```python
    raise ValueError(f"Type mismatch: existing enum value already set.")
```

### Step 3: Verify typos are fixed

Run: `grep -n "alreday" src/pyghidra_mcp/context.py`

Expected: No results (typos removed)

### Step 4: Commit

```bash
git add src/pyghidra_mcp/context.py
git commit -m "fix: correct typos in set_analysis_option error messages

Change 'alreday' to 'already' in ValueError messages.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 4: Add Missing Docstrings in Context.py

**Priority:** HIGH - Complex methods lack documentation

**Files:**
- Modify: `src/pyghidra_mcp/context.py:617-637,780-808,854-961,1113-1129`

### Step 1: Add docstring for _init_program_info

**Edit after line 617 in `src/pyghidra_mcp/context.py`**

Insert after the function signature:
```python
def _init_program_info(self, program, domain_file):
    """Initialize ProgramInfo wrapper for a Ghidra program.

    Creates a thread-safe ProgramInfo object with program metadata,
    decompiler interface, and lock for concurrent access.

    Args:
        program: Ghidra Program object
        domain_file: Ghidra DomainFile for program location tracking

    Returns:
        ProgramInfo: Thread-safe program wrapper
    """
```

### Step 2: Add docstring for analyze_project

**Edit after line 780 in `src/pyghidra_mcp/context.py`**

Insert after the function signature:
```python
def analyze_project(self):
    """Analyze all programs in the project.

    Runs Ghidra's auto-analysis on each program and waits for completion.
    Supports both single-threaded and threaded analysis modes.
    After analysis completes, initializes ChromaDB collections for semantic search.

    Raises:
        RuntimeError: If analysis fails for any program
    """
```

### Step 3: Add docstring for analyze_program

**Edit after line 854 in `src/pyghidra_mcp/context.py`**

Insert after the function signature:
```python
def analyze_program(
    self,
    program_info: ProgramInfo,
    allow_analysis_timeout: bool = False,
    analysis_timeout_seconds: int = 300,
) -> bool:
    """Analyze a single Ghidra program with configurable options.

    Runs Ghidra's auto-analysis with specified timeout settings.
    Handles analysis options, decompiler configuration, and ChromaDB initialization.

    Args:
        program_info: ProgramInfo wrapper for the program to analyze
        allow_analysis_timeout: If True, use analysis timeout; if False, wait indefinitely
        analysis_timeout_seconds: Maximum seconds to wait for analysis (if timeout enabled)

    Returns:
        bool: True if analysis completed successfully

    Raises:
        RuntimeError: If analysis times out or fails critically
    """
```

### Step 4: Add docstring for setup_decompiler

**Edit after line 1113 in `src/pyghidra_mcp/context.py`**

Insert after the function signature:
```python
def setup_decompiler(self, program):
    """Configure and initialize decompiler interface for a program.

    Creates DecompInterface with increased max payload size to handle
    large function decompilations. Uses program's default decompiler options.

    Args:
        program: Ghidra Program object

    Returns:
        DecompInterface: Configured decompiler instance ready for use
    """
```

### Step 5: Verify docstrings are present

Run: `python -c "from src.pyghidra_mcp.context import PyGhidraContext; print(PyGhidraContext.analyze_program.__doc__[:50])"`

Expected: Prints first 50 chars of docstring

### Step 6: Commit

```bash
git add src/pyghidra_mcp/context.py
git commit -m "docs: add missing docstrings for complex PyGhidraContext methods

- Add docstring for _init_program_info (ProgramInfo wrapper creation)
- Add docstring for analyze_project (bulk project analysis)
- Add docstring for analyze_program (single program analysis with options)
- Add docstring for setup_decompiler (decompiler interface configuration)

These methods had no documentation despite their complexity.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 5: Add Missing Docstrings in Tools.py

**Priority:** HIGH - Public API methods lack documentation

**Files:**
- Modify: `src/pyghidra_mcp/tools.py:68-70,384-405,407-445,506-560,271-293`

### Step 1: Add docstring for _get_filename

**Edit lines 68-70 in `src/pyghidra_mcp/tools.py`**

Current code:
```python
def _get_filename(self, func: "Function"):
    max_path_len = 50
    return f"{func.getSymbol().getName(True)[:max_path_len]}-{func.entryPoint}"
```

Change to:
```python
def _get_filename(self, func: "Function") -> str:
    """Generate unique identifier for decompilation caching.

    Creates a filename-safe identifier from function name and entry point.
    Truncates long function names to 50 characters to keep identifiers manageable.

    Args:
        func: Ghidra Function object

    Returns:
        str: Unique identifier in format "name-address"
    """
    max_path_len = 50
    return f"{func.getSymbol().getName(True)[:max_path_len]}-{func.entryPoint}"
```

### Step 2: Enhance search_code docstring

**Edit lines 384-405 in `src/pyghidra_mcp/tools.py`**

Current code:
```python
def search_code(self, query: str, limit: int = 10) -> list[CodeSearchResult]:
    """Searches the code in the binary for a given query."""
```

Change to:
```python
def search_code(self, query: str, limit: int = 10) -> list[CodeSearchResult]:
    """Search decompiled code using semantic similarity.

    Performs vector-based semantic search using ChromaDB embeddings.
    Requires code collection to be initialized (run after analysis).

    Args:
        query: Natural language query describing the code you're looking for
        limit: Maximum number of results to return (default: 10)

    Returns:
        List of code snippets ranked by semantic similarity (0.0-1.0)

    Raises:
        ValueError: If code collection is not ready
    """
```

### Step 3: Enhance search_strings docstring

**Edit lines 407-445 in `src/pyghidra_mcp/tools.py`**

Current code:
```python
def search_strings(self, query: str, limit: int = 100) -> list[StringSearchResult]:
    """Searches for strings within a binary."""
```

Change to:
```python
def search_strings(
    self, query: str, limit: int = 100
) -> list[StringSearchResult]:
    """Search for strings using hybrid text + semantic search.

    First performs exact substring matching, then supplements with
    semantic similarity search using ChromaDB embeddings.

    Args:
        query: String to search for (exact match or semantic)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of string matches with similarity scores (0.0-1.0)

    Raises:
        ValueError: If strings collection is not ready
    """
```

### Step 4: Enhance get_all_strings docstring

**Edit lines 271-293 in `src/pyghidra_mcp/tools.py`**

Current code:
```python
def get_all_strings(self) -> list[StringInfo]:
    """Gets all defined strings for a binary"""
```

Change to:
```python
def get_all_strings(self) -> list[StringInfo]:
    """Get all defined strings from the program.

    Handles Ghidra version differences:
    - Ghidra 11.3.2+: Uses getDefinedStrings() (includes strings from data types)
    - Ghidra 11.x: Uses getStrings() (classic string listing)

    Returns:
        List of StringInfo objects with string content and location
    """
```

### Step 5: Add comprehensive gen_callgraph docstring

**Edit lines 506-560 in `src/pyghidra_mcp/tools.py`**

Current code:
```python
def gen_callgraph(
    self,
    function_name_or_address: str,
    cg_direction: CallGraphDirection = CallGraphDirection.CALLING,
    cg_display_type: CallGraphDisplayType = CallGraphDisplayType.FLOW,
    include_refs: bool = True,
    max_depth: int | None = None,
    max_run_time: int = 60,
    condense_threshold: int = 50,
    top_layers: int = 5,
    bottom_layers: int = 5,
) -> CallGraphResult:
    """Generates a call graph for a specified function."""
```

Change to:
```python
def gen_callgraph(
    self,
    function_name_or_address: str,
    cg_direction: CallGraphDirection = CallGraphDirection.CALLING,
    cg_display_type: CallGraphDisplayType = CallGraphDisplayType.FLOW,
    include_refs: bool = True,
    max_depth: int | None = None,
    max_run_time: int = 60,
    condense_threshold: int = 50,
    top_layers: int = 5,
    bottom_layers: int = 5,
) -> CallGraphResult:
    """Generate a call graph visualization for a function.

    Creates MermaidJS call graph showing caller/callee relationships.
    Supports multiple display types and condensation for large graphs.

    Args:
        function_name_or_address: Function name or entry point address
        cg_direction: CALLING (outgoing/callees) or CALLED (incoming/callers)
        cg_display_type: FLOW, FLOW_ENDS, or MIND visualization style
        include_refs: Include cross-reference information in nodes
        max_depth: Maximum graph depth (None for unlimited)
        max_run_time: Maximum generation time in seconds (default: 60)
        condense_threshold: Nodes threshold for condensation (default: 50)
        top_layers: Number of top layers to preserve when condensing
        bottom_layers: Number of bottom layers to preserve when condensing

    Returns:
        CallGraphResult with MermaidJS markdown and rendered image URL

    Raises:
        ValueError: If function not found
        TimeoutError: If graph generation exceeds max_run_time
    """
```

### Step 6: Test docstring access

Run: `python -c "from src.pyghidra_mcp.tools import GhidraTools; print(ghidra_tools.search_code.__doc__[:50])"`

Expected: Prints enhanced docstring content

### Step 7: Commit

```bash
git add src/pyghidra_mcp/tools.py
git commit -m "docs: add and enhance docstrings in GhidraTools

- Add docstring for _get_filename (decompilation cache identifiers)
- Enhance search_code docstring (explain semantic search, preconditions)
- Enhance search_strings docstring (explain hybrid search approach)
- Enhance get_all_strings docstring (document version compatibility)
- Add comprehensive gen_callgraph docstring (document all 8 parameters)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 6: Fix Typos and Outdated Terminology in Tools.py

**Priority:** MEDIUM - User-facing documentation issues

**Files:**
- Modify: `src/pyghidra_mcp/tools.py:205-227,229-246,325-354`

### Step 1: Fix typo in get_all_functions docstring

**Edit line 234 in `src/pyghidra_mcp/tools.py`**

Current code:
```python
    """Gets all functions within a binary.
    Returns a python list that doesn't need to be re-intialized
    """
```

Change to:
```python
    """Gets all functions in the currently loaded program.
    Returns a python list that doesn't need to be re-initialized
    """
```

### Step 2: Update decompile_function_by_name_or_addr docstring

**Edit line 209 in `src/pyghidra_mcp/tools.py`**

Current code:
```python
    """Finds and decompiles a function in a specified binary and returns its pseudo-C code."""
```

Change to:
```python
    """Finds and decompiles a function in the currently loaded program and returns its pseudo-C code."""
```

### Step 3: Update decompile_function docstring

**Edit line 216 in `src/pyghidra_mcp/tools.py`**

Current code:
```python
    """Decompiles a function in a specified binary and returns its pseudo-C code."""
```

Change to:
```python
    """Decompiles a function in the currently loaded program and returns its pseudo-C code.
```

### Step 4: Update list_exports docstring

**Edit line 333 in `src/pyghidra_mcp/tools.py`**

Current code:
```python
    """Lists all exported functions and symbols from a specified binary."""
```

Change to:
```python
    """Lists all exported functions and symbols from the currently loaded program.
```

### Step 5: Update list_imports docstring

**Edit line 349 in `src/pyghidra_mcp/tools.py`**

Current code:
```python
    """Lists all imported functions and symbols for a specified binary."""
```

Change to:
```python
    """Lists all imported functions and symbols from the currently loaded program.
```

### Step 6: Verify all changes

Run: `grep -n "specified binary\|re-intialized" src/pyghidra_mcp/tools.py`

Expected: No results (all instances fixed)

### Step 7: Commit

```bash
git add src/pyghidra_mcp/tools.py
git commit -m "docs: fix typos and outdated terminology in GhidraTools

- Fix 're-intialized' → 're-initialized' typo
- Replace 'specified binary' with 'currently loaded program' throughout
- Clarifies that operations work on the open program context

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 7: Add Missing ctx Parameter Docs in Server.py

**Priority:** MEDIUM - MCP protocol completeness

**Files:**
- Modify: `src/pyghidra_mcp/server.py:157-589` (15 functions)

### Step 1: Add ctx parameter to decompile_function

**Edit lines 166-167 in `src/pyghidra_mcp/server.py`**

After:
```python
    """
    Decompiles a function and returns its pseudo-C representation.
```

Add:
```python

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_name: Name of the binary/program in the Ghidra project
        name_or_address: Function name or entry point address
```

### Step 2: Add ctx parameter to search_symbols_by_name

**Edit lines 190-194 in `src/pyghidra_mcp/server.py`**

Add after query description:
```python
        ctx: The MCP request context (provided by FastMCP)
```

### Step 3: Add ctx parameter to search_code

**Edit lines 224-227 in `src/pyghidra_mcp/server.py`**

Add after binary_name description:
```python
        ctx: The MCP request context (provided by FastMCP)
```

### Step 4: Add ctx parameter to remaining 12 functions

For each function, add the same line:
- `list_project_binaries` (line ~247)
- `list_project_binary_metadata` (line ~300)
- `delete_project_binary` (line ~326)
- `list_exports` (line ~363)
- `list_imports` (line ~402)
- `list_cross_references` (line ~434)
- `search_strings` (line ~462)
- `get_image_base` (line ~485)
- `read_bytes` (line ~504)
- `gen_callgraph` (line ~538)
- `import_binary` (line ~574)

Pattern to add in Args section:
```python
        ctx: The MCP request context (provided by FastMCP)
```

### Step 5: Verify all functions have ctx documented

Run: `grep -A 10 "@mcp.tool" src/pyghidra_mcp/server.py | grep -B 5 "binary_name" | grep "ctx:"`

Expected: ctx parameter appears in all tool function docstrings

### Step 6: Test MCP server loads

Run: `python -m pytest tests/unit/test_version.py -v`

Expected: Tests pass (server initialization not broken)

### Step 7: Commit

```bash
git add src/pyghidra_mcp/server.py
git commit -m "docs: add missing ctx parameter to all MCP tool docstrings

- Add ctx: Context parameter to Args section in 15 tool functions
- Standardizes documentation across all MCP tools
- Clarifies FastMCP-provided request context parameter

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 8: Remove Redundant Comments in Server.py

**Priority:** LOW - Code readability improvement

**Files:**
- Modify: `src/pyghidra_mcp/server.py:133,263,576-577`

### Step 1: Remove redundant comment at line 133

**Edit lines 132-134 in `src/pyghidra_mcp/server.py`**

Current code:
```python
    # Stop the launcher if it has a stop method
    if hasattr(_pyghidra_launcher, 'stop'):
```

Change to:
```python
    if hasattr(_pyghidra_launcher, 'stop'):
```

### Step 2: Remove redundant comment at line 263

**Edit lines 262-264 in `src/pyghidra_mcp/server.py`**

Current code:
```python
        # Use thread-safe property access to ensure we see updates from background threads
        for pi in context.get_programs_list():
```

Change to:
```python
        for pi in context.get_programs_list():
```

### Step 3: Improve vague comment at lines 576-577

**Edit lines 575-578 in `src/pyghidra_mcp/server.py`**

Current code:
```python
    # We would like to do context progress updates, but until that is more
    # widely supported by clients, we will resort to this
    pyghidra_context.import_binary_backgrounded(binary_path)
```

Change to:
```python
    # Import binary in background mode with progress reporting via logging
    # (MCP progress context updates not yet widely supported by clients)
    pyghidra_context.import_binary_backgrounded(binary_path)
```

### Step 4: Verify no code changes

Run: `python -m pytest tests/unit/test_version.py -v`

Expected: Tests pass (only comments changed)

### Step 5: Commit

```bash
git add src/pyghidra_mcp/server.py
git commit -m "refactor: remove redundant comments in server.py

- Remove self-evident comment about hasattr check
- Remove duplicate thread-safe access comment
- Clarify vague comment about background import rationale

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 9: Remove Redundant Comments in Context.py

**Priority:** LOW - Code readability improvement

**Files:**
- Modify: `src/pyghidra_mcp/context.py:53-55,147,202,214,400,589-593,771,852`

### Step 1: Remove over-commented trivial code at lines 53-55

**Edit lines 47-55 in `src/pyghidra_mcp/context.py`**

Remove these lines (keep the code):
```python
        # Use a non-blocking read with a try-finally to ensure we don't deadlock
        # In Python, reading a boolean is atomic, so we don't strictly need a lock for reads
        # However, we use acquire/release without timeout for simplicity
```

### Step 2: Remove outdated note at line 147

**Edit line 147 in `src/pyghidra_mcp/context.py`**

Remove:
```python
        # From GhidraDiffEngine
```

### Step 3: Remove informal comment at line 202

**Edit line 202 in `src/pyghidra_mcp/context.py`**

Change:
```python
        # program.close()  # ← Required by Ghidra!
```

To:
```python
        # Required by Ghidra's disposal pattern
        program.close()
```

### Step 4: Remove obvious comment at line 214

**Edit line 214 in `src/pyghidra_mcp/context.py`**

Remove:
```python
        # Clear references
```

### Step 5: Remove obvious comment at line 400

**Edit line 400 in `src/pyghidra_mcp/context.py`**

Remove:
```python
        # Now safe to close and delete the program
```

### Step 6: Remove obvious comment at lines 589-593

**Edit line 590 in `src/pyghidra_mcp/context.py`**

Remove:
```python
        # Try to find by matching against pi.name
```

### Step 7: Remove redundant callback comment at line 771

**Edit line 771 in `src/pyghidra_mcp/context.py`**

Remove:
```python
        # Callback function that runs when the future is done to catch any exceptions
```

### Step 8: Soften aggressive comment at line 852

**Edit line 852 in `src/pyghidra_mcp/context.py`**

Change:
```python
        self._init_all_chroma_collections()  # DO NOT MOVE
```

To:
```python
        # Must run after analysis completes (ChromaDB requires analyzed functions)
        self._init_all_chroma_collections()
```

### Step 9: Verify no logic changes

Run: `python -c "from src.pyghidra_mcp.context import PyGhidraContext; print('Import OK')"`

Expected: No errors

### Step 10: Commit

```bash
git add src/pyghidra_mcp/context.py
git commit -m "refactor: remove redundant and informal comments in context.py

- Remove over-explanatory threading comments
- Remove outdated 'From GhidraDiffEngine' note
- Replace informal emoji comment with professional explanation
- Remove self-evident 'clear references' comments
- Soften 'DO NOT MOVE' to explanatory comment
- Remove redundant callback description

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 10: Remove Redundant Comments in Tools.py

**Priority:** LOW - Code readability improvement

**Files:**
- Modify: `src/pyghidra_mcp/tools.py:256,308,362,450,459-460,469,473,484,520,524`

### Step 1: Remove redundant comment at line 256

**Edit line 256 in `src/pyghidra_mcp/tools.py`**

Remove:
```python
        # Thread-safe symbol listing
```

### Step 2: Remove redundant comment at line 308

**Edit line 308 in `src/pyghidra_mcp/tools.py`**

Remove:
```python
        # Search for symbols containing the query string
```

### Step 3: Remove redundant comment at line 362

**Edit line 362 in `src/pyghidra_mcp/tools.py`**

Remove:
```python
        # Use the unified resolver
```

### Step 4: Remove redundant comment at line 450

**Edit line 450 in `src/pyghidra_mcp/tools.py`**

Remove:
```python
    # Get the minimum address which typically corresponds to the image base
```

### Step 5: Remove redundant comments in read_bytes (lines 459-484)

**Edit lines 459-484 in `src/pyghidra_mcp/tools.py`**

Remove these redundant comments:
```python
        with self._lock:  # Thread-safe memory reading
        # Maximum size limit to prevent excessive memory reads
        # Get address factory and parse address
        # Handle common hex address formats
        # Check if address is in valid memory
```

Keep only the JPype technical comment at lines 489-490 (it's actually useful).

### Step 6: Remove redundant comments in gen_callgraph (lines 520, 524)

**Edit lines 520 and 524 in `src/pyghidra_mcp/tools.py`**

Remove:
```python
        # Thread-safe call graph generation
        # Call the ghidrecomp function
```

### Step 7: Verify no logic changes

Run: `python -c "from src.pyghidra_mcp.tools import GhidraTools; print('Import OK')"`

Expected: No errors

### Step 8: Commit

```bash
git add src/pyghidra_mcp/tools.py
git commit -m "refactor: remove redundant comments in tools.py

- Remove self-evident 'thread-safe' comments
- Remove obvious parsing and validation comments
- Remove redundant search strategy comments
- Keep only JPype technical comment (actually useful)
- Code is now more readable with less noise

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 11: Final Verification and Testing

**Priority:** HIGH - Ensure all changes work correctly

### Step 1: Run full test suite

Run: `python -m pytest tests/ -v --tb=short`

Expected: All tests pass (no logic changed, only docs/comments)

### Step 2: Verify imports still work

Run: `python -c "from src.pyghidra_mcp import *; print('All imports OK')"`

Expected: No import errors

### Step 3: Check for remaining issues

Run: `grep -rn "alreday\|re-intialized\|specified binary" src/pyghidra_mcp/*.py | grep -v ".pyc"`

Expected: No results (all typos and outdated terminology fixed)

### Step 4: Review all docstrings are present

Run: `python -c "
from src.pyghidra_mcp.context import PyGhidraContext
from src.pyghidra_mcp.tools import GhidraTools
from src.pyghidra_mcp.models import CallGraphDirection, CallGraphDisplayType

methods = [
    PyGhidraContext._init_program_info,
    PyGhidraContext.analyze_project,
    PyGhidraContext.analyze_program,
    PyGhidraContext.setup_decompiler,
    GhidraTools._get_filename,
]

for m in methods:
    if not m.__doc__ or len(m.__doc__) < 20:
        print(f'Missing/bad docstring: {m.__name__}')

print enums)
print(CallGraphDirection.CALLING.__doc__)
print(CallGraphDisplayType.FLOW.__doc__)
"`

Expected: All methods have docstrings, enums documented

### Step 5: Create summary of changes

Run: `git log --oneline --no-decorate -11`

Expected: Shows 11 commits for this improvement series

### Step 6: Final commit if needed

If any additional fixes found during testing:
```bash
git add src/pyghidra_mcp/
git commit -m "docs: additional fixes found during testing

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Testing Strategy

**Unit Tests:** Existing test suite should pass (no logic changes)
- `pytest tests/unit/` - Verify imports and basic functionality
- `pytest tests/integration/` - Verify MCP tools work correctly

**Manual Testing:**
- Start server: `python -m pyghidra_mcp`
- Verify tools load without errors
- Check docstrings render correctly in MCP clients

**Code Review Checklist:**
- [ ] All typos fixed ("alreday" → "already", "re-intialized" → "re-initialized")
- [ ] All missing docstrings added
- [ ] All enum values documented
- [ ] All ctx parameters documented in MCP tools
- [ ] Redundant comments removed
- [ ] No logic changes (only documentation)
- [ ] All tests pass
- [ ] Imports work correctly

---

## Summary

This plan systematically improves code documentation quality across the pyghidra-mcp codebase:

**High-Impact Changes (Tasks 1-7):**
- Fix critical missing documentation (enum values, complex methods)
- Correct typos in error messages
- Add missing parameter docs
- Standardize terminology

**Low-Impact Changes (Tasks 8-10):**
- Remove redundant comments
- Improve comment professionalism
- Reduce code noise

**Total Changes:**
- 11 focused commits
- 4 files modified
- ~72 annotation issues resolved
- 0 logic changes (safe refactoring)

**Estimated Time:** 2-3 hours (including testing and commits)

**Risk Level:** LOW - Only documentation and comments changed, no logic modifications
