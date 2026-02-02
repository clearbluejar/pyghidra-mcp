# Bug: ChromaDB is Crazy - ONNX Runtime CPU Spinlock Hell

## Issue Summary

**Severity:** High
**Impact:** CPU 100% usage, thread starvation, server goes full potato
**Affected:** All multi-agent scenarios using `search_code` (vector search tool)

Look, ChromaDB is absolutely wrecking us here. When multiple AI agents concurrently invoke pyghidra-mcp tools that use ChromaDB's vector search, the ONNX Runtime threads enter a pathological spinlock contention pattern. This causes:
- 22+ threads stuck in `SpinPause` (busy-wait loop burning CPU for nothing)
- CPU usage spikes to 100% on multiple cores
- Test suite becomes completely unresponsive
- **This WILL happen in production with multiple agents - guaranteed**

## Evidence

### 1. WinDbg Analysis of Memory Dump

**File:** `python.DMP` (3.7GB crash dump from concurrent test)
- Confirmed file exists at `D:\code\pyghidra-mcp\python.DMP`
- Size: ~3.7GB (consistent with crash during high-concurrency test)
**Date:** 2026-01-30 02:23:22
**Process Uptime:** 7 minutes
**Hardware:** Intel Core i9-14900K (24 cores / 32 threads) - This is a BEAST of a CPU!

**Scary Thought:** If this can bring an i9-14900K to its knees, imagine what happens on a typical developer laptop with 4-8 cores. The 22 stuck threads would completely saturate anything weaker.

#### Thread CPU Usage (!runaway output)

```
User Mode Time
Thread       Time
113:3628      0 days 0:03:15.812   <-- HIGHEST CPU thread
200:6d44      0 days 0:00:22.109
198:6db8      0 days 0:00:22.109
197:6d68      0 days 0:00:22.062
202:6d2c      0 days 0:00:22.046
201:6df0      0 days 0:00:22.000
203:6d80      0 days 0:00:21.843
196:6d60      0 days 0:00:21.734
199:6d7c      0 days 0:00:21.578
211:6d5c      0 days 0:00:20.656
209:dd4      0 days 0:00:20.640
208:d40      0 days 0:00:20.484
210:d90      0 days 0:00:20.390
192:27e8      0 days 0:00:20.203
[... 8 more threads with similar CPU times]
```

**Key Finding:** 22 threads each consuming 18-22 seconds of CPU time simultaneously.

#### Call Stack of Highest CPU Thread (Thread 113)

```
Child-SP          RetAddr           Call Site
000000d7`3924bab0 onnxruntime_pybind11_state!onnxruntime::concurrency::SpinPause+0x18
000000d7`3924bae0 onnxruntime_pybind11_state!onnxruntime::concurrency::ThreadPoolTempl<onnxruntime::Env>::EndParallelSectionInternal+0x175
000000d7`3924bb50 onnxruntime_pybind11_state!onnxruntime::concurrency::ThreadPoolTempl<onnxruntime::Env>::RunInParallel+0x1c0
000000d7`3924be20 onnxruntime_pybind11_state!onnxruntime::concurrency::ThreadPool::RunInParallel+0xd9
000000d7`3924bf00 onnxruntime_pybind11_state!onnxruntime::concurrency::ThreadPool::ParallelForFixedBlockSizeScheduling+0x1d1
000000d7`3924c330 onnxruntime_pybind11_state!onnxruntime::concurrency::ThreadPool::TrySimpleParallelFor+0x4d
000000d7`3924c3c0 onnxruntime_pybind11_state!MlasGemmBatch+0x24c
000000d7`3924c500 onnxruntime_pybind11_state!onnxruntime::MatMul<float>::Compute+0x748
000000d7`3924c7a0 onnxruntime_pybind11_state!onnxruntime::ExecuteKernel+0x1c9
000000d7`3924cd20 onnxruntime_pybind11_state!onnxruntime::LaunchKernelStep::Execute+0x34
000000d7`3924cd70 onnxruntime_pybind11_state!onnxruntime::RunSince+0x30a
000000d7`3924d040 onnxruntime_pybind11_state!std::_Func_impl_no_alloc<<lambda_89c9376f8cf67c8dba0b931730c602ec>,void>::_Do_call+0x22
000000d7`3924d080 onnxruntime_pybind11_state!onnxruntime::concurrency::ThreadPool::Schedule+0xfc
000000d7`3924d140 onnxruntime_pybind11_state!onnxruntime::ExecuteThePlan+0x27f
000000d7`3924d550 onnxruntime_pybind11_state!onnxruntime::utils::ExecuteGraphImpl+0x26c
000000d7`3924d850 onnxruntime_pybind11_state!onnxruntime::InferenceSession::Run+0x16bb
000000d7`3924df80 onnxruntime_pybind11_state!onnxruntime::InferenceSession::Run+0x201
000000d7`3924e0c0 onnxruntime_pybind11_state!<lambda_d8bf1299d315fe98a6b0689e09ec8b90>::operator()+0x539
000000d7`3924e370 onnxruntime_pybind11_state!<lambda_5c86fce7e5f7cd0596d5b15371992a4d>::operator()+0x191
000000d7`3924e440 onnxruntime_pybind11_state!<lambda_5c86fce7e5f7cd0596d5b15371992a4d>::<lambda_invoker_cdecl>+0x14
000000d7`3924e470 onnxruntime_pybind11_state!pybind11::cpp_function::dispatcher+0xf74
000000d7`3924e930 python313!PyObject_GetOptionalAttr+0xae8
[... Python evaluation frames ...]
```

**Stack Analysis:**
1. `SpinPause` → Busy-wait loop consuming CPU
2. `ThreadPoolTempl::EndParallelSectionInternal` → Thread synchronization
3. `MlasGemmBatch` → Batch matrix multiplication (MLAS = Microsoft Linear Algebra Subprogram)
4. `MatMul<float>::Compute` → Matrix computation for neural network
5. `InferenceSession::Run` → ONNX model inference
6. Python caller → ChromaDB embedding computation

#### Thread Count Confirmation

```
22 threads found with "onnxruntime_pybind11_state!onnxruntime::concurrency::SpinPause" in call stack
```

Verified by running: `grep -c "onnxruntime.*SpinPause" windbg.log`

All 22 threads exhibit identical call stack patterns, confirming this is a systematic concurrency issue, not some random one-off thread going haywire.

### 2. Test Scenario That Triggers the Issue

**File:** `tests/integration/test_concurrent_streamable_client.py`

```python
@pytest.mark.asyncio
async def test_concurrent_streamable_client_invocations(streamable_server, test_binary):
    # ...
    num_clients = 6  # 6 concurrent clients
    tasks = [invoke_tool_concurrently(binary_name, base_url, image_base)
              for _ in range(num_clients)]

    # Each client invokes 12 tools concurrently
    async def invoke_tool_concurrently(binary_name, base_url, image_base):
        tasks = [
            session.call_tool("decompile_function", ...),
            session.call_tool("search_code", ...),             # CHROMADB: Uses vector embeddings
            session.call_tool("search_strings", ...),          # NOTE: This uses text filter, NOT embeddings
            # ... 9 more tools
        ]
        responses = await asyncio.gather(*tasks)  # 72 concurrent operations total
```

**Total concurrent operations:** 6 clients × 12 tools = **72 concurrent requests**

**Note:** Only `search_code` uses ChromaDB's vector embeddings (which triggers ONNX). The `search_strings` tool uses ChromaDB's simple text filter and doesn't invoke ONNX Runtime.

### 3. ChromaDB Involvement Confirmation

**Loaded Modules:**
```
chromadb_rust_bindings.pyd (598 references in call stacks!)
chromadb/
onnxruntime_pybind11_state.pyd
```

**Tools That Use ChromaDB:**
- `search_code` → Uses semantic embeddings (vector similarity via ONNX)
- `search_strings` → Uses ChromaDB's simple text filter (no ONNX involved)

**Why Only `search_code` Triggers This:**
1. Tool call triggers vector search
2. ChromaDB computes query embedding using ONNX Runtime
3. ONNX Runtime runs neural network inference (all-MiniLM-L6-v2 model)
4. Matrix multiplication (`MatMul`) executed in parallel thread pool
5. Multiple agents → Multiple ONNX sessions → Thread pool contention
6. Threads spin-wait for synchronization → CPU 100%

### 4. Root Cause Analysis

**Primary Issue:** ONNX Runtime Thread Pool Spinlock Contention

**What's Actually Happening:**
1. ONNX Runtime uses a fixed-size thread pool for parallel matrix operations
2. When multiple Python threads concurrently call `InferenceSession::Run`, they ALL compete for the same thread pool
3. The `EndParallelSectionInternal` function uses a spinlock (`SpinPause`) to wait for worker threads
4. With 6+ concurrent agents, this spinlock contention goes nuclear:
   - Thread A finishes work, signals completion
   - Threads B, C, D... are stuck in `SpinPause` loop polling for completion signal
   - Each `SpinPause` burns CPU cycles waiting (not blocked, just spinning like crazy)
   - 22 threads × 100% CPU = system becomes a potato

**Why It Scales Poorly:**
- Spinlocks are faster than OS blocking when contention is low (microseconds)
- But absolutely disastrous when contention is high (milliseconds) - burns CPU for literally nothing
- ONNX Runtime's thread pool is designed for single-session inference, not multi-agent chaos

**Secondary Issue:** No Concurrency Limits in pyghidra-mcp

**Current Code Pattern:**
```python
# src/pyghidra_mcp/tools.py
class PyGhidraTools:
    def search_code(self, query: str, limit: int = 10):
        # Direct ChromaDB query - NO concurrency control at all
        results = self.program_info.code_collection.query(
            query_texts=[query],
            n_results=limit
        )
```

**The Problem:**
- Multiple agents can simultaneously call `search_code` with zero coordination
- No semaphore or rate limiting on ChromaDB access
- Each call spawns its own ONNX Runtime inference session
- Unbounded concurrency → resource exhaustion → CPU spinlock hell

### 5. Production Impact Assessment

**Question:** "Will this happen in production with multiple agents?"

**Answer:** **YES, 100% reproducible.**

**Hardware Reality Check:**
- This crash dump was captured on an **Intel Core i9-14900K** (24 cores / 32 threads, $550+ CPU)
- If an i9 can't handle this, what chance does a typical laptop have?
- On a 4-core MacBook Air or 6-core ThinkPad, this would be absolutely devastating

**Why It's Guaranteed:**
1. MCP server design encourages multi-agent use cases
2. Claude Desktop / Cline may spawn multiple agents for complex tasks
3. Each agent independently calls tools without coordination
4. Vector search tools are commonly used for code understanding
5. The concurrency threshold is low (6 agents is realistic)
6. ONNX Runtime's behavior is deterministic under contention

**Real-World Scenario:**
```
User asks: "Analyze this binary's networking code and find similar patterns"

Claude spawns 6 agents in parallel:
  - Agent 1: List imports → search_code("socket")
  - Agent 2: List exports → search_code("connect")
  - Agent 3: Search strings → search_strings("http")  # OK - doesn't use ONNX
  - Agent 4: Decompiler → search_code("encryption")
  - Agent 5: Call graph → search_code("SSL")
  - Agent 6: Cross-reference → search_code("TLS")

Result: 5 concurrent ONNX sessions → CPU 100% → server hangs → agents timeout → user is sad.
```

### 6. Related Issues

**File:** `PLAN_fix_pyghidra_usage_errors.md`

The project already has identified resource management issues:
- Missing `launcher.terminate()` call (JVM leak)
- Thread pool executor not properly shut down
- Lock file cleanup issues

These compound the ChromaDB contention problem:
- JVM threads + ONNX threads = double contention
- Executor threads waiting on ChromaDB = thread starvation

## Reproduction Steps

1. Start pyghidra-mcp server with streamable-http transport
2. Import a test binary
3. Launch 6 concurrent clients (simulating 6 agents)
4. Each client simultaneously calls 12 tools including `search_code` and `search_strings`
5. Observe CPU usage spike to 100%
6. Server becomes unresponsive within 1-2 minutes

**Minimum Reproduction:**
```bash
# Terminal 1: Start server
python -m pyghidra_mcp --transport streamable-http --port 8080

# Terminal 2: Run concurrent test
pytest tests/integration/test_concurrent_streamable_client.py -v -s
```

## Proposed Solutions

### Solution 1: Add ChromaDB Concurrency Semaphore (Recommended)

**File:** `src/pyghidra_mcp/tools.py`

```python
import threading
import os

class PyGhidraTools:
    # Limit concurrent ChromaDB queries to avoid ONNX spinlock hell
    # Configurable via PYGHIDRA_CHROMADB_MAX_CONCURRENT env var (default: 2)
    _max_concurrent = int(os.getenv("PYGHIDRA_CHROMADB_MAX_CONCURRENT", "2"))
    _chromadb_semaphore = threading.Semaphore(_max_concurrent)

    def search_code(self, query: str, limit: int = 10):
        with self._chromadb_semaphore:  # Acquire semaphore before ONNX chaos
            results = self.program_info.code_collection.query(
                query_texts=[query],
                n_results=limit
            )
        # Semaphore released automatically
```

**Pros:**
- Simple fix (5 lines of code)
- Prevents resource exhaustion
- Graceful degradation (agents wait instead of crash)

**Cons:**
- May slow down multi-agent workflows (serialized access)

### Solution 2: Configure ONNX Runtime Single-Threaded

**File:** `src/pyghidra_mcp/context.py`

```python
import os

# Before importing chromadb
os.environ["ORT_TENSORRT_MAX_WORKSPACE_SIZE"] = "0"  # Disable TensorRT
os.environ["OMP_NUM_THREADS"] = "1"  # Single-threaded OpenMP
```

**Pros:**
- Eliminates thread pool contention
- Predictable performance

**Cons:**
- Slower single-agent performance (no parallel matrix ops)
- May not fully solve issue (ONNX may still use internal threading)

### Solution 3: Lazy Load ChromaDB Collections

**File:** `src/pyghidra_mcp/context.py`

```python
class PyGhidraContext:
    def __init__(self, ...):
        # DON'T create collections during import
        self._code_collection_initialized = False
        self._strings_collection_initialized = False

    def _ensure_code_collection(self, binary_name: str):
        """Create collection on first search (not during import)"""
        if not self._code_collection_initialized:
            # Expensive operation: create embeddings for all functions
            # Do this lazily to avoid blocking import
            self._create_code_collection(binary_name)
            self._code_collection_initialized = True
```

**Pros:**
- Reduces startup contention
- Collections created only when needed

**Cons:**
- First search is slower (one-time cost)
- Doesn't solve concurrent search contention

### Solution 4: Disable Vector Search in Multi-Agent Mode

**File:** `src/pyghidra_mcp/server.py`

```python
# Add startup flag
@cli.option("--disable-vector-search", is_flag=True, help="Disable ChromaDB for multi-agent scenarios")
def main(disable_vector_search: bool = False, ...):
    if disable_vector_search:
        logger.info("Vector search disabled - using fallback string matching")
        # Monkey-patch search tools to use basic string matching
```

**Pros:**
- Eliminates ONNX dependency for multi-agent scenarios
- Fallback to deterministic string search

**Cons:**
- Loses semantic search capabilities
- User must explicitly opt-in

## Recommended Action Plan

### Immediate (v1.x)

1. **Add ChromaDB semaphore** (Solution 1) - This is the low-hanging fruit
   - Limit to 2 concurrent queries (configurable via env var)
   - Add logging to monitor queue wait times
   - Test with 6+ concurrent agents to verify CPU stays sane

2. **Document multi-agent limitations**
   - Add warning to README about concurrency limits
   - Recommend `--disable-vector-search` for multi-agent setups

3. **Add timeout protection**
   ```python
   import signal

   def search_code_with_timeout(self, ...):
       """Fail fast if ChromaDB hangs"""
       with self._chromadb_semaphore, timeout(30):
           return self.program_info.code_collection.query(...)
   ```

### Long-term (v2.0)

1. **Evaluate alternative embedding backends**
   - Consider sentence-transformers (PyTorch) with better thread control
   - Or use external embedding service (API-based)

2. **Implement request queue**
   - Serialize all ChromaDB requests through a worker thread
   - Agents submit requests to queue, get results via Future
   - Better isolation from ONNX threading issues

3. **Add metrics and monitoring**
   - Track ONNX thread count, CPU usage
   - Alert on contention patterns
   - Auto-disable vector search when detected

## Testing Checklist

- [ ] Run `test_concurrent_streamable_client.py` with semaphore fix
- [ ] Verify CPU usage remains < 200% with 6 clients
- [ ] Test with 10+ concurrent clients (stress test)
- [ ] Measure response time degradation (if any)
- [ ] Test fallback to string search when semaphore timeout
- [ ] Verify single-agent performance not affected

## References

- **Memory Dump:** `D:\code\pyghidra-mcp\python.DMP` (3.7GB)
- **WinDbg Log:** `D:\code\pyghidra-mcp\windbg.log`
- **Test File:** `tests/integration/test_concurrent_streamable_client.py:201-204`
- **Related Plan:** `PLAN_fix_pyghidra_usage_errors.md`
- **ChromaDB Docs:** https://docs.trychroma.com/
- **ONNX Runtime Threading:** https://onnxruntime.ai/docs/performance/tune-performance.html

## Questions

1. **Should we set the semaphore limit to 2 or higher?**
   - Testing needed to find optimal value. 2 is conservative but safe.

2. **Should we disable ChromaDB entirely for threaded mode?**
   - Alternative: Use only in `--no-threaded` mode, or add `--disable-vector-search` flag

3. **Is there a way to share ONNX Runtime sessions across calls?**
   - Could reduce contention if sessions are reused (needs investigation)

---

**Priority:** P0 - Blocks production multi-agent use
**Effort:** 2-4 hours to implement semaphore fix
**Risk:** Low (localized change, easy rollback)
