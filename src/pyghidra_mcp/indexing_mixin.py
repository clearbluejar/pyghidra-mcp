import concurrent.futures
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any

import chromadb
from chromadb.config import Settings

from pyghidra_mcp.tools import DEFAULT_DECOMPILE_TIMEOUT_SECONDS, GhidraTools

logger = logging.getLogger(__name__)

# Collection metadata key flipped to True only after a code index is fully
# populated. A collection missing this marker (legacy) or carrying False (an
# interrupted/partial index) is rebuilt rather than trusted on restart.
COLLECTION_COMPLETE_KEY = "pyghidra_index_complete"

# Functions decompiled and written per collection.add(). A large binary has
# hundreds of thousands of functions, and holding every decompiled body until
# the end of the index is what makes that index need gigabytes of RAM; a window
# keeps only its own batch alive and gives an interruption something to resume
# from.
CODE_INGEST_WINDOW = 2000


class IndexingMixin:
    """Shared MCP-side indexing behavior for headless and GUI contexts."""

    programs: dict[str, Any]

    def _init_indexing_state(self, pyghidra_mcp_dir: Path, *, threaded: bool) -> None:
        chromadb_path = pyghidra_mcp_dir / "chromadb"
        chromadb_path.mkdir(parents=True, exist_ok=True)
        self.chroma_client = chromadb.PersistentClient(
            path=str(chromadb_path), settings=Settings(anonymized_telemetry=False)
        )
        self.index_executor = (
            concurrent.futures.ThreadPoolExecutor(max_workers=1) if threaded else None
        )
        self._index_futures: dict[str, concurrent.futures.Future] = {}
        self._index_lock = threading.Lock()

    def shutdown_executor(
        self,
        label: str,
        executor: concurrent.futures.ThreadPoolExecutor | None,
    ) -> None:
        """Drop queued work, then wait -- without a deadline -- for in-flight work.

        ``cancel_futures`` is what makes Ctrl+C responsive: tasks that have not
        started are dropped instead of run. The wait is deliberately unbounded,
        because a task already inside Ghidra cannot be interrupted from Python
        and abandoning it mid-write risks a corrupt program database.
        """
        if executor is None:
            return

        logger.info("Stopping %s tasks (queued work cancelled, in-flight work awaited)...", label)
        start = time.monotonic()
        executor.shutdown(wait=True, cancel_futures=True)
        logger.info("%s tasks stopped after %.1fs.", label.capitalize(), time.monotonic() - start)

    def shutdown_indexing(self) -> None:
        self.shutdown_executor("indexing", self.index_executor)

    def _lookup_program_info(self, binary_name: str) -> Any | None:
        raise NotImplementedError

    def schedule_indexing(
        self,
        binary_name: str,
        *,
        code: bool = True,
        strings: bool = True,
    ) -> bool:
        """Schedule MCP-side indexing for a binary when it is relevant."""
        program_info = self._lookup_program_info(binary_name)
        if program_info is None or not program_info.analysis_complete:
            return False
        if (not code or program_info.code_collection is not None) and (
            not strings or program_info.strings is not None
        ):
            return False

        with self._index_lock:
            future = self._index_futures.get(binary_name)
            if future is not None and not future.done():
                return False

            if self.index_executor is not None:
                future = self.index_executor.submit(
                    self._index_program,
                    program_info,
                    code=code,
                    strings=strings,
                )
                self._index_futures[binary_name] = future
                future.add_done_callback(
                    lambda done_future, name=binary_name: self._index_done_callback(
                        name, done_future
                    )
                )
                return True

        self._index_program(program_info, code=code, strings=strings)
        return True

    def schedule_startup_indexing(self, *, max_binaries: int | None = 10) -> None:
        """Eagerly index only manageable existing projects on startup."""
        analyzed_programs = [
            program_info
            for program_info in self.programs.values()
            if program_info.analysis_complete
        ]
        if max_binaries is not None and len(analyzed_programs) > max_binaries:
            logger.info(
                "Skipping startup indexing for %s binaries; indexing will start lazily.",
                len(analyzed_programs),
            )
            return

        for program_info in analyzed_programs:
            self.schedule_indexing(program_info.name)

    def _normalize_collection_name(self, name: str) -> str:
        """Return a name that satisfies Chroma's collection-name validation.

        Chroma only accepts ASCII letters, numbers, dots, dashes, and
        underscores, starting and ending with an alphanumeric. Names arrive here
        already carrying the "-<6 hex>" hash suffix appended by
        _gen_unique_bin_name, which guarantees they are long enough and end
        alphanumerically, so no length padding or fallback is needed.
        """
        # No consecutive dots (Chroma rejects "..").
        name = re.sub(r"\.{2,}", ".", name)

        # Replace everything Chroma rejects, including whitespace and Unicode
        # word characters (the previous regex kept both and Chroma refused the
        # resulting collection name).
        name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)

        # Chroma requires a leading and trailing alphanumeric (e.g. dotfiles
        # start with ".").
        return name.strip("._-")

    def _open_collection(self, name: str) -> Any | None:
        """Return the collection for *name* in whatever state it is in, or None.

        Completion is decided by the ``COLLECTION_COMPLETE_KEY`` marker, not by
        mere existence: chromadb persists a collection the moment it is created,
        so an index interrupted partway through leaves an empty/partial
        collection on disk.

        A partial collection is not deleted here. It has already paid for every
        window it holds, and rebuilding a large one costs hours of decompilation;
        the caller resumes it by skipping the ids that are already stored. The
        marker still decides whether the collection may be searched, so a
        resumed collection is never mistaken for a finished index.
        """
        name = self._normalize_collection_name(name)
        try:
            return self.chroma_client.get_collection(name=name)
        except Exception:
            return None

    @staticmethod
    def _collection_is_complete(collection: Any) -> bool:
        return bool((collection.metadata or {}).get(COLLECTION_COMPLETE_KEY))

    def _mark_collection_complete(self, collection: Any, function_count: int) -> None:
        """Flip a fully-populated collection's completion marker on disk."""
        collection.modify(
            metadata={COLLECTION_COMPLETE_KEY: True, "function_count": function_count}
        )

    def _init_chroma_code_collection_for_program(self, program_info: Any) -> None:
        from ghidra.program.model.listing import Function

        logger.info("Initializing Chroma code collection for %s", program_info.name)
        collection = self._open_collection(
            self._normalize_collection_name(program_info.name)
        )
        if collection is not None and self._collection_is_complete(collection):
            logger.info(
                "Collection '%s' already complete; skipping code ingest.", program_info.name
            )
            program_info.code_collection = collection
            return

        if collection is not None:
            logger.info(
                "Resuming code collection '%s': %s functions already indexed",
                program_info.name,
                collection.count(),
            )
        else:
            logger.info("Creating new code collection '%s'", program_info.name)

        # The marker stays off while windows are written, resumed or not, so a
        # search can never run against a partial index. The add failure is
        # intentionally not swallowed: a partial index must fail loudly so it is
        # not marked done.
        if collection is None:
            collection = self.chroma_client.create_collection(
                name=self._normalize_collection_name(program_info.name),
                metadata={COLLECTION_COMPLETE_KEY: False},
            )
        else:
            collection.modify(metadata={COLLECTION_COMPLETE_KEY: False})

        tools = GhidraTools(program_info)
        functions = tools.get_all_functions()
        total = len(functions)
        indexed = 0
        reused = 0
        failed = 0

        for start in range(0, total, CODE_INGEST_WINDOW):
            window = functions[start : start + CODE_INGEST_WINDOW]
            documents = []
            ids = []
            metadatas = []

            for offset, func in enumerate(window):
                func: Function
                try:
                    if offset % 10 == 0:
                        logger.debug("Decompiling %s/%s", start + offset, total)
                    decompiled = tools.decompile_function(
                        func, timeout=DEFAULT_DECOMPILE_TIMEOUT_SECONDS
                    )
                    documents.append(decompiled.code)
                    ids.append(decompiled.name)
                    metadatas.append(
                        {
                            "function_name": decompiled.name,
                            "entry_point": str(func.getEntryPoint()),
                        }
                    )
                except Exception as e:
                    failed += 1
                    logger.error(
                        "Failed to decompile %s: %s", func.getSymbol().getName(True), e
                    )

            if ids:
                # Ids already stored belong to an earlier, interrupted run; adding
                # them again fails on the duplicate key, and re-decompiling them is
                # the cost this resume exists to avoid.
                known = set(collection.get(ids=ids, include=[])["ids"])
                if known:
                    keep = [i for i, doc_id in enumerate(ids) if doc_id not in known]
                    reused += len(ids) - len(keep)
                    documents = [documents[i] for i in keep]
                    metadatas = [metadatas[i] for i in keep]
                    ids = [ids[i] for i in keep]

            if documents:
                # Only this window is alive in the heap at this point.
                collection.add(documents=documents, metadatas=metadatas, ids=ids)
                indexed += len(documents)

            logger.info(
                "Indexed %s/%s functions (%s reused, %s failed so far)",
                indexed + reused,
                total,
                reused,
                failed,
            )

        self._mark_collection_complete(collection, collection.count())
        logger.info(
            "Code analysis complete for collection '%s' (%s indexed, %s reused, %s failed)",
            program_info.name,
            indexed,
            reused,
            failed,
        )
        program_info.code_collection = collection

    def _init_strings_for_program(self, program_info: Any) -> None:
        logger.info("Loading strings for %s", program_info.name)
        program_info.strings = GhidraTools(program_info).get_all_strings()
        logger.info("Loaded %s strings for %s", len(program_info.strings), program_info.name)

    def _index_program(
        self,
        program_info: Any,
        *,
        code: bool = True,
        strings: bool = True,
    ) -> None:
        if code and program_info.code_collection is None:
            self._init_chroma_code_collection_for_program(program_info)
        if strings and program_info.strings is None:
            self._init_strings_for_program(program_info)

    def _index_done_callback(
        self,
        binary_name: str,
        future: concurrent.futures.Future,
    ) -> None:
        with self._index_lock:
            self._index_futures.pop(binary_name, None)
        # CancelledError derives from BaseException, so shutdown-cancelled work
        # must be checked for explicitly or it escapes as a spurious callback error.
        if future.cancelled():
            logger.info("Background indexing for %s cancelled during shutdown.", binary_name)
            return
        try:
            future.result()
            logger.info("Background indexing completed successfully for %s.", binary_name)
        except Exception:
            logger.error("Background indexing failed for %s.", binary_name, exc_info=True)
