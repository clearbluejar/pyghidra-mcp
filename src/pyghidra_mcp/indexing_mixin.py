import concurrent.futures
import logging
import threading
from pathlib import Path
from typing import Any

import chromadb
from chromadb.config import Settings

from pyghidra_mcp.tools import GhidraTools

logger = logging.getLogger(__name__)


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

    def shutdown_indexing(self) -> None:
        if self.index_executor:
            self.index_executor.shutdown(wait=True)

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

    def _init_chroma_code_collection_for_program(self, program_info: Any) -> None:
        from ghidra.program.model.listing import Function

        logger.info("Initializing Chroma code collection for %s", program_info.name)
        try:
            collection = self.chroma_client.get_collection(name=program_info.name)
            logger.info("Collection '%s' exists; skipping code ingest.", program_info.name)
            program_info.code_collection = collection
            return
        except Exception:
            logger.info("Creating new code collection '%s'", program_info.name)

        tools = GhidraTools(program_info)
        functions = tools.get_all_functions()
        decompiles = []
        ids = []
        metadatas = []

        for i, func in enumerate(functions):
            func: Function
            try:
                if i % 10 == 0:
                    logger.debug("Decompiling %s/%s", i, len(functions))
                decompiled = tools.decompile_function(func)
                decompiles.append(decompiled.code)
                ids.append(decompiled.name)
                metadatas.append(
                    {
                        "function_name": decompiled.name,
                        "entry_point": str(func.getEntryPoint()),
                    }
                )
            except Exception as e:
                logger.error("Failed to decompile %s: %s", func.getSymbol().getName(True), e)

        collection = self.chroma_client.create_collection(name=program_info.name)
        try:
            batch_size = 5000
            for i in range(0, len(decompiles), batch_size):
                end = min(i + batch_size, len(decompiles))
                collection.add(
                    documents=decompiles[i:end],
                    metadatas=metadatas[i:end],
                    ids=ids[i:end],
                )
        except Exception as e:
            logger.error("Failed add decompiles to collection: %s", e)

        logger.info("Code analysis complete for collection '%s'", program_info.name)
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
        try:
            future.result()
            logger.info("Background indexing completed successfully for %s.", binary_name)
        except Exception:
            logger.error("Background indexing failed for %s.", binary_name, exc_info=True)
