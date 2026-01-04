"""Data models for Ghidra context management."""

from typing import TYPE_CHECKING

import chromadb

if TYPE_CHECKING:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Program


class ProgramInfo:
    """Information about a loaded program with lazy loading support"""

    def __init__(
        self,
        name: str,
        load_callback,
        metadata: dict,
        ghidra_analysis_complete: bool,
        domain_file_path: str,
        file_path=None,
        load_time: float | None = None,
        code_collection: chromadb.Collection | None = None,
        strings_collection: chromadb.Collection | None = None,
    ):
        self.name = name
        self.load_callback = load_callback
        self.metadata = metadata
        self.ghidra_analysis_complete = ghidra_analysis_complete
        self.domain_file_path = domain_file_path
        self.file_path = file_path
        self.load_time = load_time
        self.code_collection = code_collection
        self.strings_collection = strings_collection

        # Private backing fields
        self._program: Program | None = None
        self._flat_api: FlatProgramAPI | None = None
        self._decompiler: DecompInterface | None = None

    @property
    def program(self) -> "Program":
        if self._program is None:
            self.load_callback(self.domain_file_path)
        if self._program is None:
            raise RuntimeError(f"Failed to load program {self.name}")
        return self._program

    @program.setter
    def program(self, value):
        self._program = value

    @property
    def flat_api(self) -> "FlatProgramAPI | None":
        if self._flat_api is None:
            # triggers load if needed
            if self.program:
                # self.program property ensures _program is set, which sets _flat_api
                pass
        return self._flat_api

    @flat_api.setter
    def flat_api(self, value):
        self._flat_api = value

    @property
    def decompiler(self) -> "DecompInterface":
        if self._decompiler is None:
            # Implicitally load program
            if self.program:
                pass
        return self._decompiler

    @decompiler.setter
    def decompiler(self, value):
        self._decompiler = value

    @property
    def analysis_complete(self) -> bool:
        """Check if Ghidra analysis is complete."""
        return self.ghidra_analysis_complete
