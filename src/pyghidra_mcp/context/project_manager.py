"""Project and binary management for Ghidra context."""

import concurrent.futures
import hashlib
import logging
import multiprocessing
import time
from pathlib import Path
from typing import TYPE_CHECKING

import chromadb
from chromadb.config import Settings

from pyghidra_mcp.context.models import ProgramInfo

if TYPE_CHECKING:
    from ghidra.base.project import GhidraProject
    from ghidra.framework.model import DomainFile
    from ghidra.program.model.listing import Program

# Configure logging
logger = logging.getLogger(__name__)


class ProjectManager:
    """Manages Ghidra project creation, binary import/deletion, and program caching."""

    def __init__(
        self,
        project_name: str,
        project_path: str | Path,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
        no_symbols: bool = False,
        gdts: list | None = None,
        program_options: dict | None = None,
        gzfs_path: str | Path | None = None,
        threaded: bool = True,
        max_workers: int | None = None,
        wait_for_analysis: bool = False,
    ):
        """
        Initializes a new ProjectManager for Ghidra project management.

        Args:
            project_name: The name of the Ghidra project.
            project_path: The directory where the project will be created.
            force_analysis: Force a new binary analysis each run.
            verbose_analysis: Verbose logging for analysis step.
            no_symbols: Turn off symbols for analysis.
            gdts: List of paths to GDT files for analysis.
            program_options: Dictionary with program options (custom analyzer settings).
            gzfs_path: Location to store GZFs of analyzed binaries.
            threaded: Use threading during analysis.
            max_workers: Number of workers for threaded analysis.
            wait_for_analysis: Wait for initial project analysis to complete.
        """
        from ghidra.base.project import GhidraProject

        self.project_name = project_name
        self.project_path = Path(project_path)
        self.project: GhidraProject = self._get_or_create_project()

        self.programs: dict[str, ProgramInfo] = {}
        # LRU cache to track usages of programs
        self.lru_cache: list[str] = []

        # Set cache size based on workers to ensure we don't evict programs
        # currently in use by workers Minimum 5, but at least max_workers + 2
        # (buffers for main thread etc)
        cpu_count = multiprocessing.cpu_count() or 4
        self.max_workers = max_workers if max_workers else cpu_count

        if not threaded:
            logger.warning("--no-threaded flag forcing max_workers to 1")
            self.max_workers = 1

        self.cache_size = max(5, self.max_workers + 2)
        self._init_project_programs()

        project_dir = self.project_path / self.project_name
        chromadb_path = project_dir / "chromadb"
        self.chroma_client = chromadb.PersistentClient(
            path=str(chromadb_path), settings=Settings(anonymized_telemetry=False)
        )

        # From GhidraDiffEngine
        self.force_analysis = force_analysis
        self.verbose_analysis = verbose_analysis
        self.no_symbols = no_symbols
        self.gdts = gdts if gdts is not None else []
        self.program_options = program_options
        self.gzfs_path = Path(gzfs_path) if gzfs_path else self.project_path / "gzfs"
        if self.gzfs_path:
            self.gzfs_path.mkdir(exist_ok=True, parents=True)

        self.threaded = threaded
        self.executor = (
            concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
            if self.threaded
            else None
        )
        self.import_executor = (
            concurrent.futures.ThreadPoolExecutor(max_workers=1) if self.threaded else None
        )
        self.wait_for_analysis = wait_for_analysis

        # Initialize analysis manager
        from pyghidra_mcp.context.analysis_manager import AnalysisManager

        self.analysis_manager = AnalysisManager(self)

    def close(self, save: bool = True):
        """
        Saves changes to all open programs and closes the project.
        """
        for _program_name, program_info in self.programs.items():
            if program_info._program:
                program = program_info.program
                self.project.close(program)

        if self.executor:
            self.executor.shutdown(wait=True)

        if self.import_executor:
            self.import_executor.shutdown(wait=True)

        self.project.close()
        logger.info(f"Project {self.project_name} closed.")

    def _ensure_program_loaded(self, binary_name: Path | str):
        """
        Callback to load a program when it is accessed.
        Manages LRU cache to keep memory usage in check.
        """
        from ghidra.program.flatapi import FlatProgramAPI

        binary_path = Path(binary_name)
        if not binary_path.is_absolute():
            binary_path = Path("/") / binary_path
            binary_name = str(binary_path)

        binary_name = str(binary_name)
        program_info = self.programs.get(binary_name)
        if not program_info:
            raise ValueError(f"Program {binary_name} not found in project.")

        # If already loaded, move to end of LRU (most recently used)
        if program_info._program is not None:
            if binary_name in self.lru_cache:
                self.lru_cache.remove(binary_name)
            self.lru_cache.append(binary_name)
            return

        logger.info(f"Lazy loading program: {binary_name}")

        # If cache is full, unload the least recently used program
        if len(self.lru_cache) >= self.cache_size:
            lru_binary = self.lru_cache.pop(0)
            self._unload_program(lru_binary)

        # Load the program
        # We need the parent folder path and filename
        # This was constructed during init, we can reconstruct or store it better.
        # Ideally we stored the 'domain_file_path' in ProgramInfo.
        df_path = Path(program_info.domain_file_path)
        # Ghidra expects folder path string and program name
        # df_path includes program name.
        parent_path = str(df_path.parent).replace("\\", "/")  # Ensure forward slashes for Ghidra
        # Root folder is "/"
        if parent_path == ".":
            parent_path = "/"

        program = self.project.openProgram(parent_path, df_path.name, False)

        program_info._program = program
        program_info._flat_api = FlatProgramAPI(program)
        # Decompiler setup is deferred to analysis_manager
        program_info._decompiler = None

        # Set Metadata
        program_info.metadata = self.get_metadata(program)

        self.lru_cache.append(binary_name)
        logger.info(f"Loaded {binary_name}. Cache size: {len(self.lru_cache)}")

    def _unload_program(self, binary_name: str):
        """
        Unloads a program to free memory.
        """
        program_info = self.programs.get(binary_name)
        if not program_info or not program_info._program:
            return

        logger.info(f"Unloading program to free memory: {binary_name}")
        program = program_info._program
        self.project.close(program)

        program_info._program = None
        program_info._flat_api = None
        program_info._decompiler = None

        # Ensure removed from cache if present (might have been popped already)
        if binary_name in self.lru_cache:
            self.lru_cache.remove(binary_name)

    def _get_or_create_project(self) -> "GhidraProject":
        """
        Creates a new Ghidra project if it doesn't exist, otherwise opens the existing project.

        Returns:
            The Ghidra project object.
        """
        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        project_dir = self.project_path / self.project_name
        project_dir.mkdir(exist_ok=True, parents=True)
        project_dir_str = str(project_dir.absolute())

        locator = ProjectLocator(project_dir_str, self.project_name)

        if locator.exists():
            logger.info(f"Opening existing project: {self.project_name}")
            return GhidraProject.openProject(project_dir_str, self.project_name, True)
        else:
            logger.info(f"Creating new project: {self.project_name}")
            return GhidraProject.createProject(project_dir_str, self.project_name, False)

    def _init_project_programs(self):
        """
        Initializes the programs dictionary with existing programs in the project.
        """
        all_binary_paths = self.list_binaries()
        for binary_path_s in all_binary_paths:
            # Create lazy ProgramInfo
            # We assume analysis is not complete until proven otherwise (e.g. by analyze_project)
            # Metadata is empty until loaded.
            name = Path(binary_path_s).name
            program_info = ProgramInfo(
                name=name,
                load_callback=self._ensure_program_loaded,
                metadata={},
                ghidra_analysis_complete=False,
                domain_file_path=binary_path_s,
            )
            self.programs[binary_path_s] = program_info

    def list_binaries(self) -> list[str]:
        """List all the binaries within the Ghidra project."""

        def list_folder_contents(folder) -> list[str]:
            names: list[str] = []
            for subfolder in folder.getFolders():
                names.extend(list_folder_contents(subfolder))

            names.extend([f.getPathname() for f in folder.getFiles()])
            return names

        return list_folder_contents(self.project.getRootFolder())

    def list_binary_domain_files(self) -> list["DomainFile"]:
        """Return a list of DomainFile objects for all binaries in the project.

        This mirrors `list_binaries` but returns the DomainFile objects themselves
        (filtered by content type == "Program").
        """
        from ghidra.framework.model import DomainFile

        def list_folder_domain_files(folder) -> list["DomainFile"]:
            files: list[DomainFile] = []
            for subfolder in folder.getFolders():
                files.extend(list_folder_domain_files(subfolder))

            files.extend([f for f in folder.getFiles() if f.getContentType() == "Program"])
            return files

        return list_folder_domain_files(self.project.getRootFolder())

    def delete_program(self, program_name: str) -> bool:
        """
        Deletes a program from the Ghidra project and saves the project.

        Args:
            program_name: The name of the program to delete.

        Returns:
            True if the program was deleted successfully, False otherwise.
        """
        program_info = self.programs.get(program_name)
        if not program_info:
            available_progs = list(self.programs.keys())
            raise ValueError(
                f"Binary {program_name} not found. Available binaries: {available_progs}"
            )
        else:
            logger.info(f"Deleting program: {program_name}")
            try:
                # Ensure it's unloaded (closed) before deleting
                self._unload_program(program_name)

                # We need the DomainFile to delete it but we don't want to reopen the program
                file_system = self.project.getProjectData()
                domain_file = file_system.getFile(program_info.domain_file_path)
                if domain_file:
                    domain_file.delete()
                else:
                    logger.warning(
                        f"Could not find domain file for deletion: {program_info.domain_file_path}"
                    )

                # clean up program reference
                del self.programs[program_name]

                return True
            except Exception as e:
                logger.error(f"Error deleting program '{program_name}': {e}")
                return False

    def import_binary(
        self, binary_path: str | Path, analyze: bool = False, relative_path: Path | None = None
    ) -> None:
        """
        Imports a single binary into the project.

        Args:
            binary_path: Path to the binary file.
            analyze: Perform analysis on this binary. Useful if not importing in bulk.
            relative_path: Relative path within the project hierarchy (Path("bin") or Path("lib")).

        Returns:
            None
        """
        from ghidra.program.model.listing import Program

        binary_path = Path(binary_path)
        if binary_path.is_dir():
            return self.import_binaries([binary_path])

        program_name = self._gen_unique_bin_name(binary_path)

        program: Program
        root_folder = self.project.getRootFolder()

        # Create folder hierarchy if relative_path is provided
        if relative_path:
            ghidra_folder = self._create_folder_hierarchy(root_folder, relative_path)
        else:
            ghidra_folder = root_folder

        # Check if program already exists at this location
        full_path = str(Path(ghidra_folder.pathname) / program_name)
        if self.programs.get(full_path):
            logger.info(f"Opening existing program: {program_name}")
            # Accessing .program triggers load if not loaded, but here we want to ensure it's loaded
            # AND set the _program backing field if we were just importing?
            # Actually if it exists, we just use it.
            program = self.programs[full_path].program
            program_info = self.programs[full_path]
        else:
            logger.info(f"Importing new program: {program_name}")
            program = self.project.importProgram(binary_path)
            program.name = program_name
            if program:
                self.project.saveAs(program, ghidra_folder.pathname, program_name, True)

            program_info = self._init_program_info(program)
            # The pathname might be different after saveAs?
            # program.getDomainFile().getPathname() should be correct.
            self.programs[program.getDomainFile().pathname] = program_info

            # Since we have the program open, add it to LRU
            self.lru_cache.append(program.getDomainFile().pathname)
            if len(self.lru_cache) > self.cache_size:
                # Evict oldest different from this one
                # We just appended, so this one is last.
                # Pop first.
                evict = self.lru_cache.pop(0)
                self._unload_program(evict)

        if not program:
            raise ImportError(f"Failed to import binary: {binary_path}")

        if analyze:
            self.analysis_manager.analyze_program(program_info.program)
            self.analysis_manager._init_chroma_collections_for_program(program_info)

        logger.info(f"Program {program_name} is ready for use.")

    @staticmethod
    def _create_folder_hierarchy(root_folder, relative_path: Path):
        """
        Recursively creates folder hierarchy in Ghidra project.

        Args:
            root_folder: The root folder of the Ghidra project.
            relative_path: The path hierarchy to create (e.g., Path("bin/subfolder")).

        Returns:
            The folder object at the end of the hierarchy.
        """
        current_folder = root_folder

        # Split the path into parts and iterate through them
        for part in relative_path.parts:
            existing_folder = current_folder.getFolder(part)
            if existing_folder:
                current_folder = existing_folder
                logger.debug(f"Using existing folder: {part}")
            else:
                current_folder = current_folder.createFolder(part)
                logger.debug(f"Created folder: {part}")

        return current_folder

    def import_binaries(self, binary_paths: list[str | Path]):
        """
        Imports a list of binaries into the project.
        If an entry is a directory it will be walked recursively
        and all regular files found will be imported, preserving directory structure.

        Note: Ghidra does not directly support multithreaded importing into the same project.
        Args:
            binary_paths: A list of paths to the binary files or directories.
        """
        resolved_paths: list[Path] = [Path(p) for p in binary_paths]

        # Tuple of (full system path, relative path from provided path)
        files_to_import: list[tuple[Path, Path | None]] = []
        for p in resolved_paths:
            if p.is_dir():
                logger.info(f"Discovering files in directory: {p}")
                for f in p.rglob("*"):
                    if f.is_file() and self._is_binary_file(f):
                        # Store the relative path (e.g., "bin" or "lib/subfolder")
                        relative = f.relative_to(p).parent
                        files_to_import.append((f, relative))
            elif p.is_file() and self._is_binary_file(p):
                files_to_import.append((p, None))

        if not files_to_import:
            logger.info("No files found to import from provided paths.")
            return

        logger.info(f"Importing {len(files_to_import)} binary files into project...")
        for bin_path, relative_path in files_to_import:
            try:
                self.import_binary(bin_path, analyze=True, relative_path=relative_path)
            except Exception as e:
                logger.error(f"Failed to import {bin_path}: {e}")
                # continue importing remaining files

    @staticmethod
    def _is_binary_file(path: Path) -> bool:
        """
        Quick header-based check for common binary formats.
        Recognizes ELF (0x7f 'ELF') and PE ('MZ' DOS header) signatures.
        Returns False on read errors or unknown signatures.
        """
        try:
            with path.open("rb") as f:
                header = f.read(4)
                if not header:
                    return False
                # ELF: 0x7f 'ELF'
                if header.startswith(b"\x7fELF"):
                    return True
                # PE executables typically start with 'MZ' (DOS stub)
                if header.startswith(b"MZ"):
                    return True
                return False
        except Exception as e:
            logger.debug(f"Could not read file header for {path}: {e}")
            return False

    def _import_callback(self, future: concurrent.futures.Future):
        """
        A callback function to handle results or exceptions from the import task.
        """
        try:
            result = future.result()
            logger.info(f"Background import task completed successfully. Result: {result}")
        except Exception as e:
            logger.error(f"FATAL ERROR during background binary import: {e}", exc_info=True)
            raise e

    def import_binary_backgrounded(self, binary_path: str | Path):
        """
        Spawns a thread and imports a binary into the project.
        When the binary is analyzed it will be added to the project.

        Args:
            binary_path: The path of the binary to import.
        """
        if not Path(binary_path).exists():
            raise FileNotFoundError(f"The file {binary_path} cannot be found")

        if self.import_executor:
            future = self.import_executor.submit(self.import_binary, binary_path, True)
            future.add_done_callback(self._import_callback)
        else:
            self.import_binary(binary_path, True)

    def get_program_info(self, binary_name: str) -> "ProgramInfo":
        """Get program info or raise ValueError if not found."""
        import json

        program_info = self.programs.get(binary_name)
        if not program_info:
            # Exact program name not in the list
            available_progs = list(self.programs.keys())

            # If the LLM gave us just the binary name, use that
            available_prog_names = {
                Path(prog).name: prog_info for prog, prog_info in self.programs.items()
            }
            program_info = available_prog_names.get(binary_name)

            if not program_info:
                raise ValueError(
                    f"Binary {binary_name} not found. Available binaries: {available_progs}"
                )
        if not program_info.analysis_complete:
            raise RuntimeError(
                json.dumps(
                    {
                        "message": f"Analysis incomplete for binary '{binary_name}'.",
                        "binary_name": binary_name,
                        "ghidra_analysis_complete": program_info.ghidra_analysis_complete,
                        "code_collection": program_info.code_collection is not None,
                        "strings_collection": program_info.strings_collection is not None,
                        "suggestion": "Wait and try tool call again.",
                    }
                )
            )
        return program_info

    def _init_program_info(self, program):
        """Create ProgramInfo from a loaded program."""
        from ghidra.program.flatapi import FlatProgramAPI

        assert program is not None

        metadata = self.get_metadata(program)

        # This is called when we HAVE a program (e.g. from import_binary).
        # We need to create a ProgramInfo that is "loaded".

        program_info = ProgramInfo(
            name=program.name,
            load_callback=self._ensure_program_loaded,
            metadata=metadata,
            ghidra_analysis_complete=False,  # Will be set true by analyze_plugin if called
            file_path=Path(metadata.get("Executable Location", "")),  # Safely get path
            load_time=time.time(),
            code_collection=None,
            strings_collection=None,
            domain_file_path=program.getDomainFile().getPathname(),
        )

        # Manually populate the private fields since we have the object
        program_info._program = program
        program_info._flat_api = FlatProgramAPI(program)
        program_info._decompiler = None  # Will be set by analysis_manager

        return program_info

    @staticmethod
    def _gen_unique_bin_name(path: Path):
        """
        Generate unique program name from binary for Ghidra Project
        """
        path = Path(path)

        def _sha1_file(path: Path) -> str:
            sha1 = hashlib.sha1()

            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha1.update(chunk)

            return sha1.hexdigest()

        return "-".join((path.name, _sha1_file(path.absolute())[:6]))

    def get_metadata(self, prog: "Program") -> dict:
        """
        Generate dict from program metadata
        """
        meta = prog.getMetadata()
        return dict(meta)
