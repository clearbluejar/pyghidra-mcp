import concurrent.futures
import hashlib
import json
import logging
import multiprocessing
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Union

import chromadb

from pyghidra_mcp.decompiler_pool import DecompilerPool
from pyghidra_mcp.import_detection import is_ghidra_importable
from pyghidra_mcp.import_planning import ImportCandidate, build_import_plan
from pyghidra_mcp.indexing_mixin import IndexingMixin
from pyghidra_mcp.models import (
    ImportRequestResult,
    ProgramInfo as ProgramInfoModel,
    SkippedImport as SkippedImportModel,
)

if TYPE_CHECKING:
    from ghidra.base.project import GhidraProject
    from ghidra.framework.model import DomainFile
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Program

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ProgramInfo:
    """Information about a loaded program"""

    name: str
    program: "Program"
    flat_api: "FlatProgramAPI | None"
    decompiler_pool: DecompilerPool
    metadata: dict  # Ghidra program metadata
    ghidra_analysis_complete: bool
    file_path: Path | None = None
    load_time: float | None = None
    code_collection: chromadb.Collection | None = None
    strings: list | None = None

    @property
    def analysis_complete(self) -> bool:
        """Check if Ghidra analysis is complete."""
        return self.ghidra_analysis_complete


class PyGhidraContext(IndexingMixin):
    """
    Manages a Ghidra project, including its creation, program imports, and cleanup.
    """

    _analysis_bundle_host_lock = threading.RLock()

    def __init__(
        self,
        project_name: str,
        project_path: str | Path,
        pyghidra_mcp_dir: Path | None = None,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
        no_symbols: bool = False,
        gdts: list | None = None,
        program_options: dict | None = None,
        gzfs_path: str | Path | None = None,
        threaded: bool = True,
        max_workers: int | None = None,
        wait_for_analysis: bool = False,
        symbols_path: str | Path | None = None,
        sym_file_path: str | Path | None = None,
    ):
        """
        Initializes a new Ghidra project context.

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
            symbols_path: Path to local symbol store.
            sym_file_path: Path to a specific PDB file.
        """
        from ghidra.base.project import GhidraProject

        self.project_name = project_name
        self.project_path = Path(project_path)
        self.project: GhidraProject = self._get_or_create_project()

        # Use provided pyghidra-mcp directory or create default
        if pyghidra_mcp_dir:
            self.pyghidra_mcp_dir = pyghidra_mcp_dir
        else:
            # Default: create pyghidra-mcp directory alongside project
            self.pyghidra_mcp_dir = self.project_path / "pyghidra-mcp"

        # From GhidraDiffEngine
        self.force_analysis = force_analysis
        self.verbose_analysis = verbose_analysis
        self.no_symbols = no_symbols
        self.gdts = gdts if gdts is not None else []

        # Symbol configuration
        self.symbols_path = (
            Path(symbols_path) if symbols_path else self.pyghidra_mcp_dir / "symbols"
        )
        self.sym_file_path = Path(sym_file_path) if sym_file_path else None
        self.program_options = program_options
        self.gzfs_path = Path(gzfs_path) if gzfs_path else self.pyghidra_mcp_dir / "gzfs"
        if self.gzfs_path:
            self.gzfs_path.mkdir(exist_ok=True, parents=True)

        self.threaded = threaded
        cpu_count = multiprocessing.cpu_count() or 4
        self.max_workers = max_workers if max_workers else cpu_count

        if not self.threaded:
            logger.warn("--no-threaded flag forcing max_workers to 1")
            self.max_workers = 1
        self._init_indexing_state(self.pyghidra_mcp_dir, threaded=self.threaded)
        self.executor = (
            concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
            if self.threaded
            else None
        )
        self.import_executor = (
            concurrent.futures.ThreadPoolExecutor(max_workers=1) if self.threaded else None
        )
        self.wait_for_analysis = wait_for_analysis

        self.programs: dict[str, ProgramInfo] = {}
        self._init_project_programs()

    def close(self, save: bool = True):
        """
        Saves changes to all open programs and closes the project.
        """
        if self.executor:
            self.executor.shutdown(wait=True)

        self.shutdown_indexing()

        if self.import_executor:
            self.import_executor.shutdown(wait=True)

        for _program_name, program_info in self.programs.items():
            self._dispose_decompiler(program_info)
            program = program_info.program
            self.project.close(program)

        self.project.close()
        logger.info(f"Project {self.project_name} closed.")

    def _get_or_create_project(self) -> "GhidraProject":
        """
        Creates a new Ghidra project if it doesn't exist, otherwise opens the existing project.

        Returns:
            The Ghidra project object.
        """

        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        # For standard Ghidra projects, use directory containing .gpr file
        project_dir = self.project_path
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
        from ghidra.program.model.listing import Program

        for domain_file in self.list_binary_domain_files():
            parent = domain_file.getParent()
            parent_path = parent.pathname if parent else "/"
            program: Program = self.project.openProgram(parent_path, domain_file.getName(), False)
            program_info = self._init_program_info(program)
            self.programs[domain_file.pathname] = program_info

    def list_binaries(self) -> list[str]:
        """List all the binaries within the Ghidra project."""

        def list_folder_contents(folder) -> list[str]:
            names: list[str] = []
            for subfolder in folder.getFolders():
                names.extend(list_folder_contents(subfolder))

            names.extend([f.getPathname() for f in folder.getFiles()])
            return names

        return list_folder_contents(self.project.getRootFolder())

    def list_program_infos(self) -> list[ProgramInfo]:
        """Return loaded program infos for MCP project listing."""
        return list(self.programs.values())

    def list_project_binary_infos(self) -> list[ProgramInfoModel]:
        """Return MCP response models for project binaries."""
        program_infos = []
        for name, pi in self.programs.items():
            program_infos.append(
                ProgramInfoModel(
                    name=name,
                    file_path=str(pi.file_path) if pi.file_path else None,
                    load_time=pi.load_time,
                    analysis_complete=pi.analysis_complete,
                    metadata={},
                    code_indexed=pi.code_collection is not None,
                    strings_indexed=pi.strings is not None,
                )
            )
        return program_infos

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
                program_to_delete: Program = program_info.program
                program_to_delete_df: DomainFile = program_to_delete.getDomainFile()
                self._dispose_decompiler(program_info)
                self.project.close(program_to_delete)
                program_to_delete_df.delete()
                # clean up program reference
                del self.programs[program_name]
                return True
            except Exception as e:
                logger.error(f"Error deleting program '{program_name}': {e}")
                return False

    def import_binary(
        self, binary_path: str | Path, analyze: bool = False, relative_path: Path | None = None
    ) -> str | list[str]:
        """
        Imports a single binary into the project.

        Args:
            binary_path: Path to the binary file.
            analyze: Perform analysis on this binary. Useful if not importing in bulk.
            relative_path: Relative path within the project hierarchy (Path("bin") or Path("lib")).

        Returns:
            Imported program pathname.
        """
        from ghidra.program.model.listing import Program

        binary_path = Path(binary_path)
        if binary_path.is_dir():
            return self.import_binaries([binary_path], analyze=analyze)

        program_name = PyGhidraContext._gen_unique_bin_name(binary_path)

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
            program = self.programs[full_path].program
            program_info = self.programs[full_path]
        else:
            logger.info(f"Importing new program: {program_name}")
            imported_program = self.project.importProgram(binary_path)
            program = imported_program
            program.name = program_name
            if program:
                self.project.saveAs(program, ghidra_folder.pathname, program_name, True)
                self.project.close(imported_program)
                program = self.project.openProgram(ghidra_folder.pathname, program_name, False)

            program_info = self._init_program_info(program)
            self.programs[program.getDomainFile().pathname] = program_info

        if not program:
            raise ImportError(f"Failed to import binary: {binary_path}")

        if analyze:
            self.analyze_program(program_info.program)
            self.schedule_indexing(str(program.getDomainFile().pathname))

        logger.info(f"Program {program_name} is ready for use.")
        return str(program.getDomainFile().pathname)

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

    def import_binaries(self, binary_paths: list[str | Path], analyze: bool = False) -> list[str]:
        """
        Imports a list of binaries into the project.
        If an entry is a directory it will be walked recursively
        and all regular files found will be imported, preserving directory structure.

        Note: Ghidra does not directly support multithreaded importing into the same project.
        Args:
            binary_paths: A list of paths to the binary files or directories.
            analyze: Whether to analyze the imported binaries.
        """
        import_plan = build_import_plan(binary_paths)
        files_to_import = [
            (candidate.path, candidate.relative_path) for candidate in import_plan.candidates
        ]

        for skipped in import_plan.skipped:
            logger.info("Skipping %s: %s", skipped.path, skipped.reason)

        if not files_to_import:
            logger.info("No files found to import from provided paths.")
            return []

        logger.info(f"Importing {len(files_to_import)} binary files into project...")
        return self._import_candidates(import_plan.candidates, analyze=analyze)

    def _import_candidates(
        self,
        candidates: list[ImportCandidate],
        *,
        analyze: bool = False,
    ) -> list[str]:
        imported_programs: list[str] = []
        for candidate in candidates:
            try:
                imported = self.import_binary(
                    candidate.path,
                    analyze=analyze,
                    relative_path=candidate.relative_path,
                )
                if isinstance(imported, list):
                    imported_programs.extend(imported)
                else:
                    imported_programs.append(imported)
            except Exception as e:
                logger.error(f"Failed to import {candidate.path}: {e}")
                # continue importing remaining files
        return imported_programs

    def _is_binary_file(self, path: Path) -> bool:
        return is_ghidra_importable(path)

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

    def import_binary_backgrounded(self, binary_path: str | Path) -> ImportRequestResult:
        """
        Spawns a thread and imports a binary into the project.
        When the binary is analyzed it will be added to the project.

        Args:
            binary_path: The path of the binary to import.
        """
        if not Path(binary_path).exists():
            raise FileNotFoundError(f"The file {binary_path} cannot be found")

        import_plan = build_import_plan([binary_path])

        if self.import_executor and import_plan.candidates:
            future = self.import_executor.submit(
                self._import_candidates,
                import_plan.candidates,
                analyze=True,
            )
            future.add_done_callback(self._import_callback)
        elif import_plan.candidates:
            self._import_candidates(import_plan.candidates, analyze=True)

        queued_paths = [str(candidate.path) for candidate in import_plan.candidates]
        skipped = [
            SkippedImportModel(path=str(skipped.path), reason=skipped.reason)
            for skipped in import_plan.skipped
        ]
        message = (
            f"Queued {len(queued_paths)} import(s) from {binary_path} in the background."
            if queued_paths
            else f"No importable files were queued from {binary_path}."
        )
        return ImportRequestResult(
            requested_path=str(binary_path),
            queued_count=len(queued_paths),
            queued_paths=queued_paths,
            skipped_count=len(skipped),
            skipped=skipped,
            message=message,
        )

    def get_program_info(self, binary_name: str) -> "ProgramInfo":
        """Get program info or raise ValueError if not found."""
        program_info = self._lookup_program_info(binary_name)
        if not program_info:
            # Exact program name not in the list
            available_progs = list(self.programs.keys())
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
                        "code_indexed": program_info.code_collection is not None,
                        "strings_indexed": program_info.strings is not None,
                        "suggestion": "Wait and try tool call again.",
                    }
                )
            )
        self.schedule_indexing(binary_name)
        return program_info

    def _lookup_program_info(self, binary_name: str) -> "ProgramInfo | None":
        program_info = self.programs.get(binary_name)
        if program_info is not None:
            return program_info

        available_prog_names = {
            Path(prog).name: prog_info for prog, prog_info in self.programs.items()
        }
        return available_prog_names.get(binary_name)

    def _init_program_info(self, program):
        from ghidra.program.flatapi import FlatProgramAPI

        assert program is not None

        metadata = self.get_metadata(program)

        program_info = ProgramInfo(
            name=program.name,
            program=program,
            flat_api=FlatProgramAPI(program),
            decompiler_pool=self._create_decompiler_pool(program),
            metadata=metadata,
            ghidra_analysis_complete=False,
            file_path=metadata["Executable Location"],
            load_time=time.time(),
            code_collection=None,
            strings=None,
        )

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

    # Callback function that runs when the future is done to catch any exceptions
    def _analysis_done_callback(self, future: concurrent.futures.Future):
        try:
            future.result()
            logging.info("Asynchronous analysis finished successfully.")
            if not self.wait_for_analysis:
                self.schedule_startup_indexing(max_binaries=max(len(self.programs), 1))
        except Exception as e:
            logging.error(f"Asynchronous analysis failed with exception: {e}")
            raise e

    def analyze_project(
        self,
        require_symbols: bool = True,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
    ) -> concurrent.futures.Future | None:
        if self.executor:
            future = self.executor.submit(
                self._analyze_project,
                require_symbols,
                force_analysis,
                verbose_analysis,
            )

            future.add_done_callback(self._analysis_done_callback)

            if self.wait_for_analysis:
                logger.info("Waiting for analysis to complete...")
                try:
                    future.result()
                    logger.info("Analysis complete.")
                except Exception as e:
                    logger.error(f"Analysis completed with an exception: {e}")
                return None
            return future
        else:
            # No executor: just run synchronously
            self._analyze_project(require_symbols, force_analysis, verbose_analysis)
            self.schedule_startup_indexing(max_binaries=max(len(self.programs), 1))
            return None

    def _analyze_project(
        self,
        require_symbols: bool = True,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
    ) -> None:
        """
        Analyzes all files found within the Ghidra project
        """
        domain_files = self.list_binary_domain_files()

        logger.info(f"Starting analysis for {len(domain_files)} binaries")

        prog_count = len(domain_files)
        completed_count = 0

        if self.executor:
            futures = {
                self.executor.submit(
                    self.analyze_program,
                    domainFile,
                    require_symbols,
                    force_analysis,
                    verbose_analysis,
                )
                for domainFile in domain_files
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                logger.info(f"Analysis complete for {result.getName()}")
                completed_count += 1
                logger.info(f"Completed {completed_count}/{prog_count} programs")
        else:
            for domain_file in domain_files:
                self.analyze_program(domain_file, require_symbols, force_analysis, verbose_analysis)
                completed_count += 1
                logger.info(f"Completed {completed_count}/{prog_count} programs")

        logger.info("All programs analyzed.")

    def analyze_program(  # noqa C901
        self,
        df_or_prog: Union["DomainFile", "Program"],
        require_symbols: bool = True,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
    ):
        # Import symbol utilities from ghidrecomp
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.framework.model import DomainFile
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.listing import Program
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidrecomp.utility import get_pdb, set_pdb, set_remote_pdbs, setup_symbol_server

        df = df_or_prog
        if not isinstance(df_or_prog, DomainFile):
            df = df_or_prog.getDomainFile()

        if self.programs.get(df.pathname):
            # program already opened and initialized
            program = self.programs[df.pathname].program
        else:
            # open program from Ghidra Project
            program = self.project.openProgram(df.getParent().pathname, df_or_prog.getName(), False)
            self.programs[df.pathname] = self._init_program_info(program)

        assert isinstance(program, Program)

        logger.info(f"Analyzing: {program}")

        for gdt in self.gdts:
            logger.info(f"Loading GDT: {gdt}")
            if not Path(gdt).exists():
                raise FileNotFoundError(f"GDT Path not found {gdt}")
            self.apply_gdt(program, gdt)

        gdt_names = [name for name in program.getDataTypeManager().getSourceArchives()]
        if len(gdt_names) > 0:
            logger.debug(f"Using file gdts: {gdt_names}")

        if verbose_analysis or self.verbose_analysis:
            monitor = ConsoleTaskMonitor()
            flat_api = FlatProgramAPI(program, monitor)
        else:
            flat_api = FlatProgramAPI(program)

        if (
            GhidraProgramUtilities.shouldAskToAnalyze(program)
            or force_analysis
            or self.force_analysis
        ):
            with self._analysis_bundle_host_lock:
                GhidraScriptUtil.acquireBundleHostReference()

                if program and program.getFunctionManager().getFunctionCount() > 1000:
                    # Force Decomp Param ID is not set
                    if (
                        self.program_options is not None
                        and self.program_options.get("program_options", {})
                        .get("Analyzers", {})
                        .get("Decompiler Parameter ID")
                        is None
                    ):
                        self.set_analysis_option(program, "Decompiler Parameter ID", True)

                if self.program_options:
                    analyzer_options = self.program_options.get("program_options", {}).get(
                        "Analyzers", {}
                    )
                    for k, v in analyzer_options.items():
                        logger.info(f"Setting prog option:{k} with value:{v}")
                        self.set_analysis_option(program, k, v)

                if self.no_symbols:
                    logger.warn(
                        f"Disabling symbols for analysis! --no-symbols flag: {self.no_symbols}"
                    )
                    self.set_analysis_option(program, "PDB Universal", False)

                else:
                    # Configure symbols if enabled
                    if self.sym_file_path:
                        logger.info(f"Setting PDB file: {self.sym_file_path}")
                        set_pdb(program, self.sym_file_path)
                    else:
                        logger.info(f"Setting up symbol server at {self.symbols_path}")
                        setup_symbol_server(self.symbols_path)
                        set_remote_pdbs(program, True)

                    # Verify PDB loaded
                    pdb = get_pdb(program)
                    if pdb is None:
                        logger.warn(f"Failed to find pdb for {program.name}")
                    else:
                        logger.info(f"Loaded pdb: {pdb}")

                logger.info(f"Starting Ghidra analysis of {program}...")
                try:
                    flat_api.analyzeAll(program)
                    if hasattr(GhidraProgramUtilities, "setAnalyzedFlag"):
                        GhidraProgramUtilities.setAnalyzedFlag(program, True)
                    elif hasattr(GhidraProgramUtilities, "markProgramAnalyzed"):
                        GhidraProgramUtilities.markProgramAnalyzed(program)
                    else:
                        raise Exception("Missing set analyzed flag method!")
                finally:
                    GhidraScriptUtil.releaseBundleHostReference()
                    self.project.save(program)
        else:
            logger.info(f"Analysis already complete.. skipping {program}!")

        # Save program as gzfs
        if self.gzfs_path is not None:
            from java.io import File  # type: ignore

            pathname = df.pathname.replace("/", "_")
            gzf_file = self.gzfs_path / f"{pathname}.gzf"
            self.project.saveAsPackedFile(program, File(str(gzf_file.absolute())), True)

        logger.info(f"Analysis for {df_or_prog.getName()} complete")
        self.programs[df.pathname].ghidra_analysis_complete = True
        return df_or_prog

    def set_analysis_option(  # noqa: C901
        self,
        prog: "Program",
        option_name: str,
        value: Any,
    ) -> None:
        """
        Set boolean program analysis options
        Inspired by: Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScript.java#L1272
        """
        from ghidra.program.model.listing import Program

        prog_options = prog.getOptions(Program.ANALYSIS_PROPERTIES)
        option_type = prog_options.getType(option_name)

        match str(option_type):
            case "INT_TYPE":
                logger.debug("Setting type: INT")
                prog_options.setInt(option_name, int(value))
            case "LONG_TYPE":
                logger.debug("Setting type: LONG")
                prog_options.setLong(option_name, int(value))
            case "STRING_TYPE":
                logger.debug("Setting type: STRING")
                prog_options.setString(option_name, value)
            case "DOUBLE_TYPE":
                logger.debug("Setting type: DOUBLE")
                prog_options.setDouble(option_name, float(value))
            case "FLOAT_TYPE":
                logger.debug("Setting type: FLOAT")
                prog_options.setFloat(option_name, float(value))
            case "BOOLEAN_TYPE":
                logger.debug("Setting type: BOOLEAN")
                if isinstance(value, str):
                    temp_bool = value.lower()
                    if temp_bool in {"true", "false"}:
                        prog_options.setBoolean(option_name, temp_bool == "true")
                elif isinstance(value, bool):
                    prog_options.setBoolean(option_name, value)
                else:
                    raise ValueError(f"Failed to setBoolean on {option_name} {option_type}")
            case "ENUM_TYPE":
                logger.debug("Setting type: ENUM")
                from java.lang import Enum  # type: ignore

                enum_for_option = prog_options.getEnum(option_name, None)
                if enum_for_option is None:
                    raise ValueError(
                        f"Attempted to set an Enum option {option_name} without an "
                        + "existing enum value alreday set."
                    )
                new_enum = None
                try:
                    new_enum = Enum.valueOf(enum_for_option.getClass(), value)
                except Exception:
                    for enum_value in enum_for_option.values():  # type: ignore
                        if value == enum_value.toString():
                            new_enum = enum_value
                            break
                if new_enum is None:
                    raise ValueError(
                        f"Attempted to set an Enum option {option_name} without an "
                        + "existing enum value alreday set."
                    )
                prog_options.setEnum(option_name, new_enum)
            case _:
                logger.warning(f"option {option_type} set not supported, ignoring")

    def configure_symbols(
        self,
        symbols_path: str | Path,
        symbol_urls: list[str] | None = None,
        allow_remote: bool = True,
    ):
        """
        Configures symbol servers and attempts to load PDBs for programs.
        """
        from ghidra.app.plugin.core.analysis import (
            PdbAnalyzer,  # type: ignore
            PdbUniversalAnalyzer,  # type: ignore
        )
        from ghidra.app.util.pdb import PdbProgramAttributes  # type: ignore

        logger.info("Configuring symbol search paths...")
        # This is a simplification. A real implementation would need to configure the symbol server
        # which is more involved. For now, we'll focus on enabling the analyzers.

        for program_name, program in self.programs.items():
            logger.info(f"Configuring symbols for {program_name}")
            try:
                if hasattr(PdbUniversalAnalyzer, "setAllowUntrustedOption"):  # Ghidra 11.2+
                    PdbUniversalAnalyzer.setAllowUntrustedOption(program, allow_remote)
                    PdbAnalyzer.setAllowUntrustedOption(program, allow_remote)
                else:  # Ghidra < 11.2
                    PdbUniversalAnalyzer.setAllowRemoteOption(program, allow_remote)
                    PdbAnalyzer.setAllowRemoteOption(program, allow_remote)

                # The following is a placeholder for actual symbol loading logic
                pdb_attr = PdbProgramAttributes(program)
                if not pdb_attr.pdbLoaded:
                    logger.warning(
                        f"PDB not loaded for {program_name}. Manual loading might be required."
                    )

            except Exception as e:
                logger.error(f"Failed to configure symbols for {program_name}: {e}")

    def apply_gdt(
        self,
        program: "Program",
        gdt_path: str | Path,
        verbose: bool = False,
    ):
        """
        Apply GDT to program
        """
        from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd
        from ghidra.program.model.data import FileDataTypeManager
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor
        from java.io import File  # type: ignore
        from java.util import List  # type: ignore

        gdt_path = Path(gdt_path)

        if verbose:
            monitor = ConsoleTaskMonitor()
        else:
            monitor = ConsoleTaskMonitor().DUMMY_MONITOR

        archive_gdt = File(str(gdt_path))
        archive_dtm = FileDataTypeManager.openFileArchive(archive_gdt, False)
        always_replace = True
        create_bookmarks_enabled = True
        cmd = ApplyFunctionDataTypesCmd(
            List.of(archive_dtm),
            None,  # type: ignore
            SourceType.USER_DEFINED,
            always_replace,
            create_bookmarks_enabled,
        )
        cmd.applyTo(program, monitor)

    def get_metadata(self, prog: "Program") -> dict:
        """
        Generate dict from program metadata
        """
        meta = prog.getMetadata()
        return dict(meta)

    def setup_decompiler(self, program: "Program"):
        from ghidra.app.decompiler import DecompileOptions, DecompInterface

        prog_options = DecompileOptions()

        decomp = DecompInterface()

        # grab default options from program
        prog_options.grabFromProgram(program)

        # increase maxpayload size to 100MB (default 50MB)
        prog_options.setMaxPayloadMBytes(100)

        decomp.setOptions(prog_options)
        decomp.openProgram(program)

        return decomp

    def _create_decompiler_pool(self, program: "Program") -> DecompilerPool:
        pool_size = 2 if self.threaded else 1
        return DecompilerPool(lambda: self.setup_decompiler(program), size=pool_size)

    @staticmethod
    def _dispose_decompiler(program_info: ProgramInfo) -> None:
        try:
            program_info.decompiler_pool.dispose()
        except Exception:
            logger.debug("Failed to dispose decompiler pool", exc_info=True)
