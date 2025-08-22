import concurrent.futures
import hashlib
import logging
import multiprocessing
import time
import typing
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

import chromadb
from chromadb.config import Settings

from pyghidra_mcp.tools import GhidraTools

if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *  # noqa: F403

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ProgramInfo:
    """Information about a loaded program"""

    name: str
    program: "ghidra.program.model.listing.Program"
    flat_api: Optional["ghidra.program.flatapi.FlatProgramAPI"]
    decompiler: "ghidra.app.decompiler.DecompInterface"
    metadata: dict  # Ghidra program metadata
    file_path: Path | None = None
    load_time: float | None = None
    analysis_complete: bool = False
    collection: chromadb.Collection | None = None
    strings_collection: chromadb.Collection | None = None


class PyGhidraContext:
    """
    Manages a Ghidra project, including its creation, program imports, and cleanup.
    """

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
        max_workers: int = multiprocessing.cpu_count(),
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
        """
        self.project_name = project_name
        self.project_path = Path(project_path)
        self.project: ghidra.base.project.GhidraProject = self._get_or_create_project()
        self.programs: dict[str, ProgramInfo] = {}

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
        self.max_workers = max_workers
        if not self.threaded:
            logger.warn("--no-threaded flag forcing max_workers to 1")
            self.max_workers = 1

    def close(self, save: bool = True):
        """
        Saves changes to all open programs and closes the project.
        """
        for _program_name, program_info in self.programs.items():
            program = program_info.program
            self.project.close(program)

        self.project.close()
        logger.info(f"Project {self.project_name} closed.")

    def _get_or_create_project(self) -> "ghidra.framework.model.GhidraProject":
        """
        Creates a new Ghidra project if it doesn't exist, otherwise opens the existing project.

        Returns:
            The Ghidra project object.
        """

        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        project_dir = self.project_path / self.project_name
        project_dir.mkdir(exist_ok=True, parents=True)

        locator = ProjectLocator(project_dir, self.project_name)

        if locator.exists():
            logger.info(f"Opening existing project: {self.project_name}")
            return GhidraProject.openProject(project_dir, self.project_name, True)
        else:
            logger.info(f"Creating new project: {self.project_name}")
            return GhidraProject.createProject(project_dir, self.project_name, False)

    def list_binaries(self) -> list[str]:
        """List all the binaries within the Ghidra project."""
        return [f.getName() for f in self.project.getRootFolder().getFiles()]

    def import_binary(self, binary_path: str | Path) -> "ghidra.program.model.listing.Program":
        """
        Imports a single binary into the project.

        Args:
            binary_path: Path to the binary file.

        Returns:
            None
        """

        binary_path = Path(binary_path)
        program_name = PyGhidraContext._gen_unique_bin_name(binary_path)

        root_folder = self.project.getRootFolder()
        program: ghidra.program.model.listing.Program = None

        if root_folder.getFile(program_name):
            logger.info(f"Opening existing program: {program_name}")
            program = self.project.openProgram("/", program_name, False)
        else:
            logger.info(f"Importing new program: {program_name}")
            program = self.project.importProgram(binary_path)
            program.name = program_name
            if program:
                self.project.saveAs(program, "/", program_name, True)
            else:
                raise ImportError(f"Failed to import binary: {binary_path}")

        if program:
            self.programs[program_name] = self._init_program_info(program)

    def import_binaries(self, binary_paths: list[str | Path]):
        """
        Imports a list of binaries into the project.

        Args:
            binary_paths: A list of paths to the binary files.
        """
        for bin_path in binary_paths:
            self.import_binary(bin_path)

    def get_program_info(self, binary_name: str) -> "ProgramInfo":
        """Get program info or raise ValueError if not found."""
        program_info = self.programs.get(binary_name)
        if not program_info:
            available_progs = list(self.programs.keys())
            raise ValueError(
                f"Binary {binary_name} not found. Available binaries: {available_progs}"
            )
        return program_info

    def _init_program_info(self, program):
        from ghidra.program.flatapi import FlatProgramAPI

        assert program is not None

        metadata = self.get_metadata(program)

        program_info = ProgramInfo(
            name=program.name,
            program=program,
            flat_api=FlatProgramAPI(program),
            decompiler=self.setup_decompiler(program),
            metadata=metadata,
            file_path=metadata["Executable Location"],
            load_time=time.time(),
            analysis_complete=False,
            collection=None,
        )

        return program_info

    @staticmethod
    def _gen_unique_bin_name(path: str | Path):
        """
        Generate unique program name from binary for Ghidra Project
        """

        path = Path(path)

        def _sha1_file(path: str) -> str:
            sha1 = hashlib.sha1()

            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha1.update(chunk)

            return sha1.hexdigest()

        return "-".join((path.name, _sha1_file(path.absolute())[:6]))

    def _init_chroma_code_collections(self):
        """
        Initialize per-program Chroma collections and ingest decompiled functions.

        For each ProgramInfo in self.programs:
        - Attempts to get an existing Chroma collection by program name. If found, assigns it
        to program_info.collection and skips ingestion (idempotent on re-runs).
        - If not found, creates a new collection, decompiles all functions via GhidraTools,
        and adds each functions decompiled code as a document with metadata:
        {"function_name": <name>, "entry_point": <address>}, using the function name as the ID.
        """

        logger.info("Creating chromadb collections...")
        for program_info in self.programs.values():
            logger.info(f"Creating collection for {program_info.name}")

            # Prefer an explicit existence check over get_or_create
            try:
                # If this succeeds, the collection already exists — skip ingest
                collection = self.chroma_client.get_collection(name=program_info.name)
                logger.info(f"Collection '{program_info.name}' exists; skipping ingest.")
                program_info.collection = collection
                continue
            except Exception:
                # Not found — create and ingest
                collection = self.chroma_client.create_collection(name=program_info.name)
                logger.info(f"Created new collection '{program_info.name}'")

            tools = GhidraTools(program_info)
            functions = tools.get_all_functions()
            for func in functions:
                try:
                    decompiled = tools.decompile_function(func.name)
                    if decompiled and decompiled.code:
                        collection.add(
                            documents=[decompiled.code],
                            metadatas=[
                                {
                                    "function_name": func.name,
                                    "entry_point": str(func.getEntryPoint()),
                                }
                            ],
                            ids=[func.name],
                        )
                except Exception as e:
                    logger.error(
                        f"Failed to decompile or add function {func.name} to collection: {e}"
                    )
            program_info.collection = collection

    def _init_chroma_strings_collections(self):
        """
        Initialize per-program Chroma collections and ingest strings.
        """
        logger.info("Creating chromadb strings collections...")
        for program_info in self.programs.values():
            collection_name = f"{program_info.name}_strings"
            logger.info(f"Creating or getting strings collection for {program_info.name}")

            try:
                collection = self.chroma_client.get_collection(name=collection_name)
                logger.info(f"Collection '{program_info.name}_strings' exists; skipping ingest.")
                program_info.strings_collection = collection
                continue
            except Exception:
                collection = self.chroma_client.create_collection(name=collection_name)
                logger.info(f"Created new collection '{program_info.name}_strings'")

            tools = GhidraTools(program_info)
            strings = tools.get_all_strings()
            for s in strings:
                try:
                    collection.add(
                        documents=[s.value],
                        metadatas=[
                            {
                                "address": str(s.address),
                            }
                        ],
                        ids=[str(s.address)],
                    )
                except Exception as e:
                    logger.error(
                        f"Failed to add string {s.value} at {s.address} to collection: {e}"
                    )
            program_info.strings_collection = collection

    def analyze_project(
        self,
        require_symbols: bool = True,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
    ) -> None:
        """
        Analyzes all files found within the Ghidra project
        """
        logger.info(
            f"Starting analysis for {len(self.project.getRootFolder().getFiles())} binaries"
        )

        domain_files = [
            domainFile
            for domainFile in self.project.getRootFolder().getFiles()
            if domainFile.getContentType() == "Program"
        ]

        prog_count = len(domain_files)
        completed_count = 0

        if self.threaded and self.max_workers > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(
                        self.analyze_program,
                        domainFile,
                        require_symbols,
                        force_analysis,
                        verbose_analysis,
                    ): domainFile
                    for domainFile in domain_files
                }
                for future in concurrent.futures.as_completed(futures):
                    completed_count += 1
                    logger.info(
                        f"Analysis % complete: {round(completed_count / prog_count, 2) * 100}"
                    )
                    try:
                        program = future.result()
                        self.programs[program.name].analysis_complete = True
                    except Exception as exc:
                        logger.error(f"{futures[future].getName()} generated an exception: {exc}")
                        raise exc
        else:
            for domain_file in domain_files:
                self.analyze_program(domain_file, require_symbols, force_analysis, verbose_analysis)

        logger.info("Ghidra Program Analysis complete")
        self._init_chroma_code_collections()
        self._init_chroma_strings_collections()

    def analyze_program(  # noqa: C901
        self,
        df_or_prog: Union[
            "ghidra.framework.model.DomainFile", "ghidra.program.model.listing.Program"
        ],
        require_symbols: bool,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
    ):
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.listing import Program
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.util.task import ConsoleTaskMonitor

        if self.programs.get(df_or_prog.name):
            # program already opened and intialized
            program = self.programs[df_or_prog.name].program
        else:
            # open program from Ghidra Project
            program = self.project.openProgram("/", df_or_prog.getName(), False)
            self.programs[df_or_prog.name] = self._init_program_info(program)

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

        try:
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
        finally:
            if self.gzfs_path is not None:
                from java.io import File

                gzf_file = self.gzfs_path / f"{program.getDomainFile().getName()}.gzf"
                self.project.saveAsPackedFile(program, File(str(gzf_file.absolute())), True)

        logger.info(f"Analysis for {df_or_prog.getName()} complete")
        return df_or_prog

    def set_analysis_option(  # noqa: C901
        self,
        prog: "ghidra.program.model.listing.Program",
        option_name: str,
        value: bool,
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
                from java.lang import Enum

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
                    for enum_value in enum_for_option.values():
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
        from ghidra.app.plugin.core.analysis import PdbAnalyzer, PdbUniversalAnalyzer
        from ghidra.app.util.pdb import PdbProgramAttributes

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
        program: "ghidra.program.model.listing.Program",
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
        from java.io import File
        from java.util import List

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
            None,
            SourceType.USER_DEFINED,
            always_replace,
            create_bookmarks_enabled,
        )
        cmd.applyTo(program, monitor)

    def get_metadata(self, prog: "ghidra.program.model.listing.Program") -> dict:
        """
        Generate dict from program metadata
        """
        meta = prog.getMetadata()
        return dict(meta)

    def setup_decompiler(
        self, program: "ghidra.program.model.listing.Program"
    ) -> "ghidra.app.decompiler.DecompInterface":
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
