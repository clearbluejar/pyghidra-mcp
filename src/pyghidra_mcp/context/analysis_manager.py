"""Analysis and vectorization management for Ghidra context."""

import concurrent.futures
import logging
from typing import TYPE_CHECKING, Any, Union

from pyghidra_mcp.context.models import ProgramInfo
from pyghidra_mcp.context.project_manager import ProjectManager
from pyghidra_mcp.tools import GhidraTools

if TYPE_CHECKING:
    from ghidra.framework.model import DomainFile
    from ghidra.program.model.listing import Program


# Configure logging
logger = logging.getLogger(__name__)


class AnalysisManager:
    """Manages program analysis, decompiler setup, and ChromaDB vectorization."""

    def __init__(self, project_manager: ProjectManager):
        """
        Initialize AnalysisManager with reference to ProjectManager.

        Args:
            project_manager: The ProjectManager instance to coordinate with.
        """
        self.project_manager = project_manager
        self.project = project_manager.project
        self.executor = project_manager.executor
        self.chroma_client = project_manager.chroma_client

    def analyze_program(  # noqa C901
        self,
        df_or_prog: Union["DomainFile", "Program"],
        require_symbols: bool = True,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
    ):
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.framework.model import DomainFile
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.listing import Program
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.util.task import ConsoleTaskMonitor

        df = df_or_prog
        if not isinstance(df_or_prog, DomainFile):
            df = df_or_prog.getDomainFile()

        if self.project_manager.programs.get(df.pathname):
            # program already opened and initialized
            program = self.project_manager.programs[df.pathname].program
        else:
            # open program from Ghidra Project
            program = self.project.openProgram(df.getParent().pathname, df_or_prog.getName(), False)
            self.project_manager.programs[df.pathname] = self.project_manager._init_program_info(
                program
            )

        assert isinstance(program, Program)

        logger.info(f"Analyzing: {program}")

        for gdt in self.project_manager.gdts:
            logger.info(f"Loading GDT: {gdt}")
            from pathlib import Path

            if not Path(gdt).exists():
                raise FileNotFoundError(f"GDT Path not found {gdt}")
            self.apply_gdt(program, gdt)

        gdt_names = [name for name in program.getDataTypeManager().getSourceArchives()]
        if len(gdt_names) > 0:
            logger.debug(f"Using file gdts: {gdt_names}")

        if verbose_analysis or self.project_manager.verbose_analysis:
            monitor = ConsoleTaskMonitor()
            flat_api = FlatProgramAPI(program, monitor)
        else:
            flat_api = FlatProgramAPI(program)

        if (
            GhidraProgramUtilities.shouldAskToAnalyze(program)
            or force_analysis
            or self.project_manager.force_analysis
        ):
            GhidraScriptUtil.acquireBundleHostReference()

            if program and program.getFunctionManager().getFunctionCount() > 1000:
                # Force Decomp Param ID is not set
                if (
                    self.project_manager.program_options is not None
                    and self.project_manager.program_options.get("program_options", {})
                    .get("Analyzers", {})
                    .get("Decompiler Parameter ID")
                    is None
                ):
                    self.set_analysis_option(program, "Decompiler Parameter ID", True)

            if self.project_manager.program_options:
                analyzer_options = self.project_manager.program_options.get(
                    "program_options", {}
                ).get("Analyzers", {})
                for k, v in analyzer_options.items():
                    logger.info(f"Setting prog option:{k} with value:{v}")
                    self.set_analysis_option(program, k, v)

            if self.project_manager.no_symbols:
                logger.warning(
                    f"Disabling symbols for analysis! --no-symbols flag: {self.project_manager.no_symbols}"
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

        # Save program as gzfs
        if self.project_manager.gzfs_path is not None:
            from pathlib import Path

            from java.io import File  # type: ignore

            pathname = df.pathname.replace("/", "_")
            gzf_file = self.project_manager.gzfs_path / f"{pathname}.gzf"
            self.project.saveAsPackedFile(program, File(str(gzf_file.absolute())), True)

        logger.info(f"Analysis for {df_or_prog.getName()} complete")

        # Set up decompiler now that analysis is complete
        program_info = self.project_manager.programs[df.pathname]
        if program_info._decompiler is None:
            from pyghidra_mcp.tools import setup_decompiler

            program_info._decompiler = setup_decompiler(program)

        self.project_manager.programs[df.pathname].ghidra_analysis_complete = True
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
        symbols_path,
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

        for program_name, program in self.project_manager.programs.items():
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
        gdt_path,
        verbose: bool = False,
    ):
        """
        Apply GDT to program
        """
        from pathlib import Path

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



    def _init_chroma_code_collection_for_program(self, program_info: ProgramInfo):
        """
        Initialize Chroma code collection for a single program.
        """
        from ghidra.program.model.listing import Function

        logger.info(f"Initializing Chroma code collection for {program_info.name}")
        try:
            collection = self.chroma_client.get_collection(name=program_info.name)
            logger.info(f"Collection '{program_info.name}' exists; skipping code ingest.")
            program_info.code_collection = collection
        except Exception:
            logger.info(f"Creating new code collection '{program_info.name}'")
            tools = GhidraTools(program_info)
            functions = tools.get_all_functions()
            decompiles = []
            ids = []
            metadatas = []

            for i, func in enumerate(functions):
                func: Function
                try:
                    if i % 10 == 0:
                        logger.debug(f"Decompiling {i}/{len(functions)}")
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
                    logger.error(f"Failed to decompile {func.getSymbol().getName(True)}: {e}")

            collection = self.chroma_client.create_collection(name=program_info.name)
            try:
                collection.add(
                    documents=decompiles,
                    metadatas=metadatas,
                    ids=ids,
                )
            except Exception as e:
                logger.error(f"Failed add decompiles to collection: {e}")

            logger.info(f"Code analysis complete for collection '{program_info.name}'")
            program_info.code_collection = collection

    def _init_chroma_strings_collection_for_program(self, program_info: ProgramInfo):
        """
        Initialize Chroma strings collection for a single program.
        """
        collection_name = f"{program_info.name}_strings"
        logger.info(f"Initializing Chroma strings collection for {program_info.name}")
        try:
            strings_collection = self.chroma_client.get_collection(name=collection_name)
            logger.info(f"Collection '{collection_name}' exists; skipping strings ingest.")
            program_info.strings_collection = strings_collection
        except Exception:
            logger.info(f"Creating new strings collection '{collection_name}'")
            tools = GhidraTools(program_info)

            ids = []
            strings = tools.get_all_strings()
            metadatas = [{"address": str(s.address)} for s in strings]
            ids = [str(s.address) for s in strings]
            strings = [s.value for s in strings]

            strings_collection = self.chroma_client.create_collection(name=collection_name)
            try:
                strings_collection.add(
                    documents=strings,
                    metadatas=metadatas,  # type: ignore
                    ids=ids,
                )
            except Exception as e:
                logger.error(f"Failed to add strings to collection: {e}")

            logger.info(f"Strings analysis complete for collection '{collection_name}'")
            program_info.strings_collection = strings_collection

    def _init_chroma_collections_for_program(self, program_info: ProgramInfo):
        """
        Initializes all Chroma collections (code and strings) for a single program.
        """
        self._init_chroma_code_collection_for_program(program_info)
        self._init_chroma_strings_collection_for_program(program_info)

    def _init_all_chroma_collections(self):
        """
        Initializes Chroma collections for all programs in the project.
        If an executor is available, tasks are submitted asynchronously.
        Otherwise, initialization runs in the main thread.
        """
        programs = list(self.project_manager.programs.values())
        mode = "background" if self.executor else "main thread"
        logger.info("Initializing Chroma DB collections in %s...", mode)

        # ensure analysis complete before init
        assert all(prog.analysis_complete for prog in programs)

        if self.executor:
            # executor.map submits all tasks at once, returns an iterator of futures
            self.executor.map(self._init_chroma_collections_for_program, programs)
        else:
            for program_info in programs:
                self._init_chroma_collections_for_program(program_info)

    def _analysis_done_callback(self, future: concurrent.futures.Future):
        try:
            future.result()
            logging.info("Asynchronous analysis finished successfully.")
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

            if self.project_manager.wait_for_analysis:
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
        domain_files = self.project_manager.list_binary_domain_files()

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
        # The chroma collections need to be initialized after analysis is complete
        # At this point, threaded or not, all analysis is done
        self._init_all_chroma_collections()  # DO NOT MOVE
