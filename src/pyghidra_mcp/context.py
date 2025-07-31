import logging
from contextlib import contextmanager
from os import name
from pathlib import Path
from typing import List, Optional, Union, Dict, TYPE_CHECKING
import concurrent.futures
import time
import random
import multiprocessing
from dataclasses import dataclass, field

# Ghidra imports
# from ghidra.app.util.importer import MessageLog
# from ghidra.base.project import GhidraProject
#
# from ghidra.program.model.listing import Program
# from ghidra.util.exception import NotFoundException
# from java.io import IOException

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# if TYPE_CHECKING:
#     import ghidra
#     from ghidra_builtins import *
#     from ghidra import *


@dataclass
class ProgramInfo:
    """Information about a loaded program"""

    name: str
    program: "ghidra.program.model.listing.Program"
    flat_api: Optional["ghidra.program.flatapi.FlatProgramAPI"]
    decompiler: "ghidra.app.decompiler.DecompInterface"
    metadata: dict  # Ghidra program metadata
    file_path: Optional[Path] = None
    load_time: Optional[float] = None
    analysis_complete: bool = False

    # def __post_init__(self):
    #     if self.file_path and isinstance(self.file_path, str):
    #         self.file_path = Path(self.file_path)


class PyGhidraContext:
    """
    Manages a Ghidra project, including its creation, program imports, and cleanup.
    """

    def __init__(self,
                 project_name: str,
                 project_path: Union[str, Path],
                 force_analysis: bool = False,
                 verbose_analysis: bool = False,
                 no_symbols: bool = False,
                 gdts: list = [],
                 program_options: dict = None,
                 gzfs_path: Union[str, Path] = None,
                 threaded: bool = True,
                 max_workers: int = multiprocessing.cpu_count()):
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
        self.project: "ghidra.base.project.GhidraProject" = self._get_or_create_project()
        self.programs: Dict[str, ProgramInfo] = {}

        # From GhidraDiffEngine
        self.force_analysis = force_analysis
        self.verbose_analysis = verbose_analysis
        self.no_symbols = no_symbols
        self.gdts = gdts
        self.program_options = program_options
        self.gzfs_path = Path(gzfs_path) if gzfs_path else None
        if self.gzfs_path:
            self.gzfs_path.mkdir(exist_ok=True, parents=True)

        self.threaded = threaded
        self.max_workers = max_workers
        if not self.threaded:
            logger.warn('--no-threaded flag forcing max_workers to 1')
            self.max_workers = 1

    def _get_or_create_project(self) -> "ghidra.framework.model.GhidraProject":
        """
        Creates a new Ghidra project if it doesn't exist, otherwise opens the existing project.

        Returns:
            The Ghidra project object.
        """

        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator
        from java.io import IOException
        from ghidra.util.exception import NotFoundException

        project_dir = self.project_path / self.project_name
        project_dir.mkdir(exist_ok=True, parents=True)

        locator = ProjectLocator(project_dir, self.project_name)

        if locator.exists():
            logger.info(f"Opening existing project: {self.project_name}")
            return GhidraProject.openProject(project_dir, self.project_name, True)
        else:
            logger.info(f"Creating new project: {self.project_name}")
            return GhidraProject.createProject(project_dir, self.project_name, False)

    def _init_program_info(self, program, binary_path):

        from ghidra.program.flatapi import FlatProgramAPI
        from .decompile import setup_decomplier

        assert program is not None

        import time
        program_info = ProgramInfo(
            name=program.name,
            program=program,
            flat_api=FlatProgramAPI(program),
            decompiler=setup_decomplier(program),
            metadata=self.get_metadata(program),
            file_path=binary_path,
            load_time=time.time(),
            analysis_complete=False
        )

        return program_info

    def import_binaries(self, binary_paths: List[Union[str, Path]]):
        """
        Imports and optionally analyzes a list of binaries into the project.

        Args:
            binary_paths: A list of paths to the binary files.
        """
        for bin_path in binary_paths:
            self.import_binary(bin_path)

    def import_binary(self, binary_path: Union[str, Path]) -> "ghidra.program.model.listing.Program":
        """
        Imports a single binary into the project.

        Args:
            binary_path: Path to the binary file.

        Returns:
            None
        """

        binary_path = Path(binary_path)
        program_name = binary_path.name

        root_folder = self.project.getRootFolder()
        program: "ghidra.program.model.listing.Program" = None

        if root_folder.getFile(program_name):
            logger.info(f"Opening existing program: {program_name}")
            program = self.project.openProgram("/", program_name, False)
        else:
            logger.info(f"Importing new program: {program_name}")
            program = self.project.importProgram(binary_path)
            if program:
                self.project.saveAs(program, "/", program_name, True)
            else:
                raise ImportError(f"Failed to import binary: {binary_path}")

        if program:
            self.programs[program_name] = self._init_program_info(
                program, binary_path)

    def configure_symbols(self, symbols_path: Union[str, Path], symbol_urls: List[str] = None, allow_remote: bool = True):
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
                if hasattr(PdbUniversalAnalyzer, 'setAllowUntrustedOption'):  # Ghidra 11.2+
                    PdbUniversalAnalyzer.setAllowUntrustedOption(
                        program, allow_remote)
                    PdbAnalyzer.setAllowUntrustedOption(program, allow_remote)
                else:  # Ghidra < 11.2
                    PdbUniversalAnalyzer.setAllowRemoteOption(
                        program, allow_remote)
                    PdbAnalyzer.setAllowRemoteOption(program, allow_remote)

                # The following is a placeholder for actual symbol loading logic
                pdb_attr = PdbProgramAttributes(program)
                if not pdb_attr.pdbLoaded:
                    logger.warning(
                        f"PDB not loaded for {program_name}. Manual loading might be required.")

            except Exception as e:
                logger.error(
                    f"Failed to configure symbols for {program_name}: {e}")

    def list_binaries(self) -> List[str]:
        """List all the binaries within the project."""
        return [f.getName() for f in self.project.getRootFolder().getFiles()]

    def close(self, save: bool = True):
        """
        Saves changes to all open programs and closes the project.
        """
        for program_name, program_info in self.programs.items():
            program = program_info.program
            self.project.close(program)

        self.project.close()
        logger.info(f"Project {self.project_name} closed.")

    def get_metadata(
        self,
        prog: "ghidra.program.model.listing.Program"
    ) -> dict:
        """
        Generate dict from program metadata
        """
        meta = prog.getMetadata()
        return dict(meta)

    def apply_gdt(self, program: "ghidra.program.model.listing.Program", gdt_path:  Union[str, Path], verbose: bool = False):
        """
        Apply GDT to program
        """
        from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd
        from ghidra.program.model.symbol import SourceType
        from java.io import File
        from java.util import List
        from ghidra.program.model.data import FileDataTypeManager
        from ghidra.util.task import ConsoleTaskMonitor

        gdt_path = Path(gdt_path)

        if verbose:
            print('Enabling verbose gdt..')
            monitor = ConsoleTaskMonitor()
        else:
            monitor = ConsoleTaskMonitor().DUMMY_MONITOR

        archiveGDT = File(str(gdt_path))
        archiveDTM = FileDataTypeManager.openFileArchive(archiveGDT, False)
        always_replace = True
        createBookmarksEnabled = True
        cmd = ApplyFunctionDataTypesCmd(List.of(archiveDTM), None, SourceType.USER_DEFINED,
                                        always_replace, createBookmarksEnabled)
        cmd.applyTo(program, monitor)

    def set_analysis_option(
        self,
        prog: "ghidra.program.model.listing.Program",
        option_name: str,
        value: bool
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
                logger.debug(f'Setting type: INT')
                prog_options.setInt(option_name, int(value))
            case "LONG_TYPE":
                logger.debug(f'Setting type: LONG')
                prog_options.setLong(option_name, int(value))
            case "STRING_TYPE":
                logger.debug(f'Setting type: STRING')
                prog_options.setString(option_name, value)
            case "DOUBLE_TYPE":
                logger.debug(f'Setting type: DOUBLE')
                prog_options.setDouble(option_name, float(value))
            case "FLOAT_TYPE":
                logger.debug(f'Setting type: FLOAT')
                prog_options.setFloat(option_name, float(value))
            case "BOOLEAN_TYPE":
                logger.debug(f'Setting type: BOOLEAN')
                if isinstance(value, str):
                    temp_bool = value.lower()
                    if temp_bool in {"true", "false"}:
                        prog_options.setBoolean(
                            option_name, temp_bool == "true")
                elif isinstance(value, bool):
                    prog_options.setBoolean(option_name, value)
                else:
                    raise ValueError(
                        f"Failed to setBoolean on {option_name} {option_type}")
            case "ENUM_TYPE":
                logger.debug(f'Setting type: ENUM')
                from java.lang import Enum
                enum_for_option = prog_options.getEnum(option_name, None)
                if enum_for_option is None:
                    raise ValueError(
                        f"Attempted to set an Enum option {option_name} without an " + "existing enum value alreday set.")
                new_enum = None
                try:
                    new_enum = Enum.valueOf(enum_for_option.getClass(), value)
                except:
                    for enumValue in enum_for_option.values():
                        if value == enumValue.toString():
                            new_enum = enumValue
                            break
                if new_enum is None:
                    raise ValueError(
                        f"Attempted to set an Enum option {option_name} without an " + "existing enum value alreday set.")
                prog_options.setEnum(option_name, new_enum)
            case _:
                logger.warning(
                    f'option {option_type} set not supported, ignoring')

    def analyze_program(self, df_or_prog: Union["ghidra.framework.model.DomainFile", "ghidra.program.model.listing.Program"], require_symbols: bool, force_analysis: bool = False, verbose_analysis: bool = False):
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.framework.model import DomainFile
        from ghidra.program.model.listing import Program
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.app.util.pdb import PdbProgramAttributes

        program_was_opened = False
        if isinstance(df_or_prog, DomainFile):
            if self.programs.get(df_or_prog.name):
                program = self.programs[df_or_prog.name].program
            else:
                program = self.project.openProgram(
                    "/", df_or_prog.getName(), False)
                self.programs[df_or_prog.name] = self._init_program_info(
                    program, program.name)

        elif isinstance(df_or_prog, Program):
            program = df_or_prog
        else:
            raise TypeError(
                f"Unsupported type for analysis: {type(df_or_prog)}")

        logger.info(f"Analyzing: {program}")

        for gdt in self.gdts:
            logger.info(f"Loading GDT: {gdt}")
            if not Path(gdt).exists():
                raise FileNotFoundError(f'GDT Path not found {gdt}')
            self.apply_gdt(program, gdt)

        gdt_names = [
            name for name in program.getDataTypeManager().getSourceArchives()]
        if len(gdt_names) > 0:
            print(f'Using file gdts: {gdt_names}')

        try:
            if verbose_analysis or self.verbose_analysis:
                monitor = ConsoleTaskMonitor()
                flat_api = FlatProgramAPI(program, monitor)
            else:
                flat_api = FlatProgramAPI(program)

            pdb_attr = PdbProgramAttributes(program)
            force_reload_for_symbols = False

            if force_reload_for_symbols:
                self.set_analysis_option(program, 'PDB Universal', True)
                logger.info(
                    'Symbols missing. Re-analysis is required. Setting PDB Universal: True')
                logger.debug(
                    f'pdb loaded: {pdb_attr.isPdbLoaded()} prog analyzed: {pdb_attr.isProgramAnalyzed()}')

            if GhidraProgramUtilities.shouldAskToAnalyze(program) or force_analysis or self.force_analysis or force_reload_for_symbols:
                GhidraScriptUtil.acquireBundleHostReference()

                if program and program.getFunctionManager().getFunctionCount() > 1000:
                    if self.program_options is not None and self.program_options.get('program_options', {}).get('Analyzers', {}).get('Shared Return Calls.Assume Contiguous Functions Only') is None:
                        logger.warn(
                            f"Turning off 'Shared Return Calls' for {program}")
                        self.set_analysis_option(
                            program, 'Shared Return Calls.Assume Contiguous Functions Only', False)

                if self.program_options is not None and self.program_options.get('program_options', {}).get('Analyzers', {}).get('Decompiler Parameter ID') is None:
                    self.set_analysis_option(
                        program, 'Decompiler Parameter ID', True)

                if self.program_options:
                    analyzer_options = self.program_options.get(
                        'program_options', {}).get('Analyzers', {})
                    for k, v in analyzer_options.items():
                        logger.info(f"Setting prog option:{k} with value:{v}")
                        self.set_analysis_option(program, k, v)

                if self.no_symbols:
                    logger.warn(
                        f'Disabling symbols for analysis! --no-symbols flag: {self.no_symbols}')
                    self.set_analysis_option(program, 'PDB Universal', False)

                logger.info(f'Starting Ghidra analysis of {program}...')
                try:
                    sleep_duration = random.uniform(3, 7)
                    time.sleep(sleep_duration)
                    flat_api.analyzeAll(program)
                    if hasattr(GhidraProgramUtilities, 'setAnalyzedFlag'):
                        GhidraProgramUtilities.setAnalyzedFlag(program, True)
                    elif hasattr(GhidraProgramUtilities, 'markProgramAnalyzed'):
                        GhidraProgramUtilities.markProgramAnalyzed(program)
                    else:
                        raise Exception('Missing set analyzed flag method!')
                finally:
                    GhidraScriptUtil.releaseBundleHostReference()
                    self.project.save(program)
            else:
                logger.info(f"Analysis already complete.. skipping {program}!")
        finally:
            if self.gzfs_path is not None:
                from java.io import File
                gzf_file = self.gzfs_path / \
                    f"{program.getDomainFile().getName()}.gzf"
                self.project.saveAsPackedFile(
                    program, File(str(gzf_file.absolute())), True)

        logger.info(f"Analysis for {df_or_prog.getName()} complete")
        return df_or_prog

    def analyze_project(self, require_symbols: bool = True, force_analysis: bool = False, verbose_analysis: bool = False) -> None:
        """
        Analyzes all files found within the project
        """
        logger.info(
            f'Starting analysis for {len(self.project.getRootFolder().getFiles())} binaries')

        domain_files = [domainFile for domainFile in self.project.getRootFolder().getFiles()
                        if domainFile.getContentType() == 'Program']

        prog_count = len(domain_files)
        completed_count = 0

        if self.threaded and self.max_workers > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(self.analyze_program, domainFile, require_symbols,
                                           force_analysis, verbose_analysis): domainFile for domainFile in domain_files}
                for future in concurrent.futures.as_completed(futures):
                    completed_count += 1
                    logger.info(
                        f"Analysis % complete: {round(completed_count/prog_count, 2)*100}")
                    try:
                        program = future.result()
                        self.programs[program.name].analysis_complete = True
                    except Exception as exc:
                        logger.error(
                            f'{futures[future].getName()} generated an exception: {exc}')
        else:
            for domainFile in domain_files:
                self.analyze_program(
                    domainFile, require_symbols, force_analysis, verbose_analysis)
