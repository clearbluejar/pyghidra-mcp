import logging
from contextlib import contextmanager
from pathlib import Path
from typing import List

from ghidra.app.util.importer import MessageLog
from ghidra.framework.model import Project, Tool, ToolListener
from ghidra.framework.project import ProjectManager
from ghidra.program.model.listing import Program
from ghidra.util import SystemUtilities

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PyGhidraContext:
    """
    Manages a Ghidra project, including its creation, program imports, and cleanup.
    """

    def __init__(self, project_name: str, project_path: Path, bin_paths: List[Path]):
        """
        Initializes a new Ghidra project context.

        Args:
            project_name: The name of the Ghidra project.
            project_path: The directory where the project will be created.
        """
        from ghidra.base.project import GhidraProject

        self.project_name = project_name
        self.project_path = project_path
        self.project: GhidraProject = self._get_or_create_project()
        self.binaries: List[Program] = self._import_binaries(bin_paths)

    def _import_binaries(self, bin_paths: List[Path]) -> None:
        for bin_path in binaries:
            self.add_binary(bin_path)

    def add_binary(self, bin_path: Path) -> None:
        """ Import and analyze a binary the binary.
        Add it to the current project
        """
        pass

    def list_binaries(self)
    """List all the binaries within the project"""
    pass

    def _get_or_create_project(self) -> "GhidraProject":
        """
        Creates a new Ghidra project if it doesn't exist, otherwise opens the existing project.

        Returns:
            The Ghidra project object.
        """

        from ghidra.base.project import GhidraProject
        # from java.lang import ClassLoader  # type:ignore @UnresolvedImport
        from ghidra.framework.model import ProjectLocator  # type:ignore @UnresolvedImport

        if ProjectLocator(self.project_path, self.project_name).exists():
            project = GhidraProject.openProject(
                self.project_path, self.project_name, True)
        else:
            project_location.mkdir(exist_ok=True, parents=True)
            project = GhidraProject.createProject(
                self.project_path, self.project_name, False)

        return project

    def close(self):
        """
        Saves changes to all open programs and closes the project.
        """
        for program in self.open_programs:
            if program.isChanged():
                program.save("Changes made by PyGhidra", None)
        self.project.close()

    @contextmanager
    def open_context(project_name: str, project_path: Path):
        """
        Context manager for creating and managing a Ghidra project.
        """
        context = PyGhidraContext(project_name, project_path)
        try:
            yield context
        finally:
            context.close()


def setup_project(
        self,
        binary_paths: List[Union[str, Path]],
        project_location: Union[str, Path],
        project_name: str,
        symbols_path: Union[str, Path],
        gzfs_path: Union[str, Path] = None,
        symbol_urls: list = None,

) -> list:
    """
    Setup and verify Ghidra Project
    1. Creat / Open Project
    2. Import / Open Binaries
    3. Configure and verify symbols
    """
    from ghidra.base.project import GhidraProject
    from ghidra.util.exception import NotFoundException
    from java.io import IOException
    from ghidra.app.plugin.core.analysis import PdbAnalyzer
    from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer

    project_location = Path(project_location) / project_name
    project_location.mkdir(exist_ok=True, parents=True)

    if gzfs_path is not None:
        gzfs_path = Path(gzfs_path)
        gzfs_path.mkdir(exist_ok=True, parents=True)
    self.gzfs_path = gzfs_path

    pdb = None

    self.logger.info(f'Setting Up Ghidra Project...')

    # Open/Create project
    project = None

    if self.project is not None:
        self.logger.warning(
            "Project Already Open! Closing project and saving")
        self.project.project.save()
        self.project.close()
        self.project = None

    try:
        project = GhidraProject.openProject(
            project_location, project_name, True)
        self.logger.info(f'Opened project: {project.project.name}')
    except (IOException, NotFoundException):
        project = GhidraProject.createProject(
            project_location, project_name, False)
        self.logger.info(f'Created project: {project.project.name}')

    self.project = project

    self.logger.info(
        f'Project Location: {project.project.projectLocator.location}')

    bin_results = []
    proj_programs = []

    # remove duplicate paths, maintain order
    import_paths = list(dict.fromkeys(binary_paths))

    # remove duplicate files (different path, but same content)
    bin_hashes = []
    for i, bin_hash in enumerate([sha1_file(path) for path in import_paths]):

        if bin_hash in bin_hashes:
            self.logger.warn(
                f'Duplicate file detected {import_paths[i]} with sha1: {bin_hash}')
        else:
            bin_hashes.append(bin_hash)

    # Import binaries and configure symbols
    for program_path in import_paths:

        # add sha1 to prevent files with same name collision
        program_name = self.gen_proj_bin_name_from_path(program_path)

        # Import binaries and configure symbols
        if not project.getRootFolder().getFile(program_name):
            self.logger.info(f'Importing {program_path} as {program_name}')
            program = project.importProgram(program_path)
            project.saveAs(program, "/", program_name, True)
        else:
            self.logger.info(f'Opening {program_path}')
            program = self.project.openProgram("/", program_name, False)

        self.logger.info(f'Loaded {program}')

        # set base address if provided
        img_base = program.getImageBase()
        if self.base_address is not None and self.base_address != img_base.offset:
            self.logger.info(
                f'Setting {program} base address: 0x{img_base} to {hex(self.base_address)}')
            new_image_base = img_base.getNewAddress(self.base_address)
            program.setImageBase(new_image_base, True)
            project.save(program)
        else:
            self.logger.info(f'Image base address: 0x{img_base}')

        proj_programs.append(program)

    # Print of project files
    self.logger.info('Project Files:')
    for df in self.project.getRootFolder().getFiles():
        self.logger.info(df)

    # Setup Symbols Server
    if not self.no_symbols:
        if any(self.prog_is_windows(prog) for prog in proj_programs):
            # Windows level 1 symbol server location
            level = 1
        else:
            # Symbols stored in specified symbols path
            level = 0
        self.setup_symbol_server(
            symbols_path, level, server_urls=symbol_urls)

    for program in proj_programs:

        if not self.no_symbols:
            # Enable Remote Symbol Servers

            if hasattr(PdbUniversalAnalyzer, 'setAllowUntrustedOption'):
                # Ghidra 11.2 +
                PdbUniversalAnalyzer.setAllowUntrustedOption(program, True)
                PdbAnalyzer.setAllowUntrustedOption(program, True)
            else:
                # Ghidra < 11.2
                PdbUniversalAnalyzer.setAllowRemoteOption(program, True)
                PdbAnalyzer.setAllowRemoteOption(program, True)

            pdb = self.get_pdb(program)
        else:
            # Run get_pdb to make sure the symbols dont exist locally
            pdb = self.get_pdb(program, allow_remote=False)

            if pdb:
                err = f'Symbols are disabled, but the symbol is already downloaded {pdb}. Delete symbol or remove --no-symbol flag'  # nopep8
                self.logger.error(err)
                raise FileExistsError(err)

        if pdb is None and not self.no_symbols:
            self.logger.warn(f"PDB not found for {program.getName()}!")

        from ghidra.app.util.pdb import PdbProgramAttributes

        pdb_attr = PdbProgramAttributes(program)

        imported = program is not None
        has_pdb = pdb is not None
        pdb_loaded = pdb_attr.pdbLoaded
        prog_analyzed = pdb_attr.programAnalyzed

        bin_results.append(
            [program.getDomainFile().name, imported, has_pdb, pdb_loaded, prog_analyzed])

        project.close(program)

    for result in bin_results:
        self.logger.info(
            'Program: %s imported: %s has_pdb: %s pdb_loaded: %s analyzed %s', *result)

    return bin_results
