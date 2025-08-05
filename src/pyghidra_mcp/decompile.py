import typing

if typing.TYPE_CHECKING:
    pass


def setup_decomplier(
    program: "ghidra.program.model.listing.Program",
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


def get_filename(func: "ghidra.program.model.listing.Function"):
    max_path_len = 12
    return f"{func.getName()[:max_path_len]}-{func.entryPoint}"


def decompile_func(
    func: "ghidra.program.model.listing.Function", decompiler: dict, timeout: int = 0, monitor=None
) -> list:
    """
    Decompile function and return [funcname, decompilation]
    Ghidra/Features/Decompiler/src/main/java/ghidra/app/util/exporter/CppExporter.java#L514
    """
    from ghidra.app.decompiler import DecompileResults
    from ghidra.util.task import ConsoleTaskMonitor

    if monitor is None:
        monitor = ConsoleTaskMonitor()

    result: DecompileResults = decompiler.decompileFunction(func, timeout, monitor)

    if "" == result.getErrorMessage():
        code = result.decompiledFunction.getC()
        sig = result.decompiledFunction.getSignature()
    else:
        code = result.getErrorMessage()
        sig = None

    return [get_filename(func), code, sig]
