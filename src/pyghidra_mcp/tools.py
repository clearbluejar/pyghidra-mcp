"""
Comprehensive tool implementations for pyghidra-mcp.
"""

import functools
import logging
import re
import typing

from jpype import JByte

from pyghidra_mcp.models import (
    BytesReadResult,
    CodeSearchResult,
    CrossReferenceInfo,
    DecompiledFunction,
    ExportInfo,
    ImportInfo,
    StringInfo,
    StringSearchResult,
    SymbolInfo,
)

if typing.TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults
    from ghidra.program.model.listing import Function

    from .context import ProgramInfo

logger = logging.getLogger(__name__)


def handle_exceptions(func):
    """Decorator to handle exceptions in tool methods"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e!s}")
            raise

    return wrapper


class GhidraTools:
    """Comprehensive tool handler for Ghidra MCP tools"""

    def __init__(self, program_info: "ProgramInfo"):
        """Initialize with a Ghidra ProgramInfo object"""
        self.program_info = program_info
        self.program = program_info.program
        self.decompiler = program_info.decompiler

    def _get_filename(self, func: "Function"):
        max_path_len = 12
        return f"{func.getName()[:max_path_len]}-{func.entryPoint}"

    @handle_exceptions
    def decompile_function(self, name: str, timeout: int = 0) -> DecompiledFunction:
        """Decompiles a function in a specified binary and returns its pseudo-C code."""
        from ghidra.util.task import ConsoleTaskMonitor

        fm = self.program.getFunctionManager()
        functions = fm.getFunctions(True)
        for func in functions:
            if name == func.name:
                monitor = ConsoleTaskMonitor()
                result: DecompileResults = self.decompiler.decompileFunction(func, timeout, monitor)
                if "" == result.getErrorMessage():
                    code = result.decompiledFunction.getC()
                    sig = result.decompiledFunction.getSignature()
                else:
                    code = result.getErrorMessage()
                    sig = None
                return DecompiledFunction(name=self._get_filename(func), code=code, signature=sig)
        raise ValueError(f"Function {name} not found")

    @handle_exceptions
    def get_all_functions(self, include_externals=False) -> list["Function"]:
        """Gets all functions within a binary."""

        funcs = []
        fm = self.program.getFunctionManager()
        functions = fm.getFunctions(True)
        for func in functions:
            func: Function
            if not include_externals and func.isExternal():
                continue
            if not include_externals and func.thunk:
                continue
            funcs.append(func)
        return funcs

    def get_all_strings(self) -> list[StringInfo]:
        """Gets all defined strings for a binary"""
        try:
            from ghidra.program.util import DefinedStringIterator  # type: ignore

            data_iterator = DefinedStringIterator.forProgram(self.program)
        except ImportError:
            # Support Ghidra 11.3.2
            from ghidra.program.util import DefinedDataIterator

            data_iterator = DefinedDataIterator.definedStrings(self.program)

        strings = []
        for data in data_iterator:
            try:
                string_value = data.getValue()
                strings.append(StringInfo(value=str(string_value), address=str(data.getAddress())))
            except Exception as e:
                logger.debug(f"Could not get string value from data at {data.getAddress()}: {e}")

        return strings

    @handle_exceptions
    def search_symbols_by_name(
        self, query: str, offset: int = 0, limit: int = 100
    ) -> list[SymbolInfo]:
        """Searches for symbols within a binary by name."""
        from ghidra.program.model.symbol import SymbolTable

        if not query:
            raise ValueError("Query string is required")

        symbols_info = []
        st: SymbolTable = self.program.getSymbolTable()
        symbols = st.getAllSymbols(True)
        rm = self.program.getReferenceManager()

        # Search for symbols containing the query string
        for symbol in symbols:
            if query.lower() in symbol.name.lower():
                ref_count = len(list(rm.getReferencesTo(symbol.getAddress())))
                symbols_info.append(
                    SymbolInfo(
                        name=symbol.name,
                        address=str(symbol.getAddress()),
                        type=str(symbol.getSymbolType()),
                        namespace=str(symbol.getParentNamespace()),
                        source=str(symbol.getSource()),
                        refcount=ref_count,
                    )
                )
        return symbols_info[offset : limit + offset]

    @handle_exceptions
    def list_exports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ExportInfo]:
        """Lists all exported functions and symbols from a specified binary."""
        exports = []
        symbols = self.program.getSymbolTable().getAllSymbols(True)
        for symbol in symbols:
            if symbol.isExternalEntryPoint():
                if query and not re.search(query, symbol.getName(), re.IGNORECASE):
                    continue
                exports.append(ExportInfo(name=symbol.getName(), address=str(symbol.getAddress())))
        return exports[offset : limit + offset]

    @handle_exceptions
    def list_imports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ImportInfo]:
        """Lists all imported functions and symbols for a specified binary."""
        imports = []
        symbols = self.program.getSymbolTable().getExternalSymbols()
        for symbol in symbols:
            if query and not re.search(query, symbol.getName(), re.IGNORECASE):
                continue
            imports.append(
                ImportInfo(name=symbol.getName(), library=str(symbol.getParentNamespace()))
            )
        return imports[offset : limit + offset]

    @handle_exceptions
    def list_cross_references(self, name_or_address: str) -> list[CrossReferenceInfo]:
        """Finds and lists all cross-references (x-refs) to a given function, symbol,
        or address within a binary.
        """
        addr = None
        try:
            addr = self.program.getAddressFactory().getAddress(name_or_address)
        except Exception:
            pass

        if addr is None:
            # Search for exact match in symbols. Functions are symbols, so this covers them.
            st = self.program.getSymbolTable()
            symbols = st.getAllSymbols(True)
            for symbol in symbols:
                if name_or_address.lower() == symbol.name.lower():
                    addr = symbol.getAddress()
                    break

        # If no exact match is found, find close matches and raise an error
        if addr is None:
            close_matches = []
            st = self.program.getSymbolTable()
            symbols = st.getAllSymbols(True)
            for symbol in symbols:
                if name_or_address.lower() in symbol.name.lower():
                    close_matches.append(symbol.name)

            if close_matches:
                unique_matches = sorted(list(set(close_matches)))
                total_matches = len(unique_matches)

                # Sort by length to get potentially more relevant matches first, and take top 10
                display_matches = sorted(unique_matches, key=len)[:10]

                suggestions = ", ".join(display_matches)
                message = (
                    f"Could not find '{name_or_address}'. Did you mean one of these: {suggestions}"
                )
                message += f" (total similar symbols {total_matches})?"
                raise ValueError(message)
            else:
                raise ValueError(f"Could not find function, symbol, or address: {name_or_address}")

        cross_references = []

        # Get references
        rm = self.program.getReferenceManager()
        references = rm.getReferencesTo(addr)

        for ref in references:
            func = self.program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
            cross_references.append(
                CrossReferenceInfo(
                    function_name=func.getName() if func else None,
                    from_address=str(ref.getFromAddress()),
                    to_address=str(ref.getToAddress()),
                    type=str(ref.getReferenceType()),
                )
            )
        return cross_references

    @handle_exceptions
    def search_code(self, query: str, limit: int = 10) -> list[CodeSearchResult]:
        """Searches the code in the binary for a given query."""
        if not self.program_info.code_collection:
            raise ValueError(
                "Code indexing is not complete for this binary. Please try again later."
            )

        results = self.program_info.code_collection.query(query_texts=[query], n_results=limit)
        search_results = []
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                metadata = results["metadatas"][0][i]  # type: ignore
                distance = results["distances"][0][i]  # type: ignore
                search_results.append(
                    CodeSearchResult(
                        function_name=str(metadata["function_name"]),
                        code=doc,
                        similarity=1 - distance,
                    )
                )
        return search_results

    @handle_exceptions
    def search_strings(self, query: str, limit: int = 100) -> list[StringSearchResult]:
        """Searches for strings within a binary."""

        if not self.program_info.strings_collection:
            raise ValueError(
                "String indexing is not complete for this binary. Please try again later."
            )

        search_results = []
        results = self.program_info.strings_collection.get(
            where_document={"$contains": query}, limit=limit
        )
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"]):
                metadata = results["metadatas"][i]  # type: ignore
                search_results.append(
                    StringSearchResult(
                        value=doc,
                        address=str(metadata["address"]),
                        similarity=1,
                    )
                )
            limit -= len(results["documents"])

        results = self.program_info.strings_collection.query(query_texts=[query], n_results=limit)
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                metadata = results["metadatas"][0][i]  # type: ignore
                distance = results["distances"][0][i]  # type: ignore
                search_results.append(
                    StringSearchResult(
                        value=doc,
                        address=str(metadata["address"]),
                        similarity=1 - distance,
                    )
                )

        return search_results

    @handle_exceptions
    def read_bytes(self, address: str, size: int = 32) -> BytesReadResult:
        """Reads raw bytes from memory at a specified address."""
        # Maximum size limit to prevent excessive memory reads
        max_read_size = 8192

        if size <= 0:
            raise ValueError("size must be > 0")

        if size > max_read_size:
            raise ValueError(f"Size {size} exceeds maximum {max_read_size}")

        # Get address factory and parse address
        af = self.program.getAddressFactory()

        try:
            # Handle common hex address formats
            addr_str = address
            if address.lower().startswith("0x"):
                addr_str = address[2:]

            addr = af.getAddress(addr_str)
            if addr is None:
                raise ValueError(f"Invalid address: {address}")
        except Exception as e:
            raise ValueError(f"Invalid address format '{address}': {e}") from e

        # Check if address is in valid memory
        mem = self.program.getMemory()
        if not mem.contains(addr):
            raise ValueError(f"Address {address} is not in mapped memory")

        # Use JPype to handle byte arrays properly for PyGhidra
        # Create Java byte array - JPype's runtime magic confuses static type checkers
        buf = JByte[size]  # type: ignore[reportInvalidTypeArguments]
        n = mem.getBytes(addr, buf)

        # Convert Java signed bytes (-128 to 127) to Python unsigned (0 to 255)
        if n > 0:
            data = bytes([b & 0xFF for b in buf[:n]])  # type: ignore[reportGeneralTypeIssues]
        else:
            data = b""

        return BytesReadResult(
            address=str(addr),
            size=len(data),
            data=data.hex(),
        )
