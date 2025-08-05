from pydantic import BaseModel, Field


class DecompiledFunction(BaseModel):
    """Model for a decompiled function."""

    name: str = Field(..., description="The name of the function.")
    code: str = Field(..., description="The decompiled C code of the function.")
    signature: str | None = Field(None, description="The signature of the function.")


class FunctionInfo(BaseModel):
    """Model for basic function information."""

    name: str = Field(..., description="The name of the function.")
    entry_point: str = Field(..., description="The entry point address of the function.")


class FunctionSearchResults(BaseModel):
    """Model for a list of functions."""

    functions: list[FunctionInfo] = Field(
        ..., description="A list of functions that match the search criteria."
    )


class ProgramInfo(BaseModel):
    """Model for program information."""

    name: str = Field(..., description="The name of the program.")
    file_path: str | None = Field(None, description="The file path of the program.")
    load_time: float | None = Field(None, description="The load time of the program.")
    analysis_complete: bool = Field(..., description="Whether analysis is complete.")
    metadata: dict = Field(..., description="The metadata of the program.")


class ProgramInfos(BaseModel):
    """Model for a list of program information."""

    programs: list[ProgramInfo] = Field(..., description="A list of program information.")


class ExportInfo(BaseModel):
    """Model for basic export information."""

    name: str = Field(..., description="The name of the export.")
    address: str = Field(..., description="The address of the export.")


class ExportInfos(BaseModel):
    """Model for a list of exports."""

    exports: list[ExportInfo] = Field(..., description="A list of exports.")
