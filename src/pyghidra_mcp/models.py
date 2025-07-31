from pydantic import BaseModel, Field
from typing import Optional, List


class DecompiledFunction(BaseModel):
    """Model for a decompiled function."""
    name: str = Field(..., description="The name of the function.")
    code: str = Field(...,
                      description="The decompiled C code of the function.")
    signature: Optional[str] = Field(
        None, description="The signature of the function.")


class FunctionInfo(BaseModel):
    """Model for basic function information."""
    name: str = Field(..., description="The name of the function.")
    entry_point: str = Field(...,
                             description="The entry point address of the function.")


class FunctionSearchResults(BaseModel):
    """Model for a list of functions."""
    functions: List[FunctionInfo] = Field(
        ..., description="A list of functions that match the search criteria.")


class ProgramInfo(BaseModel):
    """Model for program information."""
    name: str = Field(..., description="The name of the program.")
    file_path: Optional[str] = Field(
        None, description="The file path of the program.")
    load_time: Optional[float] = Field(
        None, description="The load time of the program.")
    analysis_complete: bool = Field(...,
                                    description="Whether analysis is complete.")
    metadata: dict = Field(..., description="The metadata of the program.")


class ProgramInfos(BaseModel):
    """Model for a list of program information."""
    programs: List[ProgramInfo] = Field(...,
                                        description="A list of program information.")