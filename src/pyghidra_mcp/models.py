from pydantic import BaseModel, Field
from typing import Optional, List

class DecompiledFunction(BaseModel):
    """Model for a decompiled function."""
    name: str = Field(..., description="The name of the function.")
    code: str = Field(..., description="The decompiled C code of the function.")
    signature: Optional[str] = Field(None, description="The signature of the function.")

class FunctionInfo(BaseModel):
    """Model for basic function information."""
    name: str = Field(..., description="The name of the function.")
    entry_point: str = Field(..., description="The entry point address of the function.")

class FunctionSearchResults(BaseModel):
    """Model for a list of functions."""
    functions: List[FunctionInfo] = Field(..., description="A list of functions that match the search criteria.")
