import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import BytesReadResult


@pytest.mark.asyncio
async def test_read_bytes_happy_path(server_params):
    """Test reading bytes from a valid memory address."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # First, get functions to find a valid address (not external symbols)
            functions_response = await session.call_tool(
                "search_functions_by_name", {"binary_name": binary_name, "query": "main", "limit": 1}
            )

            functions_result = functions_response.content[0].text
            import json
            functions_data = json.loads(functions_result)

            # Skip test if no functions found
            if not functions_data.get("functions"):
                pytest.skip("No functions found in test binary")
                return

            # Get the entry point address of main function
            main_address = functions_data["functions"][0]["entry_point"]

            # Test reading bytes from main function
            response = await session.call_tool(
                "read_bytes", 
                {
                    "binary_name": binary_name, 
                    "address": main_address, 
                    "size": 16
                }
            )

            # Validate response structure
            result_text = response.content[0].text
            result = BytesReadResult.model_validate_json(result_text)
            
            assert result.address is not None
            assert result.size > 0
            assert result.size <= 16
            assert len(result.bytes_hex) == result.size * 2  # Hex string is 2 chars per byte
            assert len(result.hexdump) > 0
            assert len(result.ascii_preview) <= 128
            
            # Verify hex string contains valid hex characters
            try:
                bytes.fromhex(result.bytes_hex)
            except ValueError:
                pytest.fail("Invalid hex string in bytes_hex")


@pytest.mark.asyncio
async def test_read_bytes_with_hex_prefix(server_params):
    """Test reading bytes using 0x hex prefix."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Get a valid address from functions
            functions_response = await session.call_tool(
                "search_functions_by_name", {"binary_name": binary_name, "query": "main", "limit": 1}
            )

            functions_result = functions_response.content[0].text
            import json
            functions_data = json.loads(functions_result)

            if not functions_data.get("functions"):
                pytest.skip("No functions found in test binary")
                return

            # Get address and add 0x prefix
            main_address = functions_data["functions"][0]["entry_point"]
            if not main_address.startswith("0x"):
                main_address = "0x" + main_address

            # Test reading with 0x prefix
            response = await session.call_tool(
                "read_bytes", 
                {
                    "binary_name": binary_name, 
                    "address": main_address, 
                    "size": 8
                }
            )

            result_text = response.content[0].text
            result = BytesReadResult.model_validate_json(result_text)
            
            assert result.size > 0
            assert len(result.bytes_hex) == result.size * 2


@pytest.mark.asyncio
async def test_read_bytes_invalid_address(server_params):
    """Test reading from an invalid address format."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Test with invalid address format
            try:
                await session.call_tool(
                    "read_bytes", 
                    {
                        "binary_name": binary_name, 
                        "address": "invalid_address", 
                        "size": 16
                    }
                )
                pytest.fail("Should have raised an exception for invalid address")
            except Exception as e:
                # Should get an error about invalid address format
                assert "Invalid address" in str(e) or "address format" in str(e)


@pytest.mark.asyncio
async def test_read_bytes_unmapped_address(server_params):
    """Test reading from an unmapped memory address."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Test with a likely unmapped address (very high address)
            try:
                await session.call_tool(
                    "read_bytes", 
                    {
                        "binary_name": binary_name, 
                        "address": "FFFFFFFF", 
                        "size": 16
                    }
                )
                pytest.fail("Should have raised an exception for unmapped address")
            except Exception as e:
                # Should get an error about unmapped memory
                assert "not in mapped memory" in str(e) or "Invalid address" in str(e)


@pytest.mark.asyncio
async def test_read_bytes_invalid_size(server_params):
    """Test reading with invalid size parameters."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Get a valid address first
            functions_response = await session.call_tool(
                "search_functions_by_name", {"binary_name": binary_name, "query": "main", "limit": 1}
            )

            functions_result = functions_response.content[0].text
            import json
            functions_data = json.loads(functions_result)

            if not functions_data.get("functions"):
                pytest.skip("No functions found in test binary")
                return

            main_address = functions_data["functions"][0]["entry_point"]

            # Test with size = 0
            try:
                await session.call_tool(
                    "read_bytes", 
                    {
                        "binary_name": binary_name, 
                        "address": main_address, 
                        "size": 0
                    }
                )
                pytest.fail("Should have raised an exception for size = 0")
            except Exception as e:
                assert "size must be > 0" in str(e)

            # Test with negative size
            try:
                await session.call_tool(
                    "read_bytes", 
                    {
                        "binary_name": binary_name, 
                        "address": main_address, 
                        "size": -1
                    }
                )
                pytest.fail("Should have raised an exception for negative size")
            except Exception as e:
                assert "size must be > 0" in str(e)

            # Test with size too large (>8192)
            try:
                await session.call_tool(
                    "read_bytes", 
                    {
                        "binary_name": binary_name, 
                        "address": main_address, 
                        "size": 10000
                    }
                )
                pytest.fail("Should have raised an exception for size too large")
            except Exception as e:
                assert "exceeds maximum" in str(e)


@pytest.mark.asyncio
async def test_read_bytes_default_size(server_params):
    """Test reading bytes with default size parameter."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_name = PyGhidraContext._gen_unique_bin_name(server_params.args[-1])

            # Get a valid address
            functions_response = await session.call_tool(
                "search_functions_by_name", {"binary_name": binary_name, "query": "main", "limit": 1}
            )

            functions_result = functions_response.content[0].text
            import json
            functions_data = json.loads(functions_result)

            if not functions_data.get("functions"):
                pytest.skip("No functions found in test binary")
                return

            main_address = functions_data["functions"][0]["entry_point"]

            # Test with default size (should be 32)
            response = await session.call_tool(
                "read_bytes", 
                {
                    "binary_name": binary_name, 
                    "address": main_address
                    # No size parameter - should default to 32
                }
            )

            result_text = response.content[0].text
            result = BytesReadResult.model_validate_json(result_text)
            
            # Size should be 32 or less (if we hit memory boundary)
            assert 0 < result.size <= 32
            assert len(result.bytes_hex) == result.size * 2


@pytest.mark.asyncio
async def test_read_bytes_nonexistent_binary(server_params):
    """Test reading bytes from a non-existent binary."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Test with non-existent binary
            try:
                await session.call_tool(
                    "read_bytes", 
                    {
                        "binary_name": "nonexistent_binary", 
                        "address": "1000", 
                        "size": 16
                    }
                )
                pytest.fail("Should have raised an exception for non-existent binary")
            except Exception as e:
                assert "not found" in str(e)