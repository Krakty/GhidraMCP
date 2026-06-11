# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

# Cached /info payload + display label, populated by _identify_program() at
# startup. Empty dict until then; tools that read it should treat absence as
# "Ghidra not reachable yet".
program_info_cache: dict = {}
program_label: str = ""

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_get_json(endpoint: str, params: dict = None) -> dict:
    """
    GET <endpoint> and parse the response as JSON. Used by spool-mode
    (to_file=True) responses, which return a small envelope describing where
    the agent can curl the actual body.

    On HTTP or decode error, returns {"error": "..."} so the caller (an MCP
    tool) can surface the failure as a normal tool result rather than raising.
    """
    if params is None:
        params = {}
    url = urljoin(ghidra_server_url, endpoint)
    try:
        response = requests.get(url, params=params, timeout=30)
        response.encoding = "utf-8"
        if not response.ok:
            return {"error": f"HTTP {response.status_code}: {response.text.strip()}"}
        return response.json()
    except ValueError as e:
        return {"error": f"JSON decode failed: {e}"}
    except Exception as e:
        return {"error": f"Request failed: {e}"}


def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=30)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions(to_file: bool = False):
    """
    List all functions in the database.

    When to_file=True, the result is spooled to a file on the plugin host and
    a small JSON envelope with a fetch URL is returned. Useful for large
    binaries where the full function list would otherwise overflow the MCP
    transport. Fetch the URL with curl in a Bash tool call.
    """
    if to_file:
        return safe_get_json("list_functions", {"to_file": "true"})
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str, to_file: bool = False):
    """
    Decompile a function at the given address.

    When to_file=True, the decompiled C is spooled to a file on the plugin
    host and a small JSON envelope with a fetch URL is returned. Useful for
    very large functions where the MCP transport would otherwise drop. Fetch
    the URL with curl in a Bash tool call.
    """
    if to_file:
        return safe_get_json("decompile_function",
                             {"address": address, "to_file": "true"})
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str, to_file: bool = False):
    """
    Get assembly code (address: instruction; comment) for a function.

    When to_file=True, the disassembly is spooled to a file on the plugin
    host and a small JSON envelope with a fetch URL is returned. Useful for
    very large functions where the MCP transport would otherwise drop. Fetch
    the URL with curl in a Bash tool call.
    """
    if to_file:
        return safe_get_json("disassemble_function",
                             {"address": address, "to_file": "true"})
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None,
                 to_file: bool = False):
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        to_file: When True, spool the result to a file on the plugin host
                 and return a small JSON envelope with a fetch URL. Useful
                 for large string tables. Fetch with curl in a Bash call.

    Returns:
        Without to_file: list of strings with their addresses.
        With to_file:    dict envelope {url, uuid, bytes, lines, ttl_seconds}.
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    if to_file:
        params["to_file"] = "true"
        return safe_get_json("strings", params)
    return safe_get("strings", params)

@mcp.tool()
def program_info() -> dict:
    """
    Identify the Ghidra program this MCP server is bound to.

    Returns the cached /info payload (port, tool name, program name, date
    prefix, plugin version) plus a human-readable label. Useful when several
    ghidra-* MCP servers are loaded at once and you need to tell them apart.
    """
    return {
        "label": program_label,
        "ghidra_server": ghidra_server_url,
        "info": program_info_cache,
    }


def _identify_program() -> None:
    """
    Hit /info once at startup, cache the payload, and stamp a human-readable
    label into every registered tool's description plus the MCP server name.
    This is how each bridge instance announces *which* Ghidra program it
    represents, so Claude can tell ghidra-8090 (eqgame) from ghidra-8091
    (eqmain) without making the user do per-port mental bookkeeping.

    Failures are non-fatal — the bridge still serves; the label just falls
    back to "<ghidra_server_url> (offline)" so the absence is visible.
    """
    global program_info_cache, program_label

    info = {}
    try:
        url = urljoin(ghidra_server_url, "info")
        resp = requests.get(url, timeout=2)
        if resp.ok:
            info = resp.json()
    except Exception as e:
        logger.warning(f"/info probe failed for {ghidra_server_url}: {e}")

    program_info_cache = info

    if info:
        port = info.get("port", "?")
        name = info.get("name") or "(no program loaded)"
        date = info.get("datePrefix") or ""
        # The plugin returns the FULL DomainFile name which often already starts
        # with the date prefix (e.g. "6-9-2026-test-eqgame.exe"). When we have
        # a canonical datePrefix to display, strip the leading date from name
        # so the label reads "06-09-2026 test-eqgame.exe @ 8090" rather than
        # "06-09-2026 6-9-2026-test-eqgame.exe @ 8090".
        if date:
            import re
            name = re.sub(r"^\d{1,2}-\d{1,2}-\d{4}-", "", name)
            program_label = f"{date} {name} @ {port}"
        else:
            program_label = f"{name} @ {port}"
    else:
        program_label = f"{ghidra_server_url} (offline)"

    # Prepend label to every tool's description so it appears in Claude's
    # tool catalog. Iterate via list_tools() to get the same objects the
    # tool manager exposes to the protocol layer.
    try:
        prefix = f"[{program_label}] "
        for tool in mcp._tool_manager.list_tools():
            tool.description = prefix + (tool.description or "")
    except Exception as e:
        logger.warning(f"could not patch tool descriptions: {e}")

    # Also override the server name. Many MCP clients display this in the
    # tool list header, which makes the binding obvious at a glance.
    try:
        mcp._mcp_server.name = f"ghidra-mcp [{program_label}]"
    except Exception as e:
        logger.warning(f"could not patch server name: {e}")


def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server

    # Probe /info and stamp the program identity into tool metadata so
    # Claude can distinguish multiple ghidra-* MCP servers at a glance.
    _identify_program()

    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

