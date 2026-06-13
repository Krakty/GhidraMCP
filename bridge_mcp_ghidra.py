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


def safe_post_json(endpoint: str, data: dict | str) -> dict:
    """
    POST <endpoint> and parse the response as JSON. Used by bulk endpoints
    that return structured envelopes. On HTTP or decode error, returns
    {"error": "..."}.
    """
    url = urljoin(ghidra_server_url, endpoint)
    try:
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=60)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=60)
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


# ----------------------------------------------------------------------------
# Tier 1 PR 1: symbol-table endpoints
# ----------------------------------------------------------------------------

@mcp.tool()
def list_symbols(offset: int = 0, limit: int = 200,
                 type: str = None, source: str = None,
                 to_file: bool = False):
    """
    List every entry in the SymbolTable (the whole-program one — not just
    defined Data). One line per symbol:

        <address> <type> <source> [<namespace>::]<name>

    Useful for verification sweeps where the legacy /data endpoint returned
    nothing because bare labels created by rename_data don't show up there.

    Args:
        offset:  pagination offset (default 0)
        limit:   max symbols to return (default 200)
        type:    filter to one SymbolType — "function", "label", "parameter",
                 "local_var", "global_var", "namespace", "class", "library".
                 Case-insensitive; "all" or None means no filter.
        source:  filter to one SourceType — "user_defined", "analysis",
                 "imported", "default". Case-insensitive.
        to_file: spool the result; see decompile_function for the curl
                 pattern. Recommended for large binaries.
    """
    params = {"offset": offset, "limit": limit}
    if type:   params["type"] = type
    if source: params["source"] = source
    if to_file:
        params["to_file"] = "true"
        return safe_get_json("list_symbols", params)
    return safe_get("list_symbols", params)


@mcp.tool()
def get_symbol_at(address: str) -> list:
    """
    Return every symbol at the given address as a list of dicts. Empty list
    if there's no symbol. There can be more than one (primary + aliases);
    the dict's "primary" field flags which is which.

    Each entry: {name, address, type, source, primary, namespace}.
    """
    res = safe_get_json("get_symbol_at", {"address": address})
    # Server returns a JSON array; safe_get_json gives us the parsed value.
    return res if isinstance(res, list) else [res]


@mcp.tool()
def delete_label(address: str = None, name: str = None) -> str:
    """
    Delete a label by address, name, or both. Either argument alone is
    accepted; supplying both narrows the match (helpful when an address
    carries multiple symbols).

    Wraps the removal in a Ghidra transaction so the change is undoable
    via Edit -> Undo in the GUI.

    Returns a short text payload like "removed 1 of 1 matched".
    """
    payload = {}
    if address: payload["address"] = address
    if name:    payload["name"]    = name
    return safe_post("delete_label", payload)


# ----------------------------------------------------------------------------
# Tier 1 PR 2: function lifecycle endpoints
# ----------------------------------------------------------------------------

@mcp.tool()
def create_function(address: str, name: str = None) -> str:
    """
    Create a function at <address>. Uses Ghidra's CreateFunctionCmd which
    auto-discovers the function body via flow analysis from the entry
    point. Pass <name> to set the function name; if omitted, Ghidra picks
    FUN_<addr>.

    Use this to promote code Ghidra's auto-analysis missed (e.g., entries
    found via xrefs, prologue scans, or LLM-driven analysis). The change is
    transaction-wrapped and undoable from the Ghidra GUI.

    Refuses if a function already exists at the address — call
    delete_function first to recreate.
    """
    payload = {"address": address}
    if name: payload["name"] = name
    return safe_post("create_function", payload)


@mcp.tool()
def delete_function(address: str) -> str:
    """
    Remove the function at <address> from the FunctionManager. The
    underlying disassembly stays — only the function classification is
    dropped. Use to retract bad auto-analysis results or stale labels from
    prior patchdays.

    Transaction-wrapped and undoable from the Ghidra GUI.
    """
    return safe_post("delete_function", {"address": address})


@mcp.tool()
def mark_function_thunk(address: str, target: str = None) -> str:
    """
    Mark the function at <address> as a thunk to the function at <target>.
    Ghidra's decompiler then redirects call sites through to the target's
    decompilation — useful for jump-table stubs that JMP into a real
    function.

    Pass target="clear" (or omit it / pass empty) to detach an existing
    thunk relationship.

    Both addresses must already be classified as functions; the call
    fails otherwise.

    Transaction-wrapped and undoable from the Ghidra GUI.
    """
    payload = {"address": address}
    if target: payload["target"] = target
    return safe_post("mark_function_thunk", payload)


# ----------------------------------------------------------------------------
# Tier 1 PR 3: DataType endpoints
# ----------------------------------------------------------------------------

@mcp.tool()
def parse_c_header(header: str) -> dict:
    """
    Parse C source into the program's DataTypeManager — same engine as the
    GUI File -> Parse C Source.

    Accepts arbitrary C: a single struct, multiple structs, typedefs, enums,
    function prototypes. Forward-declared or referenced types not yet in the
    DTM are created as opaque/undefined so the parse doesn't fail on
    incomplete inputs — fill them in with follow-up parse_c_header calls.

    Returns a JSON envelope: {successful, added: [<paths>], added_count,
    error?}. Wraps the parse in a Ghidra transaction so it's undoable.
    """
    return safe_post("parse_c_header", {"header": header})


@mcp.tool()
def apply_data_type_at(address: str, type: str, clear: bool = True) -> str:
    """
    Apply the named DataType at <address>. The type must already exist in the
    DTM (use parse_c_header first if needed).

    With clear=True (default), existing code units in the affected byte range
    are cleared first so the apply is idempotent — re-running on the same
    address with the same type is a no-op. Set clear=False to refuse if the
    address already has data.

    Type names can include * for pointers (e.g. "CXWnd*") and array suffixes
    like "[16]" when resolveDataType supports them.

    Transaction-wrapped.
    """
    payload = {"address": address, "type": type,
               "clear": "true" if clear else "false"}
    return safe_post("apply_data_type_at", payload)


@mcp.tool()
def get_data_type(name: str, to_file: bool = False):
    """
    Return a JSON description of the named DataType.

    For structures the response includes a "members" array with each field's
    offset, ordinal, name, type pathname, length, and optional comment —
    everything you need to verify or migrate a struct layout. For non-struct
    types the response is a compact descriptor.

    Pass to_file=True to spool the JSON envelope for big structures (PlayerClient,
    CharacterZoneClient have hundreds of members); curl the URL the same way as
    the other to_file endpoints.
    """
    params = {"name": name}
    if to_file:
        params["to_file"] = "true"
        return safe_get_json("get_data_type", params)
    return safe_get_json("get_data_type", params)


@mcp.tool()
def list_data_types(offset: int = 0, limit: int = 200,
                    category: str = None, pattern: str = None,
                    kind: str = None, to_file: bool = False):
    """
    Enumerate types in the DataTypeManager.

    Args:
        offset:   pagination offset (default 0)
        limit:    max entries (default 200)
        category: category-path prefix filter (e.g. "/MyHeader")
        pattern:  case-insensitive substring match against the pathname
        kind:     case-insensitive substring of the type-class name —
                  "structure", "enum", "typedef", "pointer", etc.
                  "all" or None = no filter
        to_file:  spool the result (recommended for full-DTM dumps)

    One line per type: "<path> <kind> <length>".
    """
    params = {"offset": offset, "limit": limit}
    if category: params["category"] = category
    if pattern:  params["pattern"]  = pattern
    if kind:     params["kind"]     = kind
    if to_file:
        params["to_file"] = "true"
        return safe_get_json("list_data_types", params)
    return safe_get("list_data_types", params)


@mcp.tool()
def apply_labels_from_header(header: str,
                             strip_suffix: str = None,
                             create_if_missing: bool = True) -> dict:
    """
    Bulk-apply #define NAME ADDR pairs in a C-style header as function
    renames and/or data labels. Replaces the external ApplyEqgameLabels.py
    Jython tool documented in MQ-RE's TOOLS_MATRIX.md.

    For each parsed #define:
      - If a function exists at ADDR: rename it (function-name promotion).
      - Else if any symbol exists at ADDR: rename the primary symbol.
      - Else if create_if_missing: create a USER_DEFINED label at ADDR.
      - Else: count as skipped.

    Args:
        header:           C-style header text with #define lines.
        strip_suffix:     trailing string to strip from each NAME (e.g. "_x").
        create_if_missing: when True, addresses with no existing symbol get
                          a new USER_DEFINED label. When False, they're
                          counted as skipped instead.

    Returns: {parsed, renamed_functions, renamed_symbols, created_labels,
              skipped, errors: [...]}.
    """
    payload = {"header": header}
    if strip_suffix is not None:
        payload["strip_suffix"] = strip_suffix
    payload["create_if_missing"] = "true" if create_if_missing else "false"
    return safe_post_json("apply_labels_from_header", payload)


@mcp.tool()
def rename_functions_bulk(header: str, strip_suffix: str = None) -> dict:
    """
    Strict variant of apply_labels_from_header: only renames addresses that
    are already classified as functions. Addresses that aren't functions are
    reported in the "missing" list — useful as input for a follow-up
    create_function pass.

    Returns: {parsed, renamed, missing: [...], errors: [...]}.
    """
    payload = {"header": header}
    if strip_suffix is not None:
        payload["strip_suffix"] = strip_suffix
    return safe_post_json("rename_functions_bulk", payload)


# ----------------------------------------------------------------------------
# Script execution: /run_script + /list_scripts
# ----------------------------------------------------------------------------

@mcp.tool()
def list_scripts(offset: int = 0, limit: int = 500,
                 category: str = None, pattern: str = None,
                 language: str = None, to_file: bool = False):
    """
    Enumerate Ghidra scripts visible to run_script.

    Walks every directory in Ghidra's script-source path (the install's bundled
    scripts plus ~/ghidra_scripts/) and returns metadata per script:
    {name, path, language, category, description}.

    Args:
        category: substring filter on the script's category path (e.g. "FunctionID")
        pattern:  substring filter on the script name or full path
        language: substring filter on the runtime language (e.g. "Python", "Java")
        to_file:  spool the response (useful for big installs with hundreds of scripts)
    """
    params = {"offset": offset, "limit": limit}
    if category: params["category"] = category
    if pattern:  params["pattern"]  = pattern
    if language: params["language"] = language
    if to_file:  params["to_file"]  = "true"
    return safe_get_json("list_scripts", params)


@mcp.tool()
def run_script(script_name: str = None, script_body: str = None,
               args: list = None, to_file: bool = False,
               transaction_name: str = None) -> dict:
    """
    Execute a Ghidra script against the program bound to this MCP server.

    Exactly one of script_name or script_body must be supplied.
      script_name: name of an installed script (e.g. "ApplySig.py"). Discover
                   available names via list_scripts.
      script_body: raw Python source text. The plugin stages it as a temp
                   inline script under <project>/.mcp_inline_scripts/, runs
                   it, and deletes the file in finally — regardless of
                   success or failure.

    Inside an inline script_body, the standard Ghidra GhidraScript context is
    available: currentProgram, currentAddress, currentSelection, monitor,
    plus the flat API (getFunctionAt, parseAddress, getBytes, etc.) and the
    full ghidra.* / java.* import surface via PyGhidra/JPype.

    Args:
        args:             list of strings passed to the script as
                          script.getScriptArgs(). Order-preserving.
        to_file:          when True, stdout spools to disk and the response
                          contains stdout_url to curl (Tier 0 pattern).
                          Recommended for scripts that produce large output.
        transaction_name: override the default transaction label for the
                          mutation; useful when you want a meaningful Undo
                          label in the Ghidra GUI.

    Returns dict:
        {script, exit_code, runtime_ms, stdout|stdout_url, stderr}.
        exit_code is 0 on success, 1 if the script raised an exception
        during execute(), 2 if the script failed to load. stderr always
        carries the traceback when exit_code != 0.

    Transactions: mutations are wrapped in a single transaction (so the
    whole script is one undo step in the Ghidra GUI). Scripts that open
    their own nested transactions get Ghidra's standard nesting behaviour.
    """
    payload = {}
    if script_name is not None:      payload["script_name"] = script_name
    if script_body is not None:      payload["script_body"] = script_body
    if args is not None:             payload["args"] = "\n".join(str(a) for a in args)
    if to_file:                      payload["to_file"] = "true"
    if transaction_name is not None: payload["transaction_name"] = transaction_name
    return safe_post_json("run_script", payload)


@mcp.tool()
def list_bookmarks(offset: int = 0, limit: int = 200,
                   category: str = None, type: str = None,
                   to_file: bool = False):
    """
    Enumerate bookmarks in the program. One line per bookmark:
    "<addr> <type> <category> <comment>".

    Bookmarks are Ghidra's persistent annotation system — perfect for the
    "deferred_placements" pattern (mark addresses for follow-up sessions
    by category like "verified" / "needs_review" / "stop_condition").

    Args:
        category: case-insensitive substring filter on category
        type:     case-insensitive substring filter on type (Note, Analysis,
                  Error, Warning, Info, or a custom type)
    """
    params = {"offset": offset, "limit": limit}
    if category: params["category"] = category
    if type:     params["type"]     = type
    if to_file:
        params["to_file"] = "true"
        return safe_get_json("list_bookmarks", params)
    return safe_get("list_bookmarks", params)


@mcp.tool()
def add_bookmark(address: str, type: str = "Note",
                 category: str = "", note: str = "") -> str:
    """
    Add or update a bookmark at <address>. <type> auto-creates if it doesn't
    exist (Ghidra's defaults: Note, Analysis, Error, Warning, Info). Use
    <category> as a free-form subdivision the agent can grep on later
    (e.g. "verified", "deferred", "needs_review").
    """
    return safe_post("add_bookmark", {
        "address": address, "type": type,
        "category": category, "note": note,
    })


@mcp.tool()
def delete_bookmark(address: str, type: str = "Note",
                    category: str = None) -> str:
    """
    Delete the bookmark(s) at <address> matching <type> and (optionally)
    <category>. Pass category=None to delete every bookmark of the given
    type at that address.
    """
    payload = {"address": address, "type": type}
    if category is not None: payload["category"] = category
    return safe_post("delete_bookmark", payload)


@mcp.tool()
def list_comments_for_function(address: str, to_file: bool = False):
    """
    Return all comments inside the function containing <address>. One line
    per comment: "<addr> <kind> '<text>'". Kind is PLATE / PRE / EOL / POST /
    REPEATABLE. Text is single-quoted with embedded newlines escaped.

    Closes the "evidence comments aren't readable back later" gap — the
    MQ-RE workflow leaves a lot of decompiler-comment evidence; this lets
    later sessions pick those up without manual grep.
    """
    params = {"address": address}
    if to_file:
        params["to_file"] = "true"
        return safe_get_json("list_comments_for_function", params)
    return safe_get("list_comments_for_function", params)


@mcp.tool()
def get_callgraph(address: str, depth: int = 2,
                  direction: str = "callees") -> dict:
    """
    Walk the callgraph from the function at <address> up to <depth> levels
    deep. <direction> is "callees", "callers", or "both". Depth is clamped
    to 1..6.

    Returns a JSON envelope with each reachable function as a node:
    {address, name, depth, parents: [edges]}. Useful for Phase 5 STEP 0 in
    the runbook (ctor-prove sub-object bases) — instead of chaining
    individual get_xrefs_to calls, the whole local callgraph slice is one
    request.
    """
    return safe_get_json("get_callgraph",
        {"address": address, "depth": depth, "direction": direction})


@mcp.tool()
def set_function_signature_bulk(text: str) -> dict:
    """
    Bulk-apply function prototypes from a per-line input. Each line:

        <address>\\t<prototype>

    Tab-separated, with prototype in standard C declaration form. Lines
    beginning with # or // are skipped. Each prototype is processed by the
    same logic as set_function_prototype, wrapped in a single transaction
    so the batch is atomic.

    Returns: {parsed, applied, errors: [...]}.
    """
    return safe_post_json("set_function_signature_bulk", {"text": text})


@mcp.tool()
def set_struct_member(struct: str, offset: str = None, current_name: str = None,
                      new_name: str = None, new_type: str = None,
                      comment: str = None) -> str:
    """
    Rename and/or retype one member of a struct.

    Identify the member by exactly one of:
      offset       — hex or decimal offset (e.g. "0x50" or "80")
      current_name — the field's current name

    Any of new_name, new_type, comment can be omitted to leave that attribute
    alone. new_type must already exist in the DTM. Widening (new_type wider
    than the current slot) is refused — agents should retype neighbours first
    or use parse_c_header to redefine the whole struct.

    The optional comment field is durable evidence storage — same place
    Ghidra's GUI shows when you hover a struct field. Use it to anchor the
    "axis-evidence" / "ASM-trace" rationale right on the field.

    Transaction-wrapped.
    """
    payload = {"struct": struct}
    if offset is not None:        payload["offset"] = str(offset)
    if current_name is not None:  payload["current_name"] = current_name
    if new_name is not None:      payload["new_name"] = new_name
    if new_type is not None:      payload["new_type"] = new_type
    if comment is not None:       payload["comment"] = comment
    return safe_post("set_struct_member", payload)


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


@mcp.tool()
def open_program(path: str) -> dict:
    """
    Open a program from the Ghidra project into this CodeBrowser tool.
    path: project path (e.g. "/3-16-2026-test-eqgame.exe"). Leading / optional.
    Returns {"opened": path} on success.
    """
    return safe_post_json("open_program", {"path": path})


@mcp.tool()
def vt_list_sessions() -> dict:
    """
    List all Version Tracking sessions in the current Ghidra project.
    Returns {"sessions": ["/SessionName", ...]} with full project paths.
    """
    return safe_get_json("vt_list_sessions")


@mcp.tool()
def vt_create_session(name: str, source_program: str, dest_program: str) -> dict:
    """
    Create a new Version Tracking session in the current Ghidra project.
    name: session name (stored as /name in project root).
    source_program: project path to the annotated/known binary (e.g. "/old_eqgame.exe").
    dest_program: project path to the new binary to annotate (e.g. "/new_eqgame.exe").
    Returns {"created": name, "source": path, "dest": path} on success.
    """
    return safe_post_json("vt_create_session", {
        "name": name,
        "source_program": source_program,
        "dest_program": dest_program,
    })


@mcp.tool()
def vt_run_correlators(session: str, algorithms: str = "") -> dict:
    """
    Run matching correlators on a VT session to find function/data matches.
    WARNING: This is slow -- can take minutes for large binaries. Blocks until done.
    session: session path (e.g. "/MySession").
    algorithms: comma-separated list from: exact_bytes, exact_instructions, exact_data,
                duplicate, reference, similar_symbol.
                Default (empty): exact_bytes, exact_instructions, exact_data, duplicate.
    Returns {"correlators": [{"algorithm": name, "matches": count}, ...]}.
    """
    url = urljoin(ghidra_server_url, "vt_run_correlators")
    data: dict = {"session": session}
    if algorithms:
        data["algorithms"] = algorithms
    try:
        response = requests.post(url, data=data, timeout=600)
        response.encoding = "utf-8"
        if not response.ok:
            return {"error": f"HTTP {response.status_code}: {response.text.strip()}"}
        return response.json()
    except ValueError as e:
        return {"error": f"JSON decode failed: {e}"}
    except Exception as e:
        return {"error": f"Request failed: {e}"}


@mcp.tool()
def vt_list_matches(session: str, min_score: float = 0.0, status: str = "all",
                    offset: int = 0, limit: int = 200) -> dict:
    """
    List matches from a VT session.
    session: session path (e.g. "/MySession").
    min_score: minimum similarity score (0.0 to 1.0, default 0.0 = all).
    status: filter by AVAILABLE, ACCEPTED, REJECTED, or all (default).
    Returns {"total": N, "offset": N, "matches": [{src, dst, score, confidence, status, type}]}.
    """
    return safe_get_json("vt_list_matches", {
        "session": session,
        "min_score": min_score,
        "status": status,
        "offset": offset,
        "limit": limit,
    })


@mcp.tool()
def vt_accept_matches(session: str, min_score: float = 0.0) -> dict:
    """
    Accept all AVAILABLE matches at or above min_score in a VT session.
    session: session path (e.g. "/MySession").
    min_score: minimum similarity score required to accept (default 0.0 = accept all available).
    Returns {"accepted": N, "skipped": N}.
    """
    return safe_post_json("vt_accept_matches", {
        "session": session,
        "min_score": min_score,
    })


@mcp.tool()
def vt_apply_markups(session: str, types: str = "") -> dict:
    """
    Apply markups from accepted VT matches to the destination program and save it.
    session: session path (e.g. "/MySession").
    types: comma-separated subset of: function_name, label, function_signature,
           data_type, eol_comment, plate_comment. Default (empty): function_name, label.
    Returns {"applied": N, "failed": N, "skipped": N}.
    """
    data: dict = {"session": session}
    if types:
        data["types"] = types
    return safe_post_json("vt_apply_markups", data)


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

