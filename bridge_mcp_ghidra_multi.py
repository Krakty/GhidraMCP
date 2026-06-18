# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///
"""
Multi-port GhidraMCP bridge with auto-discovery.

Unlike the single-port bridge (bridge_mcp_ghidra.py) which hard-codes one port,
this bridge PROBES the entire GhidraMCP port range (8090-8129) at startup,
discovers which programs are live where, and exposes a SINGLE tool::

    ghidra_query(port=8093, action="decompile", args='{"name":"FUN_..."}')

Agents can also query by PROGRAM NAME (fuzzy match against the /info "name"
field) instead of port::

    ghidra_query(program="eqlib", action="info")
    ghidra_query(program="eqgame.exe", action="search", args='{"query":"Player"}')

If multiple ports match the same program name the bridge returns an
unambiguous error listing candidates — no silent wrong-target.

The ``ghidra_discover()`` tool re-scans the port range on demand and returns
the current port-to-program mapping.  Call it after Ghidra is restarted or
CodeBrowser windows are opened/closed.

Port range and host are configurable via CLI flags:

    python bridge_mcp_ghidra_multi.py --ghidra-host 10.7.30.37 --port-range 8090-8129
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urljoin

import requests
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclass
class Backend:
    """A discovered GhidraMCP backend."""

    port: int
    base_url: str
    info: dict  # raw /info payload
    label: str  # human-readable label e.g. "03-16-2026-test-eqgame.exe @ 8090"
    online: bool = True


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class PortScanner:
    """Scans a range of ports for GhidraMCP /info endpoints."""

    def __init__(self, host: str, port_start: int = 8090, port_end: int = 8129,
                 allowed_date_prefix: str | None = None):
        self.host = host
        self.port_start = port_start
        self.port_end = port_end
        self.allowed_date_prefix = allowed_date_prefix
        self._lock = threading.Lock()
        self._backends: dict[int, Backend] = {}

    @property
    def backends(self) -> dict[int, Backend]:
        with self._lock:
            return dict(self._backends)

    def scan(self) -> dict[int, Backend]:
        """Probe every port concurrently and return {port: Backend}."""
        results: dict[int, Backend] = {}
        ports = range(self.port_start, self.port_end + 1)

        def probe(port: int) -> Backend | None:
            url = f"http://{self.host}:{port}/"
            try:
                resp = requests.get(urljoin(url, "info"), timeout=2)
                if resp.ok:
                    info = resp.json()
                    # Date-prefix firewall: if allowed_date_prefix is set,
                    # only accept backends that match. This prevents the
                    # cross-build contamination hazard (FP-SWARM-008/019/020).
                    if self.allowed_date_prefix:
                        dp = info.get("datePrefix", "")
                        if dp != self.allowed_date_prefix:
                            return None
                    name = info.get("name", "(no program)")
                    date = info.get("datePrefix", "")
                    label = (
                        f"{date} {name} @ {port}"
                        if date
                        else f"{name} @ {port}"
                    )
                    return Backend(port=port, base_url=url, info=info, label=label)
            except requests.RequestException:
                pass
            return None

        with ThreadPoolExecutor(max_workers=20) as pool:
            futmap = {pool.submit(probe, p): p for p in ports}
            for fut in as_completed(futmap):
                bk = fut.result()
                if bk is not None:
                    results[bk.port] = bk

        with self._lock:
            self._backends = dict(results)
        return results

    def resolve_port(self, port: int) -> Backend | None:
        """Look up a backend by port, with optional live re-check."""
        with self._lock:
            bk = self._backends.get(port)
        if bk is not None:
            return bk
        # Not in cache — try a quick live probe
        bk = self._probe_one(port)
        if bk:
            with self._lock:
                self._backends[port] = bk
        return bk

    def resolve_program(self, name: str) -> Backend | tuple[str, list[Backend]]:
        """
        Fuzzy-match a program name against known backends.

        Returns a Backend on exact or unique fuzzy match, or a tuple
        (error_message, candidates) on ambiguity / not found.
        """
        backends = list(self.backends.values())
        name_lower = name.lower().replace("_", "")

        # 1. Exact match on the /info "name" field
        exact = [b for b in backends if name_lower == b.info.get("name", "").lower()]
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            return (
                f"Multiple ports match program name exactly '{name}': "
                + self._fmt_candidates(exact),
                exact,
            )

        # 2. Substring match — match any of: name, the bare filename, or "FUN" prefix
        def _score(b: Backend) -> int:
            n = b.info.get("name", "").lower()
            score = 0
            if name_lower in n:
                score += 10
            # Match on filename part (after the last "-" or "/")
            parts = re.split(r"[/-]", n)
            for p in parts:
                if name_lower == p:
                    score += 5
                elif name_lower in p:
                    score += 2
            return score

        scored = [(b, _score(b)) for b in backends]
        scored = [(b, s) for b, s in scored if s > 0]
        scored.sort(key=lambda x: -x[1])

        if not scored:
            known = ", ".join(
                sorted(set(b.info.get("name", "?") for b in backends))
            )
            return (
                f"No program matching '{name}'. "
                f"Known programs: {known}" if known else
                "No GhidraMCP backends discovered. Is Ghidra running?"
            ), []

        # Best match, or ambiguous if tie on top score
        top_score = scored[0][1]
        top = [b for b, s in scored if s == top_score]
        if len(top) == 1:
            return top[0]
        else:
            return (
                f"Ambiguous program name '{name}' — matched {len(top)} candidates. "
                + self._fmt_candidates(top),
                top,
            )

    def _probe_one(self, port: int) -> Backend | None:
        url = f"http://{self.host}:{port}/"
        try:
            resp = requests.get(urljoin(url, "info"), timeout=2)
            if resp.ok:
                info = resp.json()
                name = info.get("name", "(no program)")
                date = info.get("datePrefix", "")
                label = f"{date} {name} @ {port}" if date else f"{name} @ {port}"
                return Backend(port=port, base_url=url, info=info, label=label)
        except requests.RequestException:
            pass
        return None

    @staticmethod
    def _fmt_candidates(backends: list[Backend]) -> str:
        parts = [f"{b.port}={b.info.get('name','?')} ({b.label})" for b in backends]
        return "; ".join(parts)


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP("ghidra-mcp-multi")

# Global scanner + client cache — populated in main()
_scanner: PortScanner | None = None
_client_cache: dict[int, GhidraClient] = {}


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class GhidraClient:
    """Thin HTTP wrapper around a single GhidraMCP backend."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/") + "/"

    def _get(self, endpoint: str, params: dict | None = None) -> dict:
        url = urljoin(self.base_url, endpoint)
        try:
            resp = requests.get(url, params=params or {}, timeout=30)
            resp.encoding = "utf-8"
            if not resp.ok:
                return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text.strip()}"}
            text = resp.text.strip()
            try:
                return {"ok": True, "data": resp.json()}
            except (ValueError, json.JSONDecodeError):
                return {"ok": True, "data": text.splitlines()}
        except requests.RequestException as e:
            return {"ok": False, "error": str(e)}

    def _post(self, endpoint: str, data: dict | str) -> dict:
        url = urljoin(self.base_url, endpoint)
        try:
            if isinstance(data, dict):
                resp = requests.post(url, data=data, timeout=60)
            else:
                resp = requests.post(url, data=data.encode("utf-8"), timeout=60)
            resp.encoding = "utf-8"
            if not resp.ok:
                return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text.strip()}"}
            text = resp.text.strip()
            try:
                return {"ok": True, "data": resp.json()}
            except (ValueError, json.JSONDecodeError):
                return {"ok": True, "data": text}
        except requests.RequestException as e:
            return {"ok": False, "error": str(e)}

    def _post_json(self, endpoint: str, data: dict | str) -> dict:
        result = self._post(endpoint, data)
        if result.get("ok") and not isinstance(result["data"], dict):
            if isinstance(result["data"], str):
                try:
                    result["data"] = json.loads(result["data"])
                except (ValueError, json.JSONDecodeError):
                    result = {"ok": False, "error": f"expected JSON from {endpoint}"}
        return result

    def info(self) -> dict:
        return self._get("info")

    def decompile(self, name: str | None = None, address: str | None = None) -> dict:
        if name:
            return self._post("decompile", name)
        if address:
            return self._get("decompile_function", {"address": address})
        return {"ok": False, "error": "decompile requires name or address"}

    def disasm(self, address: str) -> dict:
        return self._get("disassemble_function", {"address": address})

    def run_script(self, script_name: str | None = None,
                   script_body: str | None = None,
                   args: list[str] | None = None) -> dict:
        payload: dict = {}
        if script_name is not None:
            payload["script_name"] = script_name
        if script_body is not None:
            payload["script_body"] = script_body
        if args is not None:
            payload["args"] = "\n".join(args)
        if not script_name and not script_body:
            return {"ok": False, "error": "run_script requires script_name or script_body"}
        return self._post_json("run_script", payload)

    def search(self, query: str, offset: int = 0, limit: int = 100) -> dict:
        return self._get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

    def segments(self, offset: int = 0, limit: int = 100) -> dict:
        return self._get("segments", {"offset": offset, "limit": limit})

    def exports(self, offset: int = 0, limit: int = 100) -> dict:
        return self._get("exports", {"offset": offset, "limit": limit})

    def rename(self, old_name: str | None = None, address: str | None = None,
               new_name: str = "") -> dict:
        if old_name:
            return self._post("renameFunction",
                              {"oldName": old_name, "newName": new_name})
        if address:
            return self._post("rename_function_by_address",
                              {"function_address": address, "new_name": new_name})
        return {"ok": False, "error": "rename requires old_name or address"}


def _get_client(backend: Backend) -> GhidraClient:
    """Get or create a cached client for a backend."""
    if backend.port not in _client_cache:
        _client_cache[backend.port] = GhidraClient(backend.base_url)
    return _client_cache[backend.port]


def _resolve(args_kw: dict) -> tuple[Backend | None, str | None]:
    """
    Resolve a backend from ghidra_query arguments.
    Returns (backend, error_string). Exactly one is non-None.
    """
    assert _scanner is not None, "bridge not initialized"

    port = args_kw.get("port")
    program = args_kw.get("program")

    if port is not None and program is not None:
        return None, "Specify EITHER port (int) OR program (string), not both."
    if port is None and program is None:
        return None, "Specify either port (int) or program (string)."

    result: Backend | tuple[str, list[Backend]] | None = None

    if port is not None:
        result = _scanner.resolve_port(int(port))
        if result is None:
            return None, (
                f"Port {port} did not respond to /info. "
                f"Scan port range with ghidra_discover() first."
            )

    if program is not None:
        result = _scanner.resolve_program(str(program))

    if isinstance(result, tuple):
        msg, _ = result
        return None, msg

    return result, None


def _require(d: dict, key: str, action: str) -> str:
    val = d.get(key)
    if val is None:
        raise ValueError(
            f"action '{action}' requires '{key}' in args. "
            f"Pass e.g. {{\"{key}\": \"...\"}}"
        )
    return str(val)


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def ghidra_discover() -> dict:
    """
    Re-scan the GhidraMCP port range and report every live backend.

    Call this after Ghidra is started/restarted or after CodeBrowser windows
    are opened/closed to refresh the port-to-program mapping.  Returns a dict
    keyed by port with program name, build date, and tool name.

    Note: if the bridge was launched with ``--allow-date-prefix``, only
    backends matching that build date are reported — all others are filtered
    out to prevent cross-build contamination.
    """
    assert _scanner is not None
    backends = _scanner.scan()
    return {
        "ok": True,
        "data": {
            str(p): {
                "name": bk.info.get("name"),
                "datePrefix": bk.info.get("datePrefix"),
                "toolName": bk.info.get("toolName"),
                "label": bk.label,
                "host": _scanner.host,
            }
            for p, bk in sorted(backends.items())
        },
    }


@mcp.tool()
def ghidra_query(
    port: int | None = None,
    program: str | None = None,
    action: str | None = None,
    args: str | dict | None = None,
) -> dict:
    """
    Query any GhidraMCP backend through the multi-port bridge.

    IDENTIFY THE TARGET by EITHER:

        ``port`` (int) — the HTTP port the backend is bound to.
            e.g. ``port=8093``

        ``program`` (string) — fuzzy match against the program name.
            e.g. ``program="eqlib"``, ``program="eqgame.exe"``
            If the match is ambiguous (multiple ports), you get an error
            listing the candidates — try again with a more specific string
            or use ``port`` instead.

    ``action`` selects the operation:

        **info**       — program identity (no args needed)
        **decompile**  — decompile a function. Pass ``{"name":"FUN_..."}``
                         (by symbol name) **or** ``{"address":"0x140001000"}``
                         (by address).
        **disasm**     — get assembly for a function at an address.
                         Pass ``{"address":"0x140001000"}``.
        **run_script** — execute a Ghidra script. Pass
                         ``{"script_name":"ApplySig.py"}`` or
                         ``{"script_body":"print('hello')"}``.
        **search**     — search functions by name. Pass
                         ``{"query":"FUN_14"}``.
                         Optional: ``{"offset":0, "limit":100}``.
        **segments**   — list memory segments.
                         Optional: ``{"offset":0, "limit":100}``.
        **exports**    — list exported symbols.
                         Optional: ``{"offset":0, "limit":100}``.
        **rename**     — rename a function. Pass
                         ``{"old_name":"FUN_...", "new_name":"MyFunc"}``
                         (by old symbol name) **or**
                         ``{"address":"0x140001000", "new_name":"MyFunc"}``
                         (by address).

    ``args`` is a JSON-encoded string OR a pre-parsed dict with action-specific
    fields (see above). Both forms are accepted transparently.

    Returns ``{"ok":true, "data":<response>, "port":N, "program":"..."}``
    on success, or ``{"ok":false, "error":"..."}`` on failure.

    To re-scan after Ghidra restarts, call ``ghidra_discover()`` first.
    """
    if not action:
        return {"ok": False, "error": "action is required. See tool description."}

    backend, err = _resolve({"port": port, "program": program})
    if err:
        return {"ok": False, "error": err}
    assert backend is not None

    client = _get_client(backend)

    parsed_args: dict = {}
    if args:
        try:
            parsed_args = json.loads(args) if isinstance(args, str) else args
        except (ValueError, json.JSONDecodeError) as e:
            return {"ok": False, "error": f"args is not valid JSON: {e}"}
    if not isinstance(parsed_args, dict):
        return {"ok": False, "error": "args must be a JSON object (key-value pairs)"}

    try:
        action_map: dict[str, Callable[[], dict]] = {
            "info": lambda: client.info(),
            "decompile": lambda: client.decompile(
                name=parsed_args.get("name"),
                address=parsed_args.get("address"),
            ),
            "disasm": lambda: client.disasm(
                address=_require(parsed_args, "address", action),
            ),
            "run_script": lambda: client.run_script(
                script_name=parsed_args.get("script_name"),
                script_body=parsed_args.get("script_body"),
                args=parsed_args.get("args"),
            ),
            "search": lambda: client.search(
                query=_require(parsed_args, "query", action),
                offset=parsed_args.get("offset", 0),
                limit=parsed_args.get("limit", 100),
            ),
            "segments": lambda: client.segments(
                offset=parsed_args.get("offset", 0),
                limit=parsed_args.get("limit", 100),
            ),
            "exports": lambda: client.exports(
                offset=parsed_args.get("offset", 0),
                limit=parsed_args.get("limit", 100),
            ),
            "rename": lambda: client.rename(
                old_name=parsed_args.get("old_name"),
                address=parsed_args.get("address"),
                new_name=parsed_args.get("new_name", ""),
            ),
        }

        handler = action_map.get(action)
        if handler is None:
            valid = sorted(action_map)
            return {
                "ok": False,
                "error": f"Unknown action '{action}'. Valid: {valid}",
            }

        result: dict = handler()
        result.setdefault("port", backend.port)
        result.setdefault("program", backend.label)
        return result

    except Exception as e:
        logger.exception("ghidra_query failed")
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-port auto-discovering MCP bridge for GhidraMCP backends"
    )
    parser.add_argument("--mcp-host", default="127.0.0.1",
                        help="Host for SSE transport (default: 127.0.0.1)")
    parser.add_argument("--mcp-port", type=int, default=8081,
                        help="Port for SSE transport (default: 8081)")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse"],
                        help="MCP transport (default: stdio)")
    parser.add_argument("--ghidra-host", default="127.0.0.1",
                        help="Host where GhidraMCP backends run (default: 127.0.0.1)")
    parser.add_argument("--port-range", default="8090-8129",
                        help="Port range to probe, e.g. 8090-8129 (default)")
    parser.add_argument("--allow-date-prefix", default=None,
                        help="Only discover backends matching this build date "
                             "(e.g. '03-16-2026'). Prevents cross-build "
                             "contamination (FP-SWARM-008/019/020).")
    args = parser.parse_args()

    # Parse port range
    port_match = re.match(r"(\d+)-(\d+)", args.port_range)
    if not port_match:
        print(f"error: invalid port range '{args.port_range}'. Use e.g. 8090-8129",
              file=sys.stderr)
        sys.exit(1)
    port_start, port_end = int(port_match.group(1)), int(port_match.group(2))

    # Discover live backends
    global _scanner
    _scanner = PortScanner(
        host=args.ghidra_host,
        port_start=port_start,
        port_end=port_end,
        allowed_date_prefix=args.allow_date_prefix,
    )

    backends = _scanner.scan()
    if backends:
        logger.info(
            "Discovered %d GhidraMCP backend(s): %s",
            len(backends),
            {p: bk.info.get("name", "?") for p, bk in sorted(backends.items())},
        )
    else:
        logger.warning(
            "No GhidraMCP backends found on %s ports %s-%s. "
            "Is Ghidra running with the plugin?",
            args.ghidra_host,
            port_start,
            port_end,
        )

    logger.info(
        "Multi-port bridge ready on %s. Call ghidra_discover() to re-scan.",
        args.ghidra_host,
    )

    if args.transport == "sse":
        mcp.settings.host = args.mcp_host
        mcp.settings.port = args.mcp_port
        mcp.settings.log_level = "INFO"
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)
        logger.info("Starting SSE on http://%s:%d/sse", args.mcp_host, args.mcp_port)
        mcp.run(transport="sse")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
