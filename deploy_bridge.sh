#!/usr/bin/env bash
# Deploy bridge_mcp_ghidra.py from this repo (source of truth) to the MCP
# runtime location used by Claude Code per project .mcp.json files.
#
# Repo: /path/to/ghidra-mcp/ (this dir)
# Runtime: ~/.claude/mcp-servers/ghidra-mcp/
#   - bridge_mcp_ghidra.py (deployed copy this script writes)
#   - .venv/                (python venv consumed by .mcp.json)
#
# Java plugin (target/GhidraMCPMultiProgram.jar) is deployed separately to
# Ghidra's Extensions/ dir on whichever host is running Ghidra; that's not
# handled here.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="$HOME/.claude/mcp-servers/ghidra-mcp"
SRC="$REPO_DIR/bridge_mcp_ghidra.py"
DST="$RUNTIME_DIR/bridge_mcp_ghidra.py"

[ -f "$SRC" ] || { echo "ERROR: source bridge not found at $SRC" >&2; exit 1; }
[ -d "$RUNTIME_DIR" ] || { echo "ERROR: runtime dir missing: $RUNTIME_DIR" >&2; exit 1; }

if [ -f "$DST" ] && cmp -s "$SRC" "$DST"; then
  echo "no change: $DST already matches repo"
  exit 0
fi

cp "$SRC" "$DST"
echo "deployed: $SRC -> $DST"
