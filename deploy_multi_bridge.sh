#!/usr/bin/env bash
# Deploy bridge_mcp_ghidra_multi.py from repo to MCP runtime location.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="$HOME/.claude/mcp-servers/ghidra-mcp"
SRC="$REPO_DIR/bridge_mcp_ghidra_multi.py"
DST="$RUNTIME_DIR/bridge_mcp_ghidra_multi.py"

[ -f "$SRC" ] || { echo "ERROR: source bridge not found at $SRC" >&2; exit 1; }
[ -d "$RUNTIME_DIR" ] || { echo "ERROR: runtime dir missing: $RUNTIME_DIR" >&2; exit 1; }

if [ -f "$DST" ] && cmp -s "$SRC" "$DST"; then
  echo "no change: $DST already matches repo"
  exit 0
fi

cp "$SRC" "$DST"
echo "deployed: $SRC -> $DST"
