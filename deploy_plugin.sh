#!/usr/bin/env bash
# Deploy GhidraMCPMultiProgram extension to a host running Ghidra.
#
# This script lets us ship the plugin to any Ghidra patch release without
# bumping `ghidraVersion=` in extension.properties for every patch — it reads
# the running Ghidra's actual version from the install and patches the
# extension ZIP's properties at deploy time.
#
# Usage:
#   ./deploy_plugin.sh [--host HOST] [--ghidra-install PATH] [--no-build] [--clean-stale]
#
#   --host HOST            SSH host to deploy to. Default: your-ghidra-host
#   --ghidra-install PATH  Ghidra install dir on the target. Default: /opt/ghidra
#   --no-build             Skip `mvn clean package`; use existing target/ ZIP.
#   --clean-stale          Remove ~/.config/ghidra/ghidra_*_DEV/Extensions/GhidraMCPMultiProgram
#                          directories on the target whose version is NOT the
#                          current Ghidra version. Prevents version drift.
#
# Side effects:
#   - Refuses to run if Ghidra is currently running on the target (the JVM
#     locks the extension files; install would silently fail).
#   - Removes any prior GhidraMCPMultiProgram dir for the current Ghidra
#     version before unzipping fresh (idempotent re-deploy).
#
# Companion to deploy_bridge.sh, which handles the Python MCP bridge.
# Java JAR deployment is handled here; the two are independent.

set -euo pipefail

# ---- args -----------------------------------------------------------------

HOST="your-ghidra-host"
GHIDRA_INSTALL="/opt/ghidra"
DO_BUILD=1
CLEAN_STALE=0

while (( $# )); do
    case "$1" in
        --host)            HOST="$2"; shift 2 ;;
        --ghidra-install)  GHIDRA_INSTALL="$2"; shift 2 ;;
        --no-build)        DO_BUILD=0; shift ;;
        --clean-stale)     CLEAN_STALE=1; shift ;;
        -h|--help)
            sed -n '2,28p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

# ---- detect Ghidra version on target --------------------------------------

echo ">> detecting Ghidra on $HOST:$GHIDRA_INSTALL"
APP_PROPS="$GHIDRA_INSTALL/Ghidra/application.properties"

PROPS_RAW="$(ssh "$HOST" "cat '$APP_PROPS' 2>/dev/null" || true)"
if [[ -z "$PROPS_RAW" ]]; then
    echo "ERROR: could not read $HOST:$APP_PROPS" >&2
    echo "       pass --ghidra-install <path> if Ghidra is installed elsewhere." >&2
    exit 1
fi

GHIDRA_VERSION="$(echo "$PROPS_RAW" | grep '^application\.version=' | cut -d= -f2)"
GHIDRA_BUILD_TYPE="$(echo "$PROPS_RAW" | grep '^application\.release\.name=' | cut -d= -f2 | tr 'a-z' 'A-Z')"

if [[ -z "$GHIDRA_VERSION" ]]; then
    echo "ERROR: no application.version in $APP_PROPS" >&2
    exit 1
fi

# _DEV (source/Arch builds) vs _PUBLIC (official ZIP releases). Falls back to DEV.
case "$GHIDRA_BUILD_TYPE" in
    PUBLIC) USER_DIR_SUFFIX="PUBLIC" ;;
    *)      USER_DIR_SUFFIX="DEV" ;;
esac

EXT_PARENT="\$HOME/.config/ghidra/ghidra_${GHIDRA_VERSION}_${USER_DIR_SUFFIX}/Extensions"
echo "   version:  $GHIDRA_VERSION ($USER_DIR_SUFFIX)"
echo "   target:   $EXT_PARENT"

# ---- refuse if Ghidra running ---------------------------------------------

if ssh "$HOST" 'ps -eo cmd | grep -E "ghidra\.GhidraRun" | grep -v grep >/dev/null'; then
    echo "ERROR: Ghidra is currently running on $HOST. Close it first." >&2
    exit 1
fi

# ---- build (optional) -----------------------------------------------------

if (( DO_BUILD )); then
    echo ">> mvn clean package"
    JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-26-openjdk} mvn -q clean package
fi

# Find the built ZIP (filename includes plugin version, which we don't want to
# hardcode here).
ZIP="$(ls -t "$REPO_DIR"/target/GhidraMCPMultiProgram-*.zip 2>/dev/null | head -1)"
if [[ -z "$ZIP" || ! -f "$ZIP" ]]; then
    echo "ERROR: no GhidraMCPMultiProgram-*.zip in target/. Run with build enabled." >&2
    exit 1
fi
echo ">> using ZIP: $ZIP"

# ---- patch ghidraVersion in the ZIP ---------------------------------------
# extension.properties inside the ZIP gets ghidraVersion=<detected> so Ghidra
# doesn't reject the extension on the patch-version gate. The in-repo file is
# left alone — only the deployed artifact is patched.

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

unzip -q "$ZIP" -d "$WORK"
PROPS="$WORK/GhidraMCPMultiProgram/extension.properties"
if [[ ! -f "$PROPS" ]]; then
    echo "ERROR: extension.properties not found inside ZIP" >&2
    exit 1
fi

CURRENT_GV="$(grep '^ghidraVersion=' "$PROPS" | cut -d= -f2)"
if [[ "$CURRENT_GV" != "$GHIDRA_VERSION" ]]; then
    echo ">> patching extension.properties ghidraVersion: $CURRENT_GV -> $GHIDRA_VERSION"
    sed -i "s/^ghidraVersion=.*/ghidraVersion=$GHIDRA_VERSION/" "$PROPS"
fi

PATCHED_ZIP="$WORK/GhidraMCPMultiProgram-deploy.zip"
( cd "$WORK" && zip -qr "$PATCHED_ZIP" GhidraMCPMultiProgram )

# ---- deploy ---------------------------------------------------------------

echo ">> deploying to $HOST"
scp -q "$PATCHED_ZIP" "$HOST:/tmp/GhidraMCPMultiProgram-deploy.zip"

ssh "$HOST" "
    set -e
    mkdir -p $EXT_PARENT
    rm -rf $EXT_PARENT/GhidraMCPMultiProgram
    unzip -q /tmp/GhidraMCPMultiProgram-deploy.zip -d $EXT_PARENT/
    rm /tmp/GhidraMCPMultiProgram-deploy.zip
    echo '   deployed: '\$(ls -d $EXT_PARENT/GhidraMCPMultiProgram)
    cat $EXT_PARENT/GhidraMCPMultiProgram/extension.properties | grep -E '^(version|ghidraVersion)='
"

# ---- clean stale (optional) -----------------------------------------------

if (( CLEAN_STALE )); then
    echo ">> sweeping stale GhidraMCPMultiProgram dirs from other Ghidra versions"
    ssh "$HOST" "
        for d in \$HOME/.config/ghidra/ghidra_*_${USER_DIR_SUFFIX}/Extensions/GhidraMCPMultiProgram; do
            [ -d \"\$d\" ] || continue
            ver=\$(echo \"\$d\" | sed -nE 's|.*/ghidra_(.*)_${USER_DIR_SUFFIX}/.*|\1|p')
            if [ \"\$ver\" != \"$GHIDRA_VERSION\" ]; then
                echo \"   removing stale: \$d\"
                rm -rf \"\$d\"
            fi
        done
    "
fi

echo ">> done. Start Ghidra on $HOST and open the CodeBrowsers; verify with:"
echo "   nmap -Pn -sT -p 8090-8099 $HOST"
