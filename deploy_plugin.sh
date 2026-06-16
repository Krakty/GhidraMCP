#!/usr/bin/env bash
# Deploy GhidraMCPMultiProgram extension to a host running Ghidra.
#
# This script lets us ship the plugin to any Ghidra patch release without
# bumping `ghidraVersion=` in extension.properties for every patch — it reads
# the running Ghidra's actual version from the install and patches the
# extension ZIP's properties at deploy time.
#
# Usage:
#   ./deploy_plugin.sh [--host HOST | --local] [--ghidra-install PATH]
#                      [--no-build] [--clean-stale]
#                      [--release vX.Y.Z | --stable]
#
#   --host HOST            SSH host to deploy to. Default: your-ghidra-host
#   --local                Deploy to THIS machine (no SSH). Cannot combine
#                          with --host.
#   --ghidra-install PATH  Ghidra install dir on the target. Default: /opt/ghidra
#   --no-build             Skip `mvn clean package`; use existing target/ ZIP.
#   --clean-stale          Remove ~/.config/ghidra/ghidra_*_DEV/Extensions/GhidraMCPMultiProgram
#                          directories on the target whose version is NOT the
#                          current Ghidra version. Prevents version drift.
#   --release vX.Y.Z       Download the GitHub Release artifact for the given
#                          tag and deploy that instead of the local target/.
#                          Requires gh CLI auth. Implies --no-build.
#                          Use this when you need a known-good fallback.
#   --stable               Like --release but fetches whatever the latest
#                          published release is. Best "panic button" mode.
#
# Side effects:
#   - Refuses to run if Ghidra is currently running on the target (the JVM
#     locks the extension files; install would silently fail). Headless
#     analyzer processes do not block the deploy.
#   - Removes any prior GhidraMCPMultiProgram dir for the current Ghidra
#     version before unzipping fresh (idempotent re-deploy).
#
# Companion to deploy_bridge.sh, which handles the Python MCP bridge.
# Java JAR deployment is handled here; the two are independent.

set -euo pipefail

# ---- helpers (local vs remote) --------------------------------------------

copy_to_target() { local src="$1" dst="$2"; if (( LOCAL )); then cp "$src" "$dst"; else scp -q "$src" "$HOST:$dst"; fi; }
run_target()     { if (( LOCAL )); then eval "$*"; else ssh "$HOST" "$*"; fi; }

# ---- args -----------------------------------------------------------------

HOST="your-ghidra-host"
LOCAL=0
GHIDRA_INSTALL="/opt/ghidra"
DO_BUILD=1
CLEAN_STALE=0
RELEASE_TAG=""        # if set, fetch from GitHub Release instead of target/
RELEASE_REPO="Krakty/GhidraMCP"

while (( $# )); do
    case "$1" in
        --host)            HOST="$2"; LOCAL=0; shift 2 ;;
        --local)           LOCAL=1; shift ;;
        --ghidra-install)  GHIDRA_INSTALL="$2"; shift 2 ;;
        --no-build)        DO_BUILD=0; shift ;;
        --clean-stale)     CLEAN_STALE=1; shift ;;
        --release)         RELEASE_TAG="$2"; DO_BUILD=0; shift 2 ;;
        --stable)          RELEASE_TAG="latest"; DO_BUILD=0; shift ;;
        -h|--help)
            sed -n '2,36p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

TARGET_LABEL="$HOST"
(( LOCAL )) && TARGET_LABEL="localhost"

# ---- detect Ghidra version on target --------------------------------------

echo ">> detecting Ghidra on $TARGET_LABEL:$GHIDRA_INSTALL"
APP_PROPS="$GHIDRA_INSTALL/Ghidra/application.properties"

PROPS_RAW="$(run_target "cat '$APP_PROPS' 2>/dev/null" || true)"
if [[ -z "$PROPS_RAW" ]]; then
    echo "ERROR: could not read $TARGET_LABEL:$APP_PROPS" >&2
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

if run_target 'ps -eo cmd | grep -E "ghidra\.GhidraRun" | grep -v grep >/dev/null'; then
    echo "ERROR: Ghidra is currently running on $TARGET_LABEL. Close it first." >&2
    exit 1
fi

# ---- build OR fetch a release artifact ------------------------------------

ZIP=""
if [[ -n "$RELEASE_TAG" ]]; then
    # Stable / specific-release mode: fetch from GitHub instead of building.
    command -v gh >/dev/null \
        || { echo "ERROR: --release/--stable needs the gh CLI (not found)." >&2; exit 3; }
    REL_DIR="$(mktemp -d)"
    trap 'rm -rf "$REL_DIR"' EXIT INT TERM
    if [[ "$RELEASE_TAG" == "latest" ]]; then
        echo ">> fetching latest published release from $RELEASE_REPO"
        gh release download -R "$RELEASE_REPO" \
            --pattern 'GhidraMCPMultiProgram-*.zip' --dir "$REL_DIR" \
            || { echo "ERROR: gh release download failed" >&2; exit 3; }
    else
        echo ">> fetching release $RELEASE_TAG from $RELEASE_REPO"
        gh release download "$RELEASE_TAG" -R "$RELEASE_REPO" \
            --pattern 'GhidraMCPMultiProgram-*.zip' --dir "$REL_DIR" \
            || { echo "ERROR: gh release download $RELEASE_TAG failed" >&2; exit 3; }
    fi
    ZIP="$(ls "$REL_DIR"/GhidraMCPMultiProgram-*.zip 2>/dev/null | head -1)"
    if [[ -z "$ZIP" || ! -f "$ZIP" ]]; then
        echo "ERROR: no zip downloaded from the release." >&2
        exit 3
    fi
    echo ">> downloaded release ZIP: $ZIP"
else
    if (( DO_BUILD )); then
        echo ">> mvn clean package"
        JAVA_HOME=${JAVA_HOME:-/path/to/your/jdk} mvn -q clean package
    fi
    # Find the built ZIP (filename includes plugin version, which we don't want
    # to hardcode here).
    ZIP="$(ls -t "$REPO_DIR"/target/GhidraMCPMultiProgram-*.zip 2>/dev/null | head -1)"
    if [[ -z "$ZIP" || ! -f "$ZIP" ]]; then
        echo "ERROR: no GhidraMCPMultiProgram-*.zip in target/. Run with build enabled." >&2
        exit 1
    fi
    echo ">> using local ZIP: $ZIP"
fi

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

echo ">> deploying to $TARGET_LABEL"
copy_to_target "$PATCHED_ZIP" "/tmp/GhidraMCPMultiProgram-deploy.zip"

run_target "
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
    run_target "
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

echo ">> done."
if (( LOCAL )); then
    echo "   Start Ghidra and open CodeBrowsers; verify with:"
    echo "     nmap -Pn -sT -p 8090-8099 localhost"
else
    echo "   Start Ghidra on $HOST and open the CodeBrowsers; verify with:"
    echo "     nmap -Pn -sT -p 8090-8099 $HOST"
fi
