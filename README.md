[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# GhidraMCP-MultiProgram (Krakty fork)

A [Model Context Protocol](https://modelcontextprotocol.io) server that lets LLM
clients (Claude Code, Claude Desktop, Cline, 5ire, etc.) drive Ghidra to
reverse-engineer binaries — **with one HTTP server bound per open CodeBrowser
tool**, so multiple programs loaded simultaneously can be addressed in parallel
without GUI program-switching.

Fork of [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP).
Plugin version **0.2.1**, built against **Ghidra 12.1**.

---

## Why this fork

Upstream `GhidraMCP` runs a single HTTP server (default port `8080`) scoped to
the program currently active in Ghidra's frontmost CodeBrowser. To analyze a
second program, you have to switch CodeBrowsers in the GUI, which is awkward
when an LLM is driving the session.

This fork makes the plugin **per-tool**: every CodeBrowser instance binds its
own HTTP server on the first free port in `8090–8099`. Each port serves the
same endpoint set as upstream, scoped to that tool's `getCurrentProgram()`. A
discovery endpoint (`/info`) on each port lets clients map ports → loaded
programs without any central coordinator.

```
                  ┌──────────────────────┐
                  │  Ghidra Project      │
                  │                      │
   CodeBrowser 1 ─┼─→ port 8090 ──┐      │
   CodeBrowser 2 ─┼─→ port 8091 ──┼──→ MCP clients hit any port,
   CodeBrowser 3 ─┼─→ port 8092 ──┘      use /info to discover
                  └──────────────────────┘
```

No JVM-wide singleton, no cross-tool listener, no central discovery server.
Each CodeBrowser is self-contained; closing one frees its port for the next
tool to open.

---

## Architecture

### Per-tool binding

The plugin is loaded once per `PluginTool` (Ghidra default behavior). On
startup, each instance:

1. Walks `8090 → 8099` and binds the first free port.
2. Fails silently and tries the next port on `BindException`.
3. If the entire range is taken, logs an error and stays inactive.
4. Otherwise registers the full endpoint set against `getCurrentProgram()` for
   that tool.

### `/info` discovery

Each bound port serves:

```http
GET /info
```

```json
{
  "version":    "0.2.1",
  "port":       8090,
  "toolName":   "CodeBrowser",
  "name":       "05-22-2026-LIVE-eqgame.exe",
  "datePrefix": "05-22-2026"
}
```

- `version` — plugin version (independent of Ghidra version).
- `port` — the port serving this response.
- `toolName` — `PluginTool.getName()` (e.g. `CodeBrowser`, `CodeBrowser(2)`).
- `name` — `DomainFile.getName()` from the Project tree, falling back to
  `Program.getName()`. This lets you give programs visually distinct names in
  the Project (e.g. date-prefixed patch builds) and have those names propagate
  to clients.
- `datePrefix` — `MM-DD-YYYY` extracted from the leading characters of `name`,
  or empty string if no date prefix.

Clients are expected to probe `/info` on every port in `8090–8099` and ignore
the ones that don't respond (connection refused = no tool bound there).

---

## Endpoint reference

All endpoints are served on every bound port. They operate on
`getCurrentProgram()` for the tool that owns that port. Most accept
`offset`/`limit` query params for pagination.

| Endpoint                       | Method | Purpose                              |
|--------------------------------|--------|--------------------------------------|
| `/info`                        | GET    | Discovery payload (see above)        |
| `/methods`                     | GET    | List all function names              |
| `/classes`                     | GET    | List class namespaces                |
| `/decompile`                   | POST   | Decompile function (by name)         |
| `/renameFunction`              | POST   | Rename function by old name          |
| `/renameData`                  | POST   | Rename data symbol at address        |
| `/renameVariable`              | POST   | Rename local var in a function       |
| `/segments`                    | GET    | List memory segments                 |
| `/imports`                     | GET    | List imported symbols                |
| `/exports`                     | GET    | List exported symbols                |
| `/namespaces`                  | GET    | List non-global namespaces           |
| `/data`                        | GET    | List defined data items              |
| `/searchFunctions`             | GET    | Substring search over function names |
| `/get_function_by_address`     | GET    | Function metadata at address         |
| `/get_current_address`         | GET    | Cursor address in the listing        |
| `/get_current_function`        | GET    | Function under cursor                |
| `/list_functions`              | GET    | All functions (full list)            |
| `/decompile_function`          | GET    | Decompile function by address        |
| `/disassemble_function`        | GET    | Disassembly listing by address       |
| `/set_decompiler_comment`      | POST   | Set decompiler comment               |
| `/set_disassembly_comment`     | POST   | Set EOL comment in disassembly       |
| `/rename_function_by_address`  | POST   | Rename function by address           |
| `/set_function_prototype`      | POST   | Apply function signature             |
| `/set_local_variable_type`     | POST   | Change a local variable's data type  |
| `/xrefs_to`                    | GET    | References to an address             |
| `/xrefs_from`                  | GET    | References out from an address       |
| `/function_xrefs`              | GET    | References involving a function      |
| `/strings`                     | GET    | Defined strings (`filter` supported) |

### `/renameData` (v0.2.1 change)

Previously a no-op when no `Data` was defined at the target address. Now also
creates a bare label when the address has no existing data definition,
enabling bulk-labeling tools to annotate addresses that Ghidra's auto-analysis
hasn't classified yet.

---

## Building

### Prerequisites

- **Ghidra 12.1** install (any platform). The build uses eight JARs from a
  real Ghidra install via Maven `system`-scoped dependencies.
- **Java 26** (`/usr/lib/jvm/java-26-openjdk` on Arch).
- **Maven** ≥ 3.9.

### Refresh `lib/`

`lib/` is `.gitignored` — each developer maintains their own local copy of the
eight Ghidra JARs the build depends on. Copy them from your Ghidra install:

```sh
cd lib/
GHIDRA=/opt/ghidra
cp $GHIDRA/Ghidra/Framework/Generic/lib/Generic.jar .
cp $GHIDRA/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar .
cp $GHIDRA/Ghidra/Framework/Project/lib/Project.jar .
cp $GHIDRA/Ghidra/Framework/Docking/lib/Docking.jar .
cp $GHIDRA/Ghidra/Features/Decompiler/lib/Decompiler.jar .
cp $GHIDRA/Ghidra/Framework/Utility/lib/Utility.jar .
cp $GHIDRA/Ghidra/Features/Base/lib/Base.jar .
cp $GHIDRA/Ghidra/Framework/Gui/lib/Gui.jar .
```

If the host running Ghidra is on a different machine, `scp` from there — and
verify md5s match if you're sharing a build host. Ghidra's API drift between
point releases is real, so build against the *exact* Ghidra version you intend
to deploy to.

### Build

```sh
JAVA_HOME=/usr/lib/jvm/java-26-openjdk mvn clean package
```

Outputs in `target/`:

- `GhidraMCPMultiProgram.jar` — runtime JAR.
- `GhidraMCPMultiProgram-<pluginVersion>.zip` — Ghidra-installable extension
  (e.g. `GhidraMCPMultiProgram-0.2.1.zip`).

### Bumping versions for a new build

| Where                                           | Field           | What it tracks                          |
|-------------------------------------------------|-----------------|------------------------------------------|
| `pom.xml`                                       | `<version>`     | Plugin version, drives ZIP filename     |
| `src/main/resources/extension.properties`       | `version`       | Plugin version (mirror of pom)          |
| `src/main/resources/extension.properties`       | `ghidraVersion` | **Ghidra** version, gates install       |
| `GhidraMCPMultiProgramPlugin.java`              | `PLUGIN_VERSION`| Shown in `/info` and Ghidra console log |

Plugin version (`0.2.1`, `0.2.2`, etc.) and Ghidra version (`12.1`, `12.2`) are
intentionally separate — they cycle on different cadences. Ghidra silently
rejects any extension whose `ghidraVersion` doesn't match the running Ghidra;
that's the most common cause of "plugin installed but no port binds".

The eight Ghidra dependency `<version>` entries in `pom.xml` should also match
the Ghidra version you built `lib/` against.

### Critical ZIP structure

Ghidra's classfinder silently drops extensions whose ZIP layout doesn't match
exactly:

```
GhidraMCPMultiProgram/
├── Module.manifest                              # MODULE DIR: lib/GhidraMCPMultiProgram.jar
├── extension.properties
└── lib/
    └── GhidraMCPMultiProgram.jar                # filename MUST equal module dir name
```

Two gotchas that have cost hours:

1. **`Module.manifest` format.** Must use `MODULE DIR:`. The
   `GHIDRA_MODULE_NAME=` key-value variant works in some Ghidra versions but
   fails silently in 12.x.
2. **JAR filename must equal the module dir name.** `GhidraMCPMultiProgram.jar`
   works; `GhidraMCP-MultiProgram.jar` (with hyphen) does not — classfinder
   skips it without logging.

The `pom.xml` and `src/assembly/ghidra-extension.xml` here are configured
correctly. Don't change `artifactId`, `finalName`, or the assembly descriptor
without re-verifying the ZIP layout.

---

## Installing in Ghidra

### Option A — `deploy_plugin.sh` (recommended for repeat deploys)

`deploy_plugin.sh` builds the ZIP, **reads the running Ghidra's version from
the target host**, patches `extension.properties` `ghidraVersion=` to match,
and unzips into the correct `~/.config/ghidra/ghidra_<version>_DEV/Extensions/`
dir over SSH. Use this so you don't have to bump `ghidraVersion=` in the repo
for every Ghidra patch release.

```sh
./deploy_plugin.sh [--host HOST] [--ghidra-install PATH] [--no-build] [--clean-stale]
```

- Default `--host` is `your-ghidra-host`; override for your setup.
- Default `--ghidra-install` is `/opt/ghidra`.
- `--no-build` reuses the existing `target/*.zip`.
- `--clean-stale` deletes any `GhidraMCPMultiProgram` dirs under
  `~/.config/ghidra/ghidra_*_DEV/Extensions/` whose version isn't the one
  you're deploying — keeps the host tidy after Ghidra patches.

The script refuses to run if Ghidra is currently running on the target (the
JVM holds the extension JAR open and installs would silently fail). Close
Ghidra first; restart it after the script finishes.

### Option B — Ghidra GUI installer

1. `File → Install Extensions`
2. Click **`+`** and select `target/GhidraMCPMultiProgram-<version>.zip`
3. **Restart Ghidra**. The plugin loads automatically under the **Developer**
   category.
4. On first launch, Ghidra may prompt to configure the plugin in any open
   tool — accept.
5. Open one or more programs in CodeBrowser windows.

To upgrade: install the new ZIP on top; Ghidra warns about the existing
extension, removes it on restart, and installs the new one.

**Caveat**: this path won't help you across Ghidra patch versions unless you
also bump `extension.properties` `ghidraVersion=` and rebuild. Use
`deploy_plugin.sh` to skip that step.

### Verifying it's running

From a machine on the same network as the host running Ghidra:

```sh
nmap -Pn -sT -p 8090-8099 <ghidra-host>
```

Then probe each open port:

```sh
for p in 8090 8091 8092 8093 8094 8095 8096 8097 8098 8099; do
  curl -s --max-time 3 "http://<ghidra-host>:$p/info" && echo
done
```

You should see one `/info` JSON per open CodeBrowser.

---

## MCP bridge (`bridge_mcp_ghidra.py`)

The Python bridge translates MCP tool calls into HTTP requests against the
plugin. It's a thin client — no business logic — and pairs one-to-one with a
plugin endpoint per MCP tool.

### Program-identity announcement

At startup the bridge hits `/info` on its target port, builds a label of the
form `MM-DD-YYYY program.ext @ <port>`, and stamps it into every tool's
description plus the MCP `serverInfo.name`. With one bridge per port, an LLM
client running against six bridges sees six distinctly labeled tool catalogs
instead of six indistinguishable `ghidra-*` blocks, so it can answer
"decompile X in the 06-09 eqgame build" without manual port juggling.

Also exposes a `program_info` MCP tool that returns the cached label + raw
`/info` payload for mid-session self-discovery.

If `/info` is unreachable at startup (Ghidra not running on that port), the
label falls back to `<url> (offline)` and the bridge still serves — endpoint
calls will surface the unreachable upstream individually.

### Transports

- `--transport stdio` (default) — MCP clients spawn the bridge per session.
- `--transport sse` — long-running server on `--mcp-host:--mcp-port`, for
  clients that want a shared connection (e.g. Cline's Remote Servers).

### CLI

```sh
python bridge_mcp_ghidra.py \
  --ghidra-server http://<host>:<port>/ \
  [--transport {stdio,sse}] \
  [--mcp-host 127.0.0.1] \
  [--mcp-port 8081]
```

### Setup

The bridge needs the [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk):

```sh
python -m venv .venv
. .venv/bin/activate
pip install "mcp[cli]" requests
```

### Deploying the bridge locally

`deploy_bridge.sh` copies `bridge_mcp_ghidra.py` from the repo into
`~/.claude/mcp-servers/ghidra-mcp/` (where the venv lives). Use it after
editing the bridge:

```sh
./deploy_bridge.sh
```

The script does not deploy the Java JAR — that's a separate step (see
"Installing in Ghidra" above).

---

## MCP client configuration

Run one bridge instance per port you want to expose. The pattern is identical
across clients — only the config file location and JSON envelope differ.

### Claude Code

Per-project `.mcp.json`:

```json
{
  "mcpServers": {
    "ghidra-8090": {
      "command": "/path/to/.venv/bin/python",
      "args": [
        "/path/to/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8090/"
      ]
    },
    "ghidra-8091": {
      "command": "/path/to/.venv/bin/python",
      "args": [
        "/path/to/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8091/"
      ]
    }
  }
}
```

Replicate for every port you care about. Bridges pointed at ports without an
active CodeBrowser error per-call but are otherwise harmless — Claude
continues to use the working ones.

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or
`%APPDATA%\Claude\claude_desktop_config.json` (Windows). Same envelope as
above.

### Cline

Run the bridge as a long-lived SSE server:

```sh
python bridge_mcp_ghidra.py \
  --transport sse \
  --mcp-host 127.0.0.1 \
  --mcp-port 8081 \
  --ghidra-server http://127.0.0.1:8090/
```

Then in Cline: **MCP Servers → Remote Servers → Add**

- Name: `GhidraMCP-8090`
- URL: `http://127.0.0.1:8081/sse`

### 5ire

**Tools → New**:

- Tool Key: `ghidra-8090`
- Name: `GhidraMCP 8090`
- Command: `/path/to/.venv/bin/python /path/to/bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8090/`

---

## Versioning model

There are deliberately two version numbers:

- **Plugin version** (currently `0.2.1`) — tracks our own changes (features,
  fixes, refactors). Lives in `pom.xml`, `extension.properties` `version=`,
  and `PLUGIN_VERSION` in the plugin source. Cycles with each release of the
  fork.
- **Ghidra version** (currently `12.1`) — the Ghidra release this build is
  *compatible* with. Lives in `extension.properties` `ghidraVersion=` and the
  eight dependency entries in `pom.xml`. Cycles only when Ghidra itself
  upgrades.

Mismatching `ghidraVersion` against the running Ghidra causes Ghidra to drop
the extension silently — `Help → Show Log` will note the mismatch. Ghidra
performs **exact string equality** on `ghidraVersion`, so a build pinned to
`12.1` won't load on `12.1.2`. To avoid bumping the repo on every patch
release, use `deploy_plugin.sh` (see "Installing in Ghidra"); it patches the
shipped `extension.properties` on the fly from the target host's installed
Ghidra version.

---

## Troubleshooting

**No ports bind in 8090–8099.**
Almost always an `extension.properties` `ghidraVersion` mismatch. Check
`Help → Show Log` in Ghidra for "extension not compatible". Rebuild `lib/`
and bump versions to match.

**Plugin loads but some ports remain closed.**
Expected — there's one port per *open CodeBrowser*. Closed CodeBrowsers free
their port for the next tool that opens.

**`/info` returns but other endpoints fail.**
Probably no program is loaded in that CodeBrowser yet. The plugin binds the
port at tool-start, but endpoints that touch `getCurrentProgram()` only work
once a program is open.

**`renameData` reports success but no symbol appears.**
v0.2.0 silently dropped renames on addresses without existing `Data`
definitions. v0.2.1+ creates a bare label in that case. If you're on 0.2.0,
upgrade.

---

## Project layout

```
.
├── pom.xml                          # Maven build, Ghidra dep versions
├── lib/                             # gitignored — eight Ghidra JARs you supply
├── src/
│   ├── main/
│   │   ├── java/com/krakty/ghidramcp/
│   │   │   └── GhidraMCPMultiProgramPlugin.java    # plugin entry + all endpoints
│   │   └── resources/
│   │       ├── extension.properties                # version + ghidraVersion
│   │       ├── Module.manifest                     # MODULE DIR directive
│   │       └── META-INF/MANIFEST.MF
│   ├── assembly/
│   │   └── ghidra-extension.xml                    # produces the install ZIP
│   └── test/                                       # placeholder JUnit
├── bridge_mcp_ghidra.py             # Python MCP bridge (FastMCP)
├── deploy_bridge.sh                 # copy bridge to ~/.claude/mcp-servers/
├── deploy_plugin.sh                 # build + push Java JAR to remote Ghidra host
├── KRAKTY.md                        # fork architecture notes / decision log
├── HANDOFF.md                       # historical: Ghidra 12.0.4 → 12.1 upgrade
└── README.md                        # this file
```

---

## Credits

- Upstream: [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) —
  the original single-port plugin and the bridge skeleton.
- Krakty fork: per-tool architecture, `/info` discovery, multi-program
  workflow.

Licensed under Apache 2.0 (inherited from upstream).
