# GhidraMCP-MultiProgram (Krakty fork)

Fork of [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) that
makes the plugin **per-tool**: each open Ghidra CodeBrowser window binds its
own HTTP server on a unique port, so MCP clients can address multiple loaded
programs in parallel without GUI program-switching.

Built and tested against **Ghidra 12.0.4**.

## Architecture (v0.2.0)

The plugin is loaded once per `PluginTool` instance (Ghidra default behavior;
each CodeBrowser window is its own tool). On startup, each instance:

1. Tries to bind an HTTP server to the first free port in **8090-8099**.
2. Fails silently and tries the next port if a port is already taken.
3. Exposes the upstream endpoint set (`/methods`, `/decompile`, etc.) plus a
   new `/info` endpoint, all operating on `getCurrentProgram()` — which is
   naturally scoped to that tool.

There is no JVM-wide singleton, no central discovery server, no cross-tool
event listener. Each instance is self-contained.

### `/info` endpoint

Each port serves a JSON discovery payload:

```json
GET /info
{
  "version":    "0.2.0",
  "port":       8090,
  "toolName":   "CodeBrowser",
  "name":       "05-01-2026-LIVE-eqgame.exe",
  "datePrefix": "05-01-2026"
}
```

- `version` is the plugin version (separate from Ghidra version).
- `name` is the **DomainFile name** as shown in the Project tree, falling
  back to `Program.getName()` if no DomainFile is available. This lets you
  give programs visually distinct names in the Project (e.g., date-prefixed)
  and have those reflected in the discovery output.
- `datePrefix` is `MM-DD-YYYY` extracted from the start of `name`, or empty.

Clients (MCP bridge, Claude, scripts) discover what's bound by hitting
`/info` on each port in 8090-8099 and ignoring the ones that don't respond.

## Build

Requires Ghidra 12.0.4 jars in `lib/`. Copy them from your installation:

```sh
cd lib/
for j in Generic SoftwareModeling Project Docking Decompiler Utility Base Gui; do
  find /opt/ghidra/Ghidra -name "${j}.jar" -exec cp {} . \;
done
```

Then:

```sh
mvn clean package
```

Output: `target/GhidraMCPMultiProgram-<version>.zip` (e.g.,
`GhidraMCPMultiProgram-0.2.0.zip`).

## Install

In Ghidra: **File → Install Extensions → +** → select the zip → restart
Ghidra. The plugin loads automatically (it's in the Developer category).

To upgrade: install the new zip on top of the existing one. Ghidra will
warn about an existing extension and prompt to remove on restart, then
install the new one. Restart Ghidra.

## MCP client configuration

`.mcp.json` should have one entry per port in the range, all pointed at the
laptop running Ghidra:

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
    "ghidra-8091": { "...": "(same with 8091)" }
  }
}
```

Ports without an active CodeBrowser instance error out per call but are
otherwise harmless — Claude can still use the active ones.

## Versioning

- `pom.xml` `<version>` drives the zip filename.
- `extension.properties` has TWO version fields:
  - `version=12.0.4` is the Ghidra compatibility version (must match
    installed Ghidra; mismatch causes the install to be rejected).
  - `ghidraVersion=12.0.4` is the same.
- `PLUGIN_VERSION` static in `GhidraMCPMultiProgramPlugin.java` is shown in
  startup logs and the `/info` response.

When iterating, bump the pom version + `PLUGIN_VERSION` constant. Do **not**
change `version=`/`ghidraVersion=` in `extension.properties` — those reflect
Ghidra's version, not ours.

## Critical extension.zip structure

For Ghidra to actually discover the plugin, the zip must follow this exact
structure (mismatches cause silent classfinder failures):

```
GhidraMCPMultiProgram/
├── Module.manifest        # contains: MODULE DIR: lib/GhidraMCPMultiProgram.jar
├── extension.properties
└── lib/
    └── GhidraMCPMultiProgram.jar    # filename MUST match module dir name
```

Two gotchas that cost hours during development:

1. **Module.manifest format.** It must use the `MODULE DIR:` directive
   pointing at the JAR. The `GHIDRA_MODULE_NAME=` / `GHIDRA_MODULE_DESC=`
   key=value format works in some Ghidra versions but failed silently for us
   in 12.0.4.
2. **JAR name must match module dir name.** `GhidraMCPMultiProgram/lib/GhidraMCPMultiProgram.jar`
   works. `GhidraMCPMultiProgram/lib/GhidraMCP-MultiProgram.jar` (with hyphen)
   does NOT — Ghidra's classfinder skips it silently.

The pom + assembly XML in this repo are configured correctly. Don't change
the artifactId or finalName values without verifying the resulting zip
structure matches the above.

## Origin and history

Original: LaurieWired/GhidraMCP (single-port, single-program, scoped to the
active tool's program). Krakty fork started 2026-05-01.

Architecture iterations during development:

- **v0.1.x (abandoned)**: JVM-singleton plugin owning multiple HTTP servers
  for slot-by-binary-name addressing (one port per binary type, with
  date-prefix sorting for current vs old). Failed because Ghidra plugin
  events are tool-scoped and cross-tool tracking required brittle
  `DomainFolderChangeListener` plumbing. Ended with split state when the
  plugin was loaded in multiple tools.
- **v0.2.0 (current)**: Per-tool plugin, port-per-tool, no central
  coordination. Each CodeBrowser instance is independent. Slot abstraction
  removed (clients use `/info` for discovery instead).
