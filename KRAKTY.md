# GhidraMCP-MultiProgram (Krakty fork)

Fork of [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) that
makes the plugin **per-tool**: each open Ghidra CodeBrowser window binds its
own HTTP server on a unique port, so MCP clients can address multiple loaded
programs in parallel without GUI program-switching.

Built and tested against **Ghidra 12.1** (previously 12.0.4 — see HANDOFF.md
for the upgrade record).

> **End-user docs live in [README.md](README.md).** This file is the design /
> decision log: architecture choices, gotchas, and history. Read README first
> for build / install / usage; come here for the *why*.

## Architecture (v0.2.x)

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
  "version":    "0.2.1",
  "port":       8090,
  "toolName":   "CodeBrowser",
  "name":       "05-22-2026-LIVE-eqgame.exe",
  "datePrefix": "05-22-2026"
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

## Build & install

See [README.md](README.md) for full build and install instructions. Short
version: copy eight JARs from your Ghidra 12.1 install into `lib/`, then
`mvn clean package`, then `File → Install Extensions` in Ghidra with the
resulting ZIP.

## Versioning

Two version numbers, deliberately separate:

- **Plugin version** (e.g. `0.2.1`) — tracks fork changes (features, fixes).
  Lives in `pom.xml` `<version>`, `extension.properties` `version=`, and
  `PLUGIN_VERSION` in the plugin source. Bump on every release.
- **Ghidra version** (e.g. `12.1`) — Ghidra release this build is compatible
  with. Lives in `extension.properties` `ghidraVersion=` and the eight
  `<version>` entries on the system-scoped dependencies in `pom.xml`. Bump
  only when migrating to a new Ghidra.

Ghidra silently drops any extension whose `ghidraVersion` doesn't match the
running Ghidra. `Help → Show Log` will reveal the mismatch.

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
- **v0.2.0**: Per-tool plugin, port-per-tool, no central coordination. Each
  CodeBrowser instance is independent. Slot abstraction removed (clients use
  `/info` for discovery instead). First Ghidra 12.0.4 build.
- **v0.2.1 (current)**:
  - Migrated build to **Ghidra 12.1** (was 12.0.4).
  - `/renameData` now creates a bare label when no `Data` is defined at the
    address (was a silent no-op in 0.2.0). Enables bulk-labeling tools to
    annotate symbols Ghidra's auto-analysis hasn't classified as data.

### Dead code from v0.1.x

`SlotAssigner.java`, `ProgramServer.java`, and the
`discoveryServer` / `registerProjectListener()` / `rebuildProgramServers()`
methods in `GhidraMCPMultiProgramPlugin.java` are leftovers from v0.1.x. They
compile but are **never called** from the plugin lifecycle — the per-tool
init in the constructor takes the only execution path. The
`@PluginInfo.description` string ("Discovery on 8089, slots on 8090-8095") is
also stale text from that era.

A future cleanup pass should remove them. Until then they're harmless but
misleading to readers exploring the codebase.
