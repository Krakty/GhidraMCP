# GhidraMCP-MultiProgram (Krakty fork)

Fork of [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) that
makes the plugin **per-tool**: each open Ghidra CodeBrowser window binds its
own HTTP server on a unique port, so MCP clients can address multiple loaded
programs in parallel without GUI program-switching.

Built and tested against **Ghidra 12.1.2** (previously 12.0.4).

> **End-user docs live in [README.md](README.md).** This file is the design /
> decision log: architecture choices, gotchas, and history. Read README first
> for build / install / usage; come here for the *why*.

## Architecture (v0.2.x)

The plugin is loaded once per `PluginTool` instance (Ghidra default behavior;
each CodeBrowser window is its own tool). On startup, each instance:

1. Tries to bind an HTTP server to the first free port in **8090-8129**.
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
  "version":    "0.3.0",
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
`/info` on each port in 8090-8129 and ignoring the ones that don't respond.

## Build & install

See [README.md](README.md) for full build and install instructions. Short
version: copy eight JARs from your Ghidra 12.1 install into `lib/`, then
`mvn clean package`, then `File → Install Extensions` in Ghidra with the
resulting ZIP.

## Versioning

Two version numbers, deliberately separate:

- **Plugin version** (e.g. `0.3.0`) — tracks fork changes (features, fixes).
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
- **v0.2.1**:
  - Migrated build to **Ghidra 12.1.2** (was 12.0.4; passed through 12.1
    briefly while Ghidra was 12.1, then re-targeted when laptop patched
    to 12.1.2).
  - Added `deploy_plugin.sh`: detects target host's installed Ghidra version
    from `application.properties` and patches the deployed
    `extension.properties` `ghidraVersion=` at install time. Means we don't
    need to bump the repo for every Ghidra patch release — the in-repo
    `ghidraVersion=` is just the last-built target; the script overrides per
    deploy. Also has `--clean-stale` to sweep old per-version Extensions dirs.
  - `/renameData` now creates a bare label when no `Data` is defined at the
    address (was a silent no-op in 0.2.0). Enables bulk-labeling tools to
    annotate symbols Ghidra's auto-analysis hasn't classified as data.
  - Dead v0.1.x code removed: `SlotAssigner.java`, `ProgramServer.java`, and
    the discovery-server / project-listener / slot-rebuild scaffolding in
    `GhidraMCPMultiProgramPlugin.java`. Two small display-name helpers
    (`effectiveName`, `extractDatePrefix`) that the live `/info` handler
    relied on were inlined into the plugin file. Plugin source shrank from
    2753 lines across 3 files to 1918 lines in 1 file. Stale
    `@PluginInfo.description` text was also corrected.
- **v0.3.0 (current)**:
  - **Port range expanded to 8090-8129 (40 ports).** Was 10 ports, which
    ran out when many programs were open concurrently. Expanded to 40 to
    cover sustained parallel analysis sessions.
  - **Spool-to-disk for large responses (Tier 0).** Four endpoints
    (`decompile_function`, `disassemble_function`, `list_functions`,
    `list_strings`) accept `to_file=true` — response body is written to a
    UUID-named file under `<projectDir>/.mcp_dumps/` and the JSON response
    contains a URL + size metadata. New HTTP endpoints `GET /dump/{uuid}`,
    `DELETE /dump/{uuid}`, `GET /dump` for streaming and cleanup. Every
    subsequent endpoint inherits the spool pattern for free.
  - **Tier 1 endpoint set** (~20 new endpoints): symbol-table read + label
    delete (`/list_symbols`, `/get_symbol_at`, `/delete_label`), function
    lifecycle (`/create_function`, `/delete_function`,
    `/mark_function_thunk`), DataType management (`/parse_c_header`,
    `/apply_data_type_at`, `/get_data_type`, `/list_data_types`,
    `/set_struct_member`), bulk operations (`/apply_labels_from_header`,
    `/rename_functions_bulk`, `/set_function_signature_bulk`), bookmarks
    (`/list_bookmarks`, `/add_bookmark`, `/delete_bookmark`), comment
    readback (`/list_comments_for_function`), and BFS callgraph slice
    (`/get_callgraph`).
  - **Script execution** (`/run_script`, `/list_scripts`). Run any installed
    Ghidra script (Python or Java) against the current program, or post an
    **inline Python body** that the plugin stages, executes, and deletes.
    Scripts run in the same JVM, see the live Ghidra DB state, and are
    transaction-wrapped for undo. Stdout/stderr/exit code/runtime are
    returned. Bridge wrappers: `run_script()` and `list_scripts()`.
  - **Version Tracker integration** (6 endpoints): `vt_list_sessions`,
    `vt_create_session`, `vt_run_correlators`, `vt_list_matches`,
    `vt_accept_matches`, `vt_apply_markups`. Enables automated VT workflows
    (create session → run correlators → accept matches → apply markups)
    entirely through MCP. Bridge has matching `vt_*` wrappers.
  - **`/open_program` endpoint**: load a project file by path into a new
    CodeBrowser tab programmatically, so the MCP agent can open programs
    without GUI interaction.
  - **Program-identity announcement in the bridge.** At startup, the bridge
    hits `/info` and stamps the program identity (`MM-DD-YYYY program.ext @
    port`) into every MCP tool description plus the MCP `serverInfo.name`.
    With multiple bridges, Claude sees distinctly labeled tool catalogs
    instead of indistinguishable `ghidra-*` blocks.
  - **SSE transport support** in the bridge (`--transport sse`), enabling
    clients that prefer a shared long-lived server (e.g. Cline's Remote
    Servers).
  - Plugin source grew from ~1918 to ~4200 lines due to the new endpoint
    set + DumpManager + VT integration + script execution.
