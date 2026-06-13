# PR Scope: `/run_script` — inline + named Python execution

> Status: design, not implemented. Draft 2026-06-12. Successor to PR_SCOPE_TIER0
> in the same way Tier 0 was the architecture-enabler for Tier 1: this PR turns
> the MCP from "fixed endpoint set" into "programmable surface against the full
> Ghidra API."

The current MCP exposes ~36 endpoints (read, write, structs, bulk, bookmarks,
callgraph, spool). Every workflow that doesn't map onto those endpoints today
either drops to the GUI, drops to headless analyzeHeadless, or asks OTTO to
ship a new endpoint. Most of the time the workflow is "walk the program in
some way the endpoints don't cover" — five-line Python against the Ghidra flat
API would do it, but there's no way in.

This PR adds two endpoints:

1. `POST /run_script` — execute a Ghidra script. Body accepts either a
   `script_name` (run an installed script) OR a raw `script_body` (inline
   Python; the plugin stages it as a temp script, runs, deletes).
2. `GET /list_scripts` — enumerate installed scripts so the agent can pick a
   target for `script_name` without poking the filesystem from outside.

Combined with Tier 0 spool-to-disk, the result is: REX writes a Python
function against the Ghidra flat API, posts it to MCP, gets the results back.
The MCP catalog stops being a hard ceiling on what's expressible.

---

## Goals

- Run any installed Ghidra script (Python, Java, Jython if available) against
  the current program of the bound tool, returning stdout / stderr / exit
  status / runtime.
- Run an **inline Python body** the agent posts on the fly, with the same
  return shape — without the agent needing filesystem or SSH access.
- Inherit the Tier 0 `to_file=true` contract so scripts that produce large
  output never hit the bridge-drop bug.
- Run in the same JVM as the plugin (no headless re-spawn) so:
  - Script sees the current Ghidra DB state, including in-flight changes
  - Script can be called between two other MCP calls atomically wrt the
    program's transaction state
  - No 10-30s analyzeHeadless cold-start tax per call
- Transaction-wrapped by default so script mutations are undoable from the
  GUI (Edit → Undo).

## Non-goals

- **Not** a generic remote-code-execution service. Sandboxing scripts inside
  a JVM that already has full access to the program is hostile-environment
  defence we don't need on the homelab LAN, but the threat model is "agent
  may make a mistake," not "attacker chains arbitrary RCE."
- **Not** persistent / background scripts. Run-and-return. Scripts that want
  to live longer write their state to disk and a subsequent call resumes from
  there.
- **Not** a script editor. Inline bodies are write-once-execute-once; named
  scripts edit via the filesystem (or via PyGhidra Script Manager in the GUI)
  as today.
- **Not** cross-program. The script runs against the program currently bound
  to *this tool's port*. To run against a different program, hit a different
  bridge.

---

## API surface

### `POST /run_script`

Request body (form-encoded today, JSON-encoded later when we add JSON bodies):

| Field | Required | Meaning |
|---|---|---|
| `script_name` | one of these two | Name of an installed script (e.g. `ApplySig.py`) |
| `script_body` | one of these two | Raw Python text. Staged as a temp script. |
| `args` | optional | Tab- or newline-separated argument list. Maps to `script.setScriptArgs(String[])` |
| `to_file` | optional | If `true`, captured stdout spools to disk; response envelope is the standard Tier-0 spool JSON |
| `transaction_name` | optional | Override the default transaction label. Default: `MCP run_script <name>` |

Exactly one of `script_name` / `script_body` must be set. Both → 400.

### Response (when `to_file=false`, default)

```json
{
  "script": "ApplySig.py" | "inline-mcp-3f2c8.py",
  "exit_code": 0,
  "runtime_ms": 4123,
  "stdout": "<captured stdout>",
  "stderr": "<captured stderr>"
}
```

### Response (when `to_file=true`)

Stdout (which is often what the agent cares about) spools to disk per the
Tier 0 pattern. Stderr stays inline because it's almost always small. Exit
status + runtime stay inline.

```json
{
  "script": "ApplySig.py",
  "exit_code": 0,
  "runtime_ms": 4123,
  "stdout_url": "http://host:8090/dump/script-3f2c8b9e",
  "stdout_bytes": 47823412,
  "stdout_lines": 412953,
  "stderr": "<usually small, stays inline>"
}
```

### `GET /list_scripts`

```json
{
  "scripts": [
    {
      "name": "ApplySig.py",
      "path": "~/ghidra_scripts/ApplySig.py",
      "language": "Python",
      "category": "FunctionID",
      "description": "Batch FLIRT signature apply"
    },
    {
      "name": "ExportViaReflection.java",
      "path": "/path/to/MQ-RE/tools/re_pipeline/ghidra/ExportViaReflection.java",
      "language": "Java",
      "category": "BinExport"
    },
    ...
  ]
}
```

Supports `?to_file=true` (the full DTM-style list can be hundreds of entries
on a well-populated install).

---

## Inline script staging — the key detail

Ghidra scripts must live on the filesystem to be executable via the standard
`GhidraScriptUtil` API. Inline bodies get staged like this:

1. Resolve the staging dir: `<projectDir>/.mcp_inline_scripts/` (gitignored).
   Created on first inline call. Same per-program scoping as the spool
   `.mcp_dumps/` dir.
2. Generate filename: `inline-mcp-<8-hex>.py` (extension matches body
   language — for Python). UUID-based, structurally unique.
3. Write body to that file.
4. Add the staging dir to the script-source search path via
   `GhidraScriptUtil.getSystemScriptDirectories()` if it isn't already (one-time).
5. Execute via the same path as named scripts.
6. **Always** delete the file in a `finally` block after execution, success or
   failure. The dir is also reaped opportunistically (same sweep as Tier 0
   dumps).

The temp file is necessary because Ghidra's script lifecycle hangs off
filesystem discovery. Direct in-memory exec would need a parallel script
infrastructure that's not worth the complexity for v1.

## Script execution path (Java side)

```java
private String runScript(String scriptName, String scriptBody, String[] args,
                         boolean toFile, String txName) {
    Program program = getCurrentProgram();
    if (program == null) return "{\"error\":\"No program loaded\"}";

    File scriptFile = null;
    boolean cleanupFile = false;
    if (scriptBody != null) {
        scriptFile = stageInlineScript(program, scriptBody);
        cleanupFile = true;
        scriptName = scriptFile.getName();
    }

    ResourceFile srcFile = (scriptFile != null)
        ? new ResourceFile(scriptFile)
        : GhidraScriptUtil.findScriptByName(scriptName);
    if (srcFile == null) {
        if (cleanupFile) scriptFile.delete();
        return "{\"error\":\"script not found: " + scriptName + "\"}";
    }

    GhidraScriptProvider provider = GhidraScriptUtil.getProvider(srcFile);
    if (provider == null) {
        if (cleanupFile) scriptFile.delete();
        return "{\"error\":\"no provider for: " + scriptName + "\"}";
    }

    StringWriter stdout = new StringWriter();
    StringWriter stderr = new StringWriter();
    PrintWriter outPw = new PrintWriter(stdout);
    PrintWriter errPw = new PrintWriter(stderr);

    GhidraState state = new GhidraState(tool, tool.getProject(), program,
        null, null, null);
    GhidraScript script;
    long t0 = System.currentTimeMillis();
    int exitCode = 0;
    try {
        script = provider.getScriptInstance(srcFile, errPw);
        if (script == null) {
            return errorEnvelope(scriptName, "instantiation returned null", stderr);
        }
        if (args != null) script.setScriptArgs(args);
        int tx = program.startTransaction(
            (txName != null ? txName : "MCP run_script " + scriptName));
        try {
            script.execute(state, new ConsoleTaskMonitor(), outPw);
            program.endTransaction(tx, true);
        }
        catch (Exception e) {
            program.endTransaction(tx, false);
            errPw.println("EXCEPTION: " + e);
            e.printStackTrace(errPw);
            exitCode = 1;
        }
    }
    catch (Exception e) {
        errPw.println("FATAL: " + e);
        e.printStackTrace(errPw);
        exitCode = 2;
    }
    finally {
        outPw.flush(); errPw.flush();
        if (cleanupFile && scriptFile != null) scriptFile.delete();
    }
    long runtimeMs = System.currentTimeMillis() - t0;

    if (toFile) {
        return spoolStdoutAndJsonResponse(scriptName, exitCode, runtimeMs,
            stdout.toString(), stderr.toString());
    } else {
        return inlineJsonResponse(scriptName, exitCode, runtimeMs,
            stdout.toString(), stderr.toString());
    }
}
```

The `GhidraState` constructor wires the script to the same Project + Program
the rest of the MCP endpoints see — script's `currentProgram`, `currentAddress`
etc. resolve correctly.

## Bridge wrappers

```python
@mcp.tool()
def run_script(script_name: str = None, script_body: str = None,
               args: list = None, to_file: bool = False,
               transaction_name: str = None):
    """
    Execute a Ghidra script against the program bound to this MCP server.

    Exactly one of script_name or script_body must be supplied.
      - script_name: name of a script installed in any of Ghidra's script
        directories (e.g. "ApplySig.py").
      - script_body: raw Python source text; the plugin stages it as a
        temp inline script, runs it, deletes it.

    Inside the script body, the standard Ghidra GhidraScript context is
    available: currentProgram, currentAddress, currentSelection, monitor,
    plus the flat API (getFunctionAt, parseAddress, getBytes, etc.) and
    the full ghidra.* / java.* import surface.

    Returns the captured stdout, stderr, exit code, and runtime. With
    to_file=True, large stdout spools to disk per the standard pattern.
    """
    payload = {}
    if script_name: payload["script_name"] = script_name
    if script_body: payload["script_body"] = script_body
    if args:        payload["args"] = "\n".join(args)
    if to_file:     payload["to_file"] = "true"
    if transaction_name: payload["transaction_name"] = transaction_name
    return safe_post_json("run_script", payload)


@mcp.tool()
def list_scripts(to_file: bool = False):
    """
    Enumerate installed Ghidra scripts visible to run_script.
    Returns list of {name, path, language, category, description}.
    """
    params = {}
    if to_file: params["to_file"] = "true"
    return safe_get_json("list_scripts", params)
```

## What this unlocks (examples REX could write)

### 1. Find functions calling X with constant Y as a specific arg

```python
# inline script_body, posted via /run_script
from ghidra.program.model.symbol import RefType

target = getFunction("MyCallee")
for ref in target.getSymbol().getReferences():
    if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL:
        caller_addr = ref.getFromAddress()
        caller_fn = getFunctionContaining(caller_addr)
        # Decompile, walk back to find the arg-2 constant at this call site...
        # (10 more lines of Python)
        print(f"{caller_fn.getName()} @ {caller_addr} passes {value}")
```

No combination of the current endpoint set does this in one MCP round trip.

### 2. Walk the call graph filtered by some predicate

### 3. Run ApplySig with REX-picked args

```python
run_script(script_name="ApplySig.py",
           args=[],  # ApplySig reads APPLYSIG_DIR env var; could extend it to take args
           to_file=True)
```

REX gets back the per-sig rename counts + summary as if they'd run it
headless, but in the live GUI session, against the live DB.

### 4. Custom verification passes

The MQ-RE workflow has dozens of `work/<class>_per_field/` evidence scripts
that have to be run in Ghidra. `run_script` lets REX trigger any of them
without an SSH round trip.

---

## Safety rails

1. **Same scoping as the rest of the plugin.** Inline scripts go under the
   program's project dir, not /tmp; they're per-program. Two programs on two
   ports can't see each other's inline staging dirs.
2. **Always-delete in a finally.** The inline script file does not survive
   execution even if the script throws or the JVM is mid-failure (the finally
   runs unless the JVM hard-crashes; in that case the opportunistic sweep on
   next request catches it).
3. **Path-safe filename for inline scripts.** UUID-only, validated against
   `^inline-mcp-[0-9a-f]{8}\.py$` before any rename/delete operation.
4. **Transaction-wrapped.** Default behavior; mutations are undoable. Scripts
   that explicitly start their own transactions (rare) get the same
   atomicity guarantees as today's set_struct_member etc.
5. **Output size guard.** If captured stdout exceeds N MB (e.g. 50), force
   `to_file=true` regardless of the request flag — protects the MCP transport
   the same way the existing Tier 0 endpoints do.
6. **No auth.** Same trust boundary as everything else on the plugin. Not in
   scope for this PR.

## Open design choices

1. **Sync vs async for long scripts.** ApplySig on a fat eqgame can run
   30-60s. HTTP timeout in the bridge is 30s today. Two ways to handle:
   - **Sync + raise the timeout to 600s** for `/run_script` only. Simple.
   - **Async with job IDs:** `POST /run_script` returns `{job_id}`, `GET
     /run_script/<job_id>` polls until done. More complex; better for very
     long scripts. Defer to v2.

   Recommendation: sync + 10-minute timeout in v1. Add async only if a
   real script needs >10 minutes.

2. **Script language detection.** Today: file extension drives provider
   selection (`.py` → PyGhidra, `.java` → Java). Inline scripts are
   Python-only in v1 (REX is the main consumer). If Java inline is wanted
   later, add `language` field to the request.

3. **Args format.** Internal: `String[]` for `setScriptArgs`. Wire format:
   the bridge takes a Python list and joins with newlines (newline is
   structurally absent in shell-style args; safer than tab). The Java side
   splits back on newline.

4. **`list_scripts` filtering.** Add `?category=`, `?name_pattern=`,
   `?language=` filters? Probably yes — Ghidra installs ship hundreds of
   stock scripts and `~/ghidra_scripts/` adds more. Match the pattern from
   `list_data_types` (substring + category + kind filters + spool support).

5. **Stderr handling.** Today's plan: always inline. Alternative: spool
   when `to_file=true` covers both. Likely keep stderr inline — script
   stderr is typically <10KB even on big runs.

6. **Script timeout enforcement.** Should `/run_script` accept a
   `?timeout_seconds=N` param and kill the script after N seconds? Ghidra
   has TaskMonitor cancel — we could trigger `monitor.cancel()` after the
   timeout. Useful belt-and-suspenders. v2 candidate.

---

## File changes

| File | Change |
|---|---|
| `src/main/java/com/krakty/ghidramcp/GhidraMCPMultiProgramPlugin.java` | Add `runScript`, `listScripts`, `stageInlineScript`, `sweepInlineDir` helpers; add `/run_script` and `/list_scripts` handlers; minor imports |
| `bridge_mcp_ghidra.py` | `run_script`, `list_scripts` `@mcp.tool` wrappers; reuse `safe_post_json` |
| `README.md` | Endpoint table rows + a new "Programmable surface" subsection with two example bodies |
| `PR_SCOPE_TIER0.md` | No change. This is a sibling, not a follow-up. |

Estimated total LOC: ~250 plugin + ~70 bridge + ~50 docs = ~370.

## Implementation order

1. `listScripts` first. Pure read, no transaction, no inline staging — proves the script-resolution path works against `GhidraScriptUtil`.
2. `runScript` named-script path. Uses `findScriptByName` → `getProvider` → `execute`. Captures stdout/stderr. No staging dir yet.
3. Add inline staging (`stageInlineScript` + finally-delete). Path-safety regex + uuid filename. Add sweep.
4. Wire to_file=true on stdout — reuse the existing `DumpManager`.
5. Bridge wrappers, README, done.

Each step ships cleanly on its own.

---

## Audit hooks (for OTTO's own review)

- After step 2: write a Python body that calls `currentProgram.getFunctionManager().getFunctionCount()` and assert the return matches `/list_functions | wc -l` from the same port. Catches "is the script actually running against the same DB."
- After step 3: write a body that just `raise RuntimeError("test")` and assert: (a) inline file deleted, (b) `exit_code != 0`, (c) stderr has the traceback. Catches the finally semantics.
- After step 4: run ApplySig.py via `/run_script` against a real binary with `to_file=true`. Verify the spool URL responds and the byte/line counts match a headless run.

## Risks

1. **PyGhidra script context behaves slightly differently than Jython.**
   Ghidra 12.x is PyGhidra-only (Jython removed). Scripts our user has on
   disk are already Python-3-ported (we did ApplySig in this session) so
   this is mostly already addressed. But: `GhidraScript.execute()` invokes
   the script through its provider, and PyGhidra's provider may handle
   imports slightly differently from how a script behaves when launched via
   `pyghidraRun -postScript`. Need to verify with a real ApplySig call.
2. **Transaction scope.** Wrapping the script in a single transaction means
   inner `program.startTransaction` calls in the script become nested — which
   Ghidra handles, but mistakes here can leak open transactions. Test by
   running a script that opens its own transaction inside the wrapper and
   verify clean state after.
3. **Multi-tool projects.** Each MCP port is one tool; one tool has one
   current program. Behavior is well-defined per-tool. But a script that
   changes the current program (rare) could surprise the next MCP call on
   that port. Document as a known caveat.

---

## Why this is the right next PR

Three threads in the prior PR_SCOPE_TIER0 / Tier 1 work converge on this:

1. Every Tier 1 PR closed a gap by adding a fixed endpoint. The remainder of
   "gaps" REX will hit in the wild are mostly long-tail "I need to do *this
   one specific thing*" — too varied to enumerate. `run_script` makes the gap
   set finite.
2. The Tier 0 spool pattern already exists. `run_script` adopts it for free.
3. The MQ-RE side has dozens of one-shot Ghidra scripts (per-class evidence,
   audit passes). All of them become MCP-callable without writing a single
   plugin endpoint.

## Out of scope for this PR (capture for later)

- **Script catalog.** A discoverable registry of "useful scripts REX should
  know about" — separate from `list_scripts` which dumps everything. Maybe a
  curated subset with descriptions in a README.
- **Pre-script hooks.** Run a pre-script before every MCP call to set
  context. Unclear if useful; defer.
- **Cross-port script execution.** Run a script on port 8090 from a request
  to port 8091 (e.g. "compare these two programs"). Possible but invites the
  bridge-coordinator pattern we sidestepped. Defer.

---

End of scope. Next OTTO: implement per §"Implementation order".
