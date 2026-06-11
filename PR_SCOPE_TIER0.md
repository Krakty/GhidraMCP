# PR Scope: Tier 0 — Spool-to-disk + HTTP-served dumps

> Status: design, not implemented. Draft 2026-06-11.

The MCP bridge drops/deregisters when an endpoint response is large (multi-MB).
Agent memory has been working around this for weeks by exporting decompiled C
from the Ghidra GUI and grepping it locally. This PR closes the gap from inside
the plugin: any potentially-large endpoint can spool its result to a file under
the project dir and return a small JSON envelope containing an HTTP URL the
agent fetches directly via `curl` — never through MCP.

The MCP/stdio failure mode that triggered the workarounds isn't *fixed* by this
PR; it just stops mattering, because nothing big ever flows over MCP again.

---

## Goals

- Add an opt-in `to_file=true` query parameter to the four known large-response
  endpoints (`decompile_function`, `disassemble_function`, `list_functions`,
  `list_strings`). When set, the response body is written to a UUID-named file
  under `<projectDir>/.mcp_dumps/` and the JSON response contains only a URL +
  size metadata.
- Expose a `GET /dump/{uuid}` endpoint on the same plugin HTTP server that
  streams the spool file (chunked transfer encoding, no in-memory buffering).
  Optional `?delete_after=true` deletes on successful read; `DELETE /dump/{uuid}`
  is the explicit form.
- Sweep expired dumps opportunistically on every spool/fetch call (TTL default
  3600s). No background thread; the sweep is bounded and cheap.
- Update the Python bridge so the four wrapped tools surface the URL + metadata
  to Claude when `to_file=True`, otherwise behave as today.
- Document the pattern in `README.md` so future endpoints inherit it.

## Non-goals

- **Fix the bridge-drop root cause.** Out of scope here. The spool pattern
  bypasses the failure, not the failure itself. A follow-up investigation can
  still happen but isn't blocking.
- **Pagination of large responses.** The dump file is the unit of delivery;
  the agent paginates by `curl | head` / `tail` / `grep` / Range requests.
- **Authentication.** The MCP plugin is unauthenticated today; spool fetch
  inherits the same trust boundary. Acceptable for the homelab; noted as a
  caveat if this ever leaves the LAN.
- **Streaming endpoints that don't *return* large bodies** (e.g.
  `rename_function`). Adding `to_file` is meaningless for them.
- **Cross-bridge / cross-program dump sharing.** Each port serves only its own
  dumps. A bridge on 8090 can't read 8091's dump dir.

---

## Architecture

```
Agent (beast)                Plugin (laptop:8090)            Disk (laptop)
  │                              │                              │
  │ MCP: disassemble_function    │                              │
  │     to_file=true ───────────►│                              │
  │                              │ write spool ────────────────►│ .mcp_dumps/
  │                              │                              │   <uuid>
  │                              │ tiny JSON {url, bytes, ...}  │
  │ ◄────────────────────────────│                              │
  │                              │                              │
  │ curl http://laptop:8090/dump/<uuid>                         │
  │ ──────────────────────────► (chunked transfer encoding)     │
  │ stream of bytes  ◄─── plugin Files.copy() to OutputStream ◄─│
  │                              │                              │
  │ grep / head / tail / Read    │                              │
  │ DELETE /dump/<uuid>          │                              │
  │ ──────────────────────────►  │ unlink ─────────────────────►│
```

Two failure-mode improvements drop out of this:

1. **MCP stdio stays small.** Tiny JSON envelope is well under any reasonable
   buffer limit.
2. **Agent can stream-search.** `curl | grep` matches the bulk-export workflow
   the other Claudes already use; the spool file never has to fit in memory or
   in the MCP transport.

---

## API surface

### Plugin: new HTTP endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/dump/{uuid}` | GET | Stream the spool file. Supports `?delete_after=true`. Supports `Range:` header for resumable fetch. |
| `/dump/{uuid}` | DELETE | Explicit cleanup. Idempotent (404 if already gone). |
| `/dump` | GET | List active dumps (for housekeeping/debug). Returns `[{uuid, endpoint, bytes, age_seconds}, ...]`. Cheap; reads dir listing. |

### Plugin: modified existing endpoints

The following endpoints gain an opt-in `to_file=true` query parameter. Default
behaviour (without the param) is unchanged.

| Endpoint | Why it's large |
|---|---|
| `/decompile_function` | Single huge function (switch-heavy game code) can produce 100KB+ of decompiled C |
| `/disassemble_function` | Same function in disassembled form is 5-10x larger than decompiled |
| `/list_functions` | EQ binary has ~25k functions; full list is multi-MB as text |
| `/list_strings` | Defined string table easily exceeds MCP buffer for game binaries |

Other endpoints can be added later. Pattern is uniform.

### Response shape with `to_file=true`

```json
{
  "url": "http://your-ghidra-host.local:8090/dump/disasm-3f2c8b9e",
  "uuid": "disasm-3f2c8b9e",
  "endpoint": "disassemble_function",
  "bytes": 47823412,
  "lines": 412953,
  "ttl_seconds": 3600,
  "created_at": "2026-06-11T18:42:13Z"
}
```

`lines` is included because most agent workflows want it to triage ("too big to
slurp — I'll grep") and computing it is free during the write.

### Bridge: tool signatures

Each wrapped tool gains a `to_file: bool = False` keyword arg. The MCP tool
schema picks up the new param automatically via the type hint, so Claude sees
it in the tool description.

```python
@mcp.tool()
def disassemble_function(address: str, to_file: bool = False) -> str | dict:
    """
    Disassemble the function at <address>. Returns a list of disassembly lines
    by default. When to_file=True, the disassembly is spooled to a file on the
    plugin host and a small JSON envelope with the fetch URL is returned —
    useful for very large functions where the MCP transport would otherwise
    choke. Fetch the spool URL with curl in a Bash tool call.
    """
    params = {"address": address}
    if to_file:
        params["to_file"] = "true"
        return safe_get_json("disassemble_function", params)
    return safe_get("disassemble_function", params)
```

`safe_get_json` is a new bridge helper that parses the response as JSON (the
spool-mode response). Existing `safe_get` returns lines as today.

---

## Internal design

### Spool directory layout

```
<projectDir>/.mcp_dumps/
├── disasm-3f2c8b9e          # raw body, UTF-8 encoded
├── disasm-3f2c8b9e.meta     # JSON metadata: endpoint, bytes, lines, created_at
└── decomp-a01f2d33
    └── ...
```

The `.meta` sidecar lets `GET /dump` list endpoints without reading the body.

**Path:** under the **project's data dir**, not /tmp. Reasoning: the project
dir is the natural lifespan boundary; closing the project leaves the dumps
behind but they'll TTL out. Using /tmp risks the OS clearing them mid-session.

**Discovery:** call `program.getDomainFile().getProjectLocator().getProjectDir()`
and append `.mcp_dumps/`. Create on first use.

### UUID scheme

Format: `<endpoint-prefix>-<8-char-hex>`. Endpoint prefix is a short tag:
`disasm`, `decomp`, `funcs`, `strs`. Hex is `UUID.randomUUID().toString().replace("-","").substring(0,8)`.

**Why short hex, not full UUID:** the hex slot has 4 billion possibilities;
collision over a 1-hour TTL with a few hundred dumps is negligible. Full UUIDs
make logs/URLs ugly.

### TTL sweep

Triggered opportunistically:
- On every successful spool write (sweep before allocating)
- On every successful `GET /dump/{uuid}` (sweep, then serve)
- On startup (sweep stale dumps from a prior session)

Sweep logic: iterate `.mcp_dumps/*.meta`, parse `created_at`, delete `{uuid}` +
`{uuid}.meta` if older than TTL. Bounded — there shouldn't be more than a few
dozen meta files at any time.

**No background thread.** Avoids lifecycle complications with Ghidra plugin
shutdown.

### Streaming response

Java's `HttpServer` chunks the response automatically when you pass `0` as the
content length:

```java
File spool = lookupByUuid(uuid);  // null-check, 404 if missing
exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
exchange.sendResponseHeaders(200, 0);  // 0 = chunked
try (OutputStream os = exchange.getResponseBody();
     FileInputStream in = new FileInputStream(spool)) {
    in.transferTo(os);  // streams in 8KB chunks; no full-file buffer
}
```

`InputStream.transferTo` (Java 9+) uses a fixed-size buffer internally and
streams to the output stream. No file-sized allocation; minimal heap pressure.

### Range requests

Bonus capability for resumable fetches. When the request has a `Range:
bytes=NNN-MMM` header, we honour it:

```java
String range = exchange.getRequestHeaders().getFirst("Range");
if (range != null) {
    long[] bounds = parseRange(range, spool.length());
    exchange.getResponseHeaders().set("Content-Range",
        "bytes " + bounds[0] + "-" + bounds[1] + "/" + spool.length());
    exchange.sendResponseHeaders(206, bounds[1] - bounds[0] + 1);
    try (RandomAccessFile raf = new RandomAccessFile(spool, "r");
         OutputStream os = exchange.getResponseBody()) {
        raf.seek(bounds[0]);
        // stream bounded byte count
    }
}
```

Lets the agent do `curl -r 0-1024 ...` to peek at a dump without fetching the
whole thing — useful for triage.

### Path safety

Critical: `{uuid}` is **never** treated as a path. The handler:

1. Validates `uuid` matches `^[a-z]+-[0-9a-f]{8}$`.
2. Looks up the file via `new File(dumpDir, uuid)` then `getCanonicalPath()`.
3. Verifies the canonical path is under `dumpDir.getCanonicalPath()`. If not,
   reject 400.

No call accepts an arbitrary path from the client. The only way a file shows
up in `.mcp_dumps/` is through the plugin's own spool writer.

### Per-program scoping

Each plugin instance binds to one tool's program. `dumpDir` is derived from
that program's project dir. A different port's program has a different project
dir (in the per-tool architecture) so dump dirs don't collide. The handler
explicitly resolves the dir at request time, so a stale path can't leak.

### Concurrency

Spool writes go to a `<uuid>.tmp` then `Files.move(... ATOMIC_MOVE)` to the
final name. Ensures partial files aren't observable by `GET /dump`.

### Failure modes

| Failure | Response | Recovery |
|---|---|---|
| Disk full during spool | 507 Insufficient Storage | Sweep + retry once; if still full, fail. |
| Spool succeeded, fetch URL hit but file gone (TTL'd or deleted) | 404 | Caller re-spools by calling the endpoint again. |
| Plugin restart between spool and fetch | 404 (sweep on startup) | Same — caller re-spools. |
| Range request with invalid bounds | 416 Range Not Satisfiable | Caller fixes the range. |

---

## Test plan

1. **Smoke**: small spool, fetch, verify content matches direct response.
2. **Large**: 100MB disassembly spool, `curl -o /tmp/foo`, verify byte count
   and `wc -l` matches metadata.
3. **Streaming**: `curl ... | head -c 1024 > /dev/null` and confirm plugin
   doesn't buffer the whole file (plugin memory should stay flat).
4. **Range**: `curl -r 0-1023` returns first 1024 bytes; `curl -r 1000000-`
   returns from offset 1M to EOF.
5. **TTL sweep**: spool, advance clock past TTL (or modify file mtime),
   confirm next spool deletes it.
6. **Path traversal**: `GET /dump/../etc/passwd` → 400.
7. **Concurrent spool**: 4 parallel `disassemble_function?to_file=true` calls,
   confirm 4 distinct UUIDs, no cross-contamination.
8. **DELETE idempotency**: DELETE twice; second is 404 not 500.
9. **Bridge integration**: from a real Claude session, `to_file=True` returns
   parseable JSON with valid URL; `to_file=False` returns lines as today.

---

## File changes

| File | Change |
|---|---|
| `src/main/java/com/krakty/ghidramcp/GhidraMCPMultiProgramPlugin.java` | Add `DumpManager` inner class (or sibling file); add `to_file=true` handling to the 4 endpoints; add `/dump`, `/dump/{uuid}` handlers |
| `src/main/java/com/krakty/ghidramcp/DumpManager.java` | New file. Manages spool dir, UUID allocation, TTL sweep, lookup |
| `bridge_mcp_ghidra.py` | Add `safe_get_json` helper; add `to_file: bool = False` param to the 4 wrapped tools |
| `README.md` | Add "Spool-to-disk for large responses" subsection under "Endpoint reference" |
| `.gitignore` | Ignore `.mcp_dumps/` if it ever appears in the repo tree (it lives under the Ghidra project dir, not the source repo, but belt-and-suspenders) |

Estimated total LOC: **~150 plugin + ~60 bridge + ~30 docs = ~240 lines**.

---

## Implementation order

Six atomic steps, each independently shippable / reviewable:

1. **DumpManager skeleton** — class, spool dir resolution, UUID generation, write
   helper, sweep. No HTTP integration yet. Unit-testable in isolation.
2. **`GET /dump/{uuid}` + `DELETE /dump/{uuid}`** — wire DumpManager into the
   HTTP server. Validate path-safety. Stream via transferTo.
3. **`GET /dump` listing endpoint** — debug/housekeeping. Tiny.
4. **`to_file=true` on `disassemble_function`** — first endpoint to opt in.
   Prove the pattern end-to-end against a real big function.
5. **`to_file=true` on the other 3 endpoints** (`decompile_function`,
   `list_functions`, `list_strings`). Pure copy of step 4.
6. **Bridge wrappers + README docs** — ship together. Bridge change is
   forward-compatible (default `to_file=False` is current behaviour).

Each step is mergeable on its own; steps 4-5 only become *useful* after 1-2 land.

---

## Code sketches

### DumpManager (Java, ~80 lines)

```java
package com.krakty.ghidramcp;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;

public class DumpManager {
    private static final long TTL_MS = 3600 * 1000L;
    private static final Pattern UUID_RE =
        Pattern.compile("^[a-z]+-[0-9a-f]{8}$");
    private final Path dumpDir;

    public DumpManager(Program program) throws IOException {
        File projectDir = program.getDomainFile()
            .getProjectLocator().getProjectDir();
        this.dumpDir = projectDir.toPath().resolve(".mcp_dumps");
        Files.createDirectories(dumpDir);
    }

    /** Returns the URL-safe UUID. Body is written + meta sidecar. */
    public String spool(String endpointTag, String body) throws IOException {
        sweep();
        String uuid = endpointTag + "-" +
            UUID.randomUUID().toString().replace("-","").substring(0, 8);
        Path target = dumpDir.resolve(uuid);
        Path tmp = dumpDir.resolve(uuid + ".tmp");
        Files.writeString(tmp, body);
        Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE);
        writeMeta(uuid, endpointTag, body.length(), countLines(body));
        return uuid;
    }

    public File resolve(String uuid) throws IOException {
        if (!UUID_RE.matcher(uuid).matches()) return null;
        Path p = dumpDir.resolve(uuid);
        // Canonicalise + ensure under dumpDir
        Path canon = p.toRealPath();
        if (!canon.startsWith(dumpDir.toRealPath())) return null;
        return Files.exists(canon) ? canon.toFile() : null;
    }

    public boolean delete(String uuid) {
        File f = null;
        try { f = resolve(uuid); } catch (IOException e) { return false; }
        if (f == null) return false;
        File meta = new File(f.getPath() + ".meta");
        meta.delete();
        return f.delete();
    }

    /** Returns metadata for all live dumps; sweeps before reading. */
    public List<Map<String, Object>> list() throws IOException {
        sweep();
        List<Map<String,Object>> out = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dumpDir, "*.meta")) {
            for (Path m : ds) out.add(readMeta(m));
        }
        return out;
    }

    private void sweep() {
        long now = System.currentTimeMillis();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dumpDir, "*.meta")) {
            for (Path m : ds) {
                long mtime = Files.getLastModifiedTime(m).toMillis();
                if (now - mtime > TTL_MS) {
                    String name = m.getFileName().toString().replace(".meta","");
                    delete(name);
                }
            }
        } catch (IOException e) {
            Msg.warn(this, "sweep failed: " + e.getMessage());
        }
    }

    // writeMeta / readMeta / countLines: trivial helpers (~30 lines total)
}
```

### Endpoint wrapper (plugin, per endpoint, ~10 lines)

```java
server.createContext("/disassemble_function", exchange -> {
    Map<String,String> qparams = parseQueryParams(exchange);
    String addr = qparams.get("address");
    boolean toFile = "true".equals(qparams.get("to_file"));
    String body = disassembleFunction(addr);  // existing helper

    if (toFile) {
        String uuid = dumpManager.spool("disasm", body);
        sendJson(exchange, makeDumpResponse(uuid, body));
    } else {
        sendResponse(exchange, body);
    }
});
```

### `/dump/{uuid}` handler (plugin, ~30 lines)

```java
server.createContext("/dump/", exchange -> {
    String path = exchange.getRequestURI().getPath();
    String uuid = path.substring("/dump/".length());
    String method = exchange.getRequestMethod();

    File f = dumpManager.resolve(uuid);
    if (f == null) { send404(exchange); return; }

    if ("DELETE".equals(method)) {
        boolean ok = dumpManager.delete(uuid);
        sendResponse(exchange, ok ? "deleted" : "not found");
        return;
    }

    boolean deleteAfter =
        "true".equals(parseQueryParams(exchange).get("delete_after"));

    exchange.getResponseHeaders().set("Content-Type",
        "text/plain; charset=utf-8");
    exchange.sendResponseHeaders(200, f.length());  // known size
    try (OutputStream os = exchange.getResponseBody();
         FileInputStream in = new FileInputStream(f)) {
        in.transferTo(os);
    }
    if (deleteAfter) dumpManager.delete(uuid);
});
```

### Bridge wrapper change (Python, per endpoint, ~10 lines)

```python
@mcp.tool()
def disassemble_function(address: str, to_file: bool = False) -> list | dict:
    """
    Disassemble the function at <address>.

    Returns a list of disassembly lines by default. When to_file=True, the
    disassembly is spooled to a file on the plugin host and a small JSON
    envelope with the fetch URL is returned — useful for very large
    functions where the MCP transport would otherwise choke. Fetch the
    spool URL with curl in a Bash tool call:

        curl -s <url> | grep <pattern>
    """
    params = {"address": address}
    if to_file:
        params["to_file"] = "true"
        return safe_get_json("disassemble_function", params)
    return safe_get("disassemble_function", params)


def safe_get_json(endpoint: str, params: dict) -> dict:
    """GET endpoint and parse response as JSON. For spool-mode responses."""
    url = urljoin(ghidra_server_url, endpoint)
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}
```

---

## Risks / open questions

1. **Disk usage.** A 100MB dump that survives the full TTL is one file the
   project dir wouldn't otherwise have. With the 1-hour TTL and the typical
   workflow ("spool, grep, delete"), expected steady-state usage is small.
   Worst-case: tens of dumps × ~50MB each = ~1-2GB transient. Acceptable for
   the project dir; document the location.
2. **Project dir not always writable.** If the project is read-only or on a
   filesystem with permissions issues, spool fails. Fallback: emit the error
   in the JSON envelope; caller can retry without `to_file`.
3. **TTL too aggressive?** 1 hour is fine for interactive sessions. Long
   batch jobs that spool and then sleep > 1h would lose dumps. The TTL can
   be made configurable via plugin options in a follow-up; not blocking.
4. **No content compression.** The dump file is plain UTF-8 text. Could gzip
   on write and decompress on fetch (HTTP Content-Encoding: gzip) for big
   wins on disassembly (~5x typical). Defer to a follow-up — measure first.
5. **`list_functions` without `to_file` is already big.** Should the default
   change to `to_file=True` for endpoints we know are usually large? No —
   keep the default backwards-compatible; let the agent opt in. Document the
   recommendation in the tool description.
6. **`Files.writeString` materialises the full body in memory.** For *spooling*,
   that's still better than the current state where the body is in memory
   anyway (it's the response body). True streaming-from-Ghidra-to-disk
   without an intermediate string would require refactoring the existing
   helpers (e.g. `getAllFunctionNames`) to write to a writer instead of
   returning a string. Defer; current memory pressure is not the blocker.
7. **Bridge `safe_get_json` has a 30s timeout** — the plugin shouldn't take
   30s to write a file. If it does, that's a real bug worth surfacing.

---

## What this PR explicitly enables next

Once the spool pattern is in place, every Tier 1 endpoint (`list_symbols`,
`get_data_type`, future `dump_all_decompilations`, etc.) inherits the same
`to_file` flag for free. No future endpoint needs to think about the bridge
size limit. That's the real payoff: this PR is **the architectural change**,
the rest of Tier 1 is **just new endpoints on top of it**.
