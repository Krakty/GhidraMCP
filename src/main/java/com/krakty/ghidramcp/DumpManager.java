package com.krakty.ghidramcp;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Manages on-disk spool files for large endpoint responses.
 *
 * The MCP stdio transport chokes on multi-MB messages, dropping the bridge
 * entirely. Rather than chasing the transport bug, endpoints that may produce
 * large output write the body to a UUID-named file under the project dir and
 * return a tiny JSON envelope containing an HTTP URL the agent fetches with
 * curl. The plugin's existing HTTP server hosts the file via {@code GET
 * /dump/{uuid}} and streams it via chunked transfer encoding, so nothing
 * large ever flows over MCP.
 *
 * Spool dir lives under each Program's project dir at {@code .mcp_dumps/}.
 * Files have a short UUID suffix ({@code endpoint-XXXXXXXX}) and a sidecar
 * {@code .meta} file holding endpoint name, byte count, line count, and a
 * timestamp. The sweep walks {@code *.meta} once per spool/fetch operation
 * (no background thread, no Ghidra-lifecycle hooks to leak) and deletes
 * anything older than {@link #TTL_MS}.
 *
 * Path safety: the public API addresses dumps only by UUID. {@link
 * #resolve(String)} validates the UUID against a fixed regex, then resolves
 * via {@code dumpDir.resolve(uuid).toRealPath()} and verifies the canonical
 * path is still under {@code dumpDir}. No caller-supplied path ever touches
 * the filesystem.
 */
public final class DumpManager {

    /** Spool TTL: 1 hour. Long enough for interactive use, short enough to keep disk bounded. */
    public static final long TTL_MS = 3600L * 1000L;

    /** UUID shape: short-endpoint-tag + 8 hex chars. */
    private static final Pattern UUID_RE = Pattern.compile("^[a-z]+-[0-9a-f]{8}$");

    /** Spool dir name under each project's data dir. */
    private static final String DUMP_DIRNAME = ".mcp_dumps";

    private final Path dumpDir;

    /**
     * Resolve the spool dir for {@code program} and ensure it exists.
     *
     * @throws IOException if the project dir is unreachable or unwritable
     */
    public DumpManager(Program program) throws IOException {
        if (program == null) {
            throw new IOException("DumpManager requires a Program (no program loaded?)");
        }
        File projectDir = program.getDomainFile().getProjectLocator().getProjectDir();
        if (projectDir == null) {
            throw new IOException("Program has no resolvable project dir");
        }
        this.dumpDir = projectDir.toPath().resolve(DUMP_DIRNAME);
        Files.createDirectories(dumpDir);
    }

    /** Path to the spool dir (for diagnostics; not for direct callers). */
    public Path getDumpDir() {
        return dumpDir;
    }

    /**
     * Write {@code body} to a fresh spool file and return its UUID.
     * Writes go through a {@code .tmp} file + {@code ATOMIC_MOVE} so partial
     * files are never observable via {@link #resolve}.
     */
    public synchronized String spool(String endpointTag, String body) throws IOException {
        sweep();
        String uuid = endpointTag + "-"
            + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        Path target = dumpDir.resolve(uuid);
        Path tmp = dumpDir.resolve(uuid + ".tmp");
        Files.writeString(tmp, body, StandardCharsets.UTF_8);
        Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE);
        writeMeta(uuid, endpointTag, body.length(), countLines(body));
        return uuid;
    }

    /**
     * Resolve a UUID to its on-disk file. Returns {@code null} if the UUID
     * doesn't match the expected shape, the file doesn't exist, or any
     * canonical-path check fails. Safe against directory traversal.
     */
    public File resolve(String uuid) {
        if (uuid == null || !UUID_RE.matcher(uuid).matches()) {
            return null;
        }
        try {
            Path candidate = dumpDir.resolve(uuid);
            if (!Files.exists(candidate)) {
                return null;
            }
            Path canon = candidate.toRealPath();
            Path dumpCanon = dumpDir.toRealPath();
            if (!canon.startsWith(dumpCanon)) {
                Msg.warn(this, "Dump UUID resolved outside dumpDir: " + uuid);
                return null;
            }
            return canon.toFile();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Delete the spool file and its meta sidecar. Idempotent — returns false
     * if there was nothing to delete or the UUID was invalid.
     */
    public synchronized boolean delete(String uuid) {
        File f = resolve(uuid);
        if (f == null) {
            return false;
        }
        File meta = new File(f.getPath() + ".meta");
        boolean metaGone = !meta.exists() || meta.delete();
        boolean bodyGone = f.delete();
        return metaGone && bodyGone;
    }

    /**
     * List active dumps for housekeeping/debug. Sweeps first, then reads
     * each surviving {@code .meta} sidecar into a plain map.
     */
    public synchronized List<Map<String, Object>> list() throws IOException {
        sweep();
        List<Map<String, Object>> out = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dumpDir, "*.meta")) {
            for (Path m : ds) {
                Map<String, Object> entry = readMeta(m);
                if (entry != null) {
                    out.add(entry);
                }
            }
        }
        return out;
    }

    /** Bounded sweep: walks {@code *.meta} files, deletes any older than TTL. */
    private void sweep() {
        long now = System.currentTimeMillis();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dumpDir, "*.meta")) {
            for (Path m : ds) {
                try {
                    FileTime ft = Files.getLastModifiedTime(m);
                    if (now - ft.toMillis() > TTL_MS) {
                        String name = m.getFileName().toString();
                        String uuid = name.substring(0, name.length() - ".meta".length());
                        delete(uuid);
                    }
                } catch (IOException ignored) {
                    // skip — sweep is best-effort
                }
            }
        } catch (IOException e) {
            Msg.warn(this, "DumpManager sweep failed: " + e.getMessage());
        }
    }

    private void writeMeta(String uuid, String endpointTag, long bytes, long lines) throws IOException {
        Path meta = dumpDir.resolve(uuid + ".meta");
        // Hand-rolled JSON to avoid a JSON library dependency. All fields are
        // numeric or fixed-alphabet strings — no escaping needed.
        String json = "{"
            + "\"uuid\":\"" + uuid + "\","
            + "\"endpoint\":\"" + endpointTag + "\","
            + "\"bytes\":" + bytes + ","
            + "\"lines\":" + lines + ","
            + "\"created_ms\":" + System.currentTimeMillis()
            + "}";
        Files.writeString(meta, json, StandardCharsets.UTF_8);
    }

    private Map<String, Object> readMeta(Path metaPath) {
        try {
            String json = Files.readString(metaPath, StandardCharsets.UTF_8);
            // Cheap parse: known shape, no nested objects.
            Map<String, Object> out = new LinkedHashMap<>();
            String uuid = extractStringField(json, "uuid");
            String endpoint = extractStringField(json, "endpoint");
            Long bytes = extractLongField(json, "bytes");
            Long lines = extractLongField(json, "lines");
            Long createdMs = extractLongField(json, "created_ms");
            if (uuid == null || endpoint == null || bytes == null
                || lines == null || createdMs == null) {
                return null;
            }
            out.put("uuid", uuid);
            out.put("endpoint", endpoint);
            out.put("bytes", bytes);
            out.put("lines", lines);
            out.put("created_ms", createdMs);
            out.put("age_seconds", (System.currentTimeMillis() - createdMs) / 1000L);
            return out;
        } catch (IOException e) {
            return null;
        }
    }

    private static String extractStringField(String json, String name) {
        String key = "\"" + name + "\":\"";
        int start = json.indexOf(key);
        if (start < 0) return null;
        start += key.length();
        int end = json.indexOf('"', start);
        if (end < 0) return null;
        return json.substring(start, end);
    }

    private static Long extractLongField(String json, String name) {
        String key = "\"" + name + "\":";
        int start = json.indexOf(key);
        if (start < 0) return null;
        start += key.length();
        int end = start;
        while (end < json.length()
            && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
            end++;
        }
        try {
            return Long.parseLong(json.substring(start, end));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Count {@code \n}-terminated lines in {@code body}. Public so callers can include line counts in spool-response envelopes without re-reading the meta sidecar. */
    public static long countLines(String body) {
        if (body == null || body.isEmpty()) return 0;
        long count = 1;
        for (int i = 0; i < body.length(); i++) {
            if (body.charAt(i) == '\n') count++;
        }
        // Trailing newline shouldn't add a phantom line.
        if (body.charAt(body.length() - 1) == '\n') count--;
        return count;
    }

    /**
     * Stream {@code spoolFile} to {@code os} without materialising the full
     * body in memory. Uses {@link java.io.InputStream#transferTo} which copies
     * via a small internal buffer.
     */
    public static void streamTo(File spoolFile, OutputStream os) throws IOException {
        try (java.io.FileInputStream in = new java.io.FileInputStream(spoolFile)) {
            in.transferTo(os);
        }
    }

    /**
     * Stream a sub-range of {@code spoolFile} to {@code os}. Used by the
     * {@code Range:} header path on the dump endpoint.
     */
    public static void streamRange(File spoolFile, long fromInclusive, long toInclusive,
                                   OutputStream os) throws IOException {
        long want = toInclusive - fromInclusive + 1;
        try (RandomAccessFile raf = new RandomAccessFile(spoolFile, "r")) {
            raf.seek(fromInclusive);
            byte[] buf = new byte[8192];
            while (want > 0) {
                int n = raf.read(buf, 0, (int) Math.min(buf.length, want));
                if (n <= 0) break;
                os.write(buf, 0, n);
                want -= n;
            }
        }
    }
}
