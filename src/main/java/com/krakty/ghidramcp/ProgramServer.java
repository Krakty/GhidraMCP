package com.krakty.ghidramcp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * One HttpServer instance bound to a single Program on a single port.
 *
 * The server tracks in-flight requests with a counter so that shutdown can wait
 * for the requests to drain (with a 5-second timeout) before actually closing
 * the underlying socket. This avoids tearing down a handler mid-request when a
 * program closes.
 */
public class ProgramServer {

    private final Program program;
    private final String slotName;
    private final int port;
    private final HttpServer http;
    private final AtomicInteger inFlight = new AtomicInteger(0);
    private volatile boolean closing = false;

    /** Functional interface for an endpoint handler that knows its bound Program. */
    public interface ProgramHandler {
        void handle(HttpExchange exchange, Program program) throws IOException;
    }

    public ProgramServer(Program program, String slotName, int port) throws IOException {
        this.program = program;
        this.slotName = slotName;
        this.port = port;
        this.http = HttpServer.create(new InetSocketAddress(port), 0);
        this.http.setExecutor(null);
    }

    public Program getProgram()  { return program; }
    public String  getSlotName() { return slotName; }
    public int     getPort()     { return port; }

    /**
     * Register an endpoint handler. The handler is wrapped so that:
     *   - in-flight requests are counted (so shutdown can drain),
     *   - if the server is closing, new requests get 503,
     *   - exceptions become 500 responses (instead of leaving the connection hanging).
     */
    public void register(String path, ProgramHandler handler) {
        http.createContext(path, new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if (closing) {
                    sendPlain(exchange, 503, "Server is shutting down");
                    return;
                }
                inFlight.incrementAndGet();
                try {
                    handler.handle(exchange, program);
                } catch (Exception e) {
                    Msg.error(this, "Handler error on " + path
                        + " (slot=" + slotName + ", port=" + port + ")", e);
                    try {
                        sendPlain(exchange, 500, "Handler error: " + e.getMessage());
                    } catch (IOException ignored) { /* connection already broken */ }
                } finally {
                    inFlight.decrementAndGet();
                }
            }
        });
    }

    public void start() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    http.start();
                    Msg.info(this, "Started ProgramServer slot=" + slotName
                        + " port=" + port + " program=" + program.getName());
                } catch (Exception e) {
                    Msg.error(this, "Failed to start ProgramServer slot=" + slotName
                        + " port=" + port, e);
                }
            }
        }, "GhidraMCP-" + slotName + "-" + port).start();
    }

    /**
     * Mark the server closing and wait up to 5 seconds for in-flight requests
     * to drain, then stop the underlying HttpServer.
     */
    public void shutdown() {
        closing = true;
        long deadline = System.currentTimeMillis() + 5000L;
        while (inFlight.get() > 0 && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(50);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        int remaining = inFlight.get();
        if (remaining > 0) {
            Msg.warn(this, "Shutting down ProgramServer slot=" + slotName
                + " with " + remaining + " in-flight request(s) still running");
        }
        try {
            http.stop(0);
            Msg.info(this, "Stopped ProgramServer slot=" + slotName + " port=" + port);
        } catch (Exception e) {
            Msg.error(this, "Error stopping ProgramServer slot=" + slotName, e);
        }
    }

    private static void sendPlain(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (java.io.OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
