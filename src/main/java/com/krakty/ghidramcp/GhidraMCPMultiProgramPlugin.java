package com.krakty.ghidramcp;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptInfo;
import generic.jar.ResourceFile;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.FileWriter;
import java.io.BufferedWriter;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import java.io.ByteArrayInputStream;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

// Version Tracking
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.db.VTSessionContentHandler;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.correlator.program.*;
import ghidra.feature.vt.api.markuptype.*;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.AddressSetView;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "GhidraMCP Multi-Program HTTP server plugin (Krakty)",
    description = "Per-tool HTTP server: each CodeBrowser binds its own port in 8090-8099 and serves the active program. Clients use /info on each port for discovery."
)
public class GhidraMCPMultiProgramPlugin extends Plugin {

    /**
     * Per-tool plugin: each CodeBrowser instance binds its own HTTP server on
     * the first free port in PORT_RANGE_LOW..PORT_RANGE_HIGH and serves the
     * program currently active in that tool via getCurrentProgram(). No JVM
     * singleton, no cross-tool coordination, no discovery server. Each port
     * exposes a /info endpoint clients can scan to discover what's bound.
     */
    public  static final String PLUGIN_VERSION = "0.3.0";
    private static final int PORT_RANGE_LOW  = 8090;
    private static final int PORT_RANGE_HIGH = 8129;

    private HttpServer server;
    private int boundPort = -1;

    /**
     * Spool manager for the to_file=true large-response pattern. Lazy-initialised
     * on first spool/dump request from the program currently bound to this tool.
     * Reset to null on program change; next request rebuilds it against the new
     * project dir.
     */
    private DumpManager dumpManager;
    private Program dumpManagerProgram;

    public GhidraMCPMultiProgramPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPMultiProgramPlugin v" + PLUGIN_VERSION
            + " loading in tool " + tool.getName());

        // Find the first free port in the configured range and bind there.
        for (int p = PORT_RANGE_LOW; p <= PORT_RANGE_HIGH; p++) {
            try {
                startServer(p);
                boundPort = p;
                break;
            }
            catch (java.net.BindException be) {
                // port already in use, try next
            }
            catch (IOException e) {
                Msg.error(this, "Unexpected error starting server on port " + p, e);
            }
        }

        if (boundPort == -1) {
            Msg.error(this, "No free port in range " + PORT_RANGE_LOW + "-" + PORT_RANGE_HIGH
                + " — plugin will be inactive.");
            return;
        }

        Msg.info(this, "GhidraMCPMultiProgramPlugin (tool=" + tool.getName()
            + ") bound to port " + boundPort);
    }


    // ----------------------------------------------------------------------------------
    // Display-name helpers (used by /info)
    // ----------------------------------------------------------------------------------

    /**
     * Date prefix at the start of a program name. Accepts both "05-22-2026-..."
     * and "6-9-2026-..." (unpadded month/day). The captured groups get
     * zero-padded by {@link #extractDatePrefix} so clients always receive
     * canonical MM-DD-YYYY.
     */
    private static final java.util.regex.Pattern DATE_PREFIX =
        java.util.regex.Pattern.compile("^(\\d{1,2})-(\\d{1,2})-(\\d{4})-.*");

    /**
     * Returns the program's display name: the DomainFile name (what shows in
     * the Project tree, which the user may have renamed for visual
     * distinctness — e.g. "05-22-2026-LIVE-eqgame.exe") falling back to
     * Program.getName() if no DomainFile is available.
     */
    private static String effectiveName(Program p) {
        if (p == null) return "";
        try {
            ghidra.framework.model.DomainFile df = p.getDomainFile();
            if (df != null) {
                String n = df.getName();
                if (n != null && !n.isEmpty()) return n;
            }
        }
        catch (Exception ignored) { /* fall through to Program.getName() */ }
        return p.getName();
    }

    /**
     * Returns zero-padded "MM-DD-YYYY" if the program name starts with a
     * recognizable date prefix (padded or unpadded), else empty.
     */
    private static String extractDatePrefix(String programName) {
        if (programName == null) return "";
        java.util.regex.Matcher m = DATE_PREFIX.matcher(programName);
        if (!m.matches()) return "";
        int mm = Integer.parseInt(m.group(1));
        int dd = Integer.parseInt(m.group(2));
        return String.format("%02d-%02d-%s", mm, dd, m.group(3));
    }

    /** Minimal JSON string escaper for the /info handler. */
    private static String jsonString(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else          sb.append(c);
            }
        }
        sb.append('"');
        return sb.toString();
    }

    // ----------------------------------------------------------------------------------
    // Per-tool HTTP server: bound in the constructor, registers every endpoint
    // against getCurrentProgram() so it's naturally scoped to this tool.
    // ----------------------------------------------------------------------------------

    private void startServer(int port) throws IOException {
        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Discovery endpoint: returns metadata about what THIS port serves.
        // Claude (or any client) can scan PORT_RANGE_LOW..PORT_RANGE_HIGH and
        // hit /info on each to learn which port has which program.
        server.createContext("/info", exchange -> {
            Program p = getCurrentProgram();
            String name = effectiveName(p);
            String prefix = extractDatePrefix(name);
            String json = "{"
                + "\"version\":" + jsonString(PLUGIN_VERSION) + ","
                + "\"port\":" + boundPort + ","
                + "\"toolName\":" + jsonString(tool.getName()) + ","
                + "\"name\":" + jsonString(name) + ","
                + "\"datePrefix\":" + jsonString(prefix)
                + "}";
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements

        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean toFile = "true".equals(qparams.get("to_file"));
            respondMaybeSpool(exchange, toFile, "funcs", listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            boolean toFile = "true".equals(qparams.get("to_file"));
            respondMaybeSpool(exchange, toFile, "decomp",
                decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            boolean toFile = "true".equals(qparams.get("to_file"));
            respondMaybeSpool(exchange, toFile, "disasm",
                disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            boolean toFile = "true".equals(qparams.get("to_file"));
            respondMaybeSpool(exchange, toFile, "strs",
                listDefinedStrings(offset, limit, filter));
        });

        // Tier 1 PR 1: symbol-table endpoints.
        server.createContext("/list_symbols", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  200);
            String typeFilter   = qparams.get("type");
            String sourceFilter = qparams.get("source");
            boolean toFile = "true".equals(qparams.get("to_file"));
            respondMaybeSpool(exchange, toFile, "symbols",
                listSymbols(offset, limit, typeFilter, sourceFilter));
        });

        server.createContext("/get_symbol_at", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJson(exchange, getSymbolAt(qparams.get("address")));
        });

        server.createContext("/delete_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange,
                deleteLabel(params.get("address"), params.get("name")));
        });

        // Tier 1 PR 2: function lifecycle.
        server.createContext("/create_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange,
                createFunction(params.get("address"), params.get("name")));
        });

        server.createContext("/delete_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteFunction(params.get("address")));
        });

        server.createContext("/mark_function_thunk", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, markFunctionThunk(
                params.get("address"), params.get("target")));
        });

        // Tier 1 PR 3: DataType endpoints.
        server.createContext("/parse_c_header", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJson(exchange, parseCHeader(params.get("header")));
        });

        server.createContext("/apply_data_type_at", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String clear = params.get("clear");
            boolean clearFirst = (clear == null) || clear.equalsIgnoreCase("true");
            sendResponse(exchange, applyDataTypeAt(
                params.get("address"), params.get("type"), clearFirst));
        });

        server.createContext("/get_data_type", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean toFile = "true".equals(qparams.get("to_file"));
            String body = getDataType(qparams.get("name"));
            if (toFile) {
                respondMaybeSpool(exchange, true, "dtype", body);
            }
            else {
                sendJson(exchange, body);
            }
        });

        server.createContext("/list_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  200);
            boolean toFile = "true".equals(qparams.get("to_file"));
            respondMaybeSpool(exchange, toFile, "dtypes",
                listDataTypes(offset, limit,
                    qparams.get("category"),
                    qparams.get("pattern"),
                    qparams.get("kind")));
        });

        server.createContext("/set_struct_member", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setStructMember(
                params.get("struct"),
                params.get("offset"),
                params.get("current_name"),
                params.get("new_name"),
                params.get("new_type"),
                params.get("comment")));
        });

        // Tier 1 PR 4: bulk operations.
        server.createContext("/apply_labels_from_header", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String header = params.get("header");
            String stripSuffix = params.get("strip_suffix");
            String createMissing = params.get("create_if_missing");
            boolean createIfMissing =
                (createMissing == null) || createMissing.equalsIgnoreCase("true");
            sendJson(exchange, applyLabelsFromHeader(
                header, stripSuffix, createIfMissing));
        });

        server.createContext("/rename_functions_bulk", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJson(exchange, renameFunctionsBulk(
                params.get("header"), params.get("strip_suffix")));
        });

        server.createContext("/set_function_signature_bulk", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJson(exchange, setFunctionSignatureBulk(params.get("text")));
        });

        // Tier 1 PR 5: bookmarks + comment readback.
        server.createContext("/list_bookmarks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  200);
            boolean toFile = "true".equals(qparams.get("to_file"));
            respondMaybeSpool(exchange, toFile, "bookmarks",
                listBookmarks(offset, limit,
                    qparams.get("category"), qparams.get("type")));
        });

        server.createContext("/add_bookmark", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, addBookmark(
                params.get("address"),
                params.get("type"),
                params.get("category"),
                params.get("note")));
        });

        server.createContext("/delete_bookmark", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteBookmark(
                params.get("address"),
                params.get("type"),
                params.get("category")));
        });

        server.createContext("/list_comments_for_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean toFile = "true".equals(qparams.get("to_file"));
            respondMaybeSpool(exchange, toFile, "fn_comments",
                listCommentsForFunction(qparams.get("address")));
        });

        // Tier 1 PR 6: callgraph.
        server.createContext("/get_callgraph", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int depth = parseIntOrDefault(qparams.get("depth"), 2);
            sendJson(exchange, getCallgraph(
                qparams.get("address"), depth, qparams.get("direction")));
        });

        // PR_SCOPE_RUN_SCRIPT: script execution + listing.
        server.createContext("/list_scripts", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  500);
            boolean toFile = "true".equals(qparams.get("to_file"));
            String body = listScripts(offset, limit,
                qparams.get("category"), qparams.get("pattern"), qparams.get("language"));
            if (toFile) {
                respondMaybeSpool(exchange, true, "scripts", body);
            } else {
                sendJson(exchange, body);
            }
        });

        server.createContext("/run_script", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String scriptName = params.get("script_name");
            String scriptBody = params.get("script_body");
            String argsRaw = params.get("args");
            String[] args = null;
            if (argsRaw != null && !argsRaw.isEmpty()) {
                args = argsRaw.split("\n");
            }
            boolean toFile = "true".equals(params.get("to_file"));
            String txName = params.get("transaction_name");
            sendJson(exchange,
                runScript(exchange, scriptName, scriptBody, args, toFile, txName));
        });

        // Spool fetch endpoints: GET /dump (list), GET/DELETE /dump/{uuid}.
        // The Java HttpServer uses longest-prefix matching; "/dump/" catches
        // ID requests, "/dump" catches the list path.
        server.createContext("/dump/", exchange -> handleDumpById(exchange));
        server.createContext("/dump",  exchange -> handleDumpList(exchange));

        // Open a program from the project into this CodeBrowser tool.
        server.createContext("/open_program", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJson(exchange, openProgramFromProject(params.get("path")));
        });

        // Version Tracking endpoints
        server.createContext("/vt_list_sessions", exchange -> {
            sendJson(exchange, vtListSessions());
        });

        server.createContext("/vt_create_session", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJson(exchange, vtCreateSession(
                params.get("name"),
                params.get("source_program"),
                params.get("dest_program")));
        });

        server.createContext("/vt_run_correlators", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJson(exchange, vtRunCorrelators(
                params.get("session"),
                params.get("algorithms")));
        });

        server.createContext("/vt_list_matches", exchange -> {
            Map<String, String> qp = parseQueryParams(exchange);
            sendJson(exchange, vtListMatches(
                qp.get("session"),
                qp.get("min_score"),
                qp.get("status"),
                parseIntOrDefault(qp.get("offset"), 0),
                parseIntOrDefault(qp.get("limit"), 200)));
        });

        server.createContext("/vt_accept_matches", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJson(exchange, vtAcceptMatches(
                params.get("session"),
                params.get("min_score")));
        });

        server.createContext("/vt_apply_markups", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJson(exchange, vtApplyMarkups(
                params.get("session"),
                params.get("types")));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    //
    // Each method now has a "WithProgram" core that takes an explicit Program;
    // the legacy zero-program-arg variant just delegates to getCurrentProgram().
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return getAllFunctionNames(program, offset, limit);
    }

    private String getAllFunctionNames(Program program, int offset, int limit) {
        if (program == null) return "No program loaded";
        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return getAllClassNames(program, offset, limit);
    }

    private String getAllClassNames(Program program, int offset, int limit) {
        if (program == null) return "No program loaded";
        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return listSegments(program, offset, limit);
    }

    private String listSegments(Program program, int offset, int limit) {
        if (program == null) return "No program loaded";
        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return listImports(program, offset, limit);
    }

    private String listImports(Program program, int offset, int limit) {
        if (program == null) return "No program loaded";
        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return listExports(program, offset, limit);
    }

    private String listExports(Program program, int offset, int limit) {
        if (program == null) return "No program loaded";
        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return listNamespaces(program, offset, limit);
    }

    private String listNamespaces(Program program, int offset, int limit) {
        if (program == null) return "No program loaded";
        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return listDefinedData(program, offset, limit);
    }

    private String listDefinedData(Program program, int offset, int limit) {
        if (program == null) return "No program loaded";
        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return searchFunctionsByName(program, searchTerm, offset, limit);
    }

    private String searchFunctionsByName(Program program, String searchTerm, int offset, int limit) {
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";

        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }

        Collections.sort(matches);

        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return decompileFunctionByName(program, name);
    }

    private String decompileFunctionByName(Program program, String name) {
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        return renameFunction(program, oldName, newName);
    }

    private boolean renameFunction(Program program, String oldName, String newName) {
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;
        renameDataAtAddress(program, addressStr, newName);
    }

    private void renameDataAtAddress(Program program, String addressStr, String newName) {
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    SymbolTable symTable = program.getSymbolTable();
                    Symbol symbol = symTable.getPrimarySymbol(addr);
                    if (data != null) {
                        // Data item already defined — rename or create label
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    } else {
                        // v0.2.1: data not defined — still create a bare label.
                        // This lets bulk-labeling tools annotate data symbols whose
                        // addresses Ghidra's auto-analysis didn't classify as data.
                        if (symbol != null && !symbol.getName().equals(newName)) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else if (symbol == null) {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return renameVariableInFunction(program, functionName, oldVarName, newVarName);
    }

    private String renameVariableInFunction(Program program, String functionName, String oldVarName, String newVarName) {
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();

            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return getFunctionByAddress(program, addressStr);
    }

    private String getFunctionByAddress(Program program, String addressStr) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI.
     * NOTE: This is a tool-level (not program-level) state, so per-program
     * servers also resolve via the tool's CodeViewerService -- the answer
     * reflects whichever program is currently active in the UI.
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI (legacy variant).
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * Per-program variant: only returns a function if the GUI's current location
     * is inside the bound program. Otherwise reports that the bound program is
     * not the active one.
     */
    private String getCurrentFunction(Program program) {
        if (program == null) return "No program loaded";
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program activeProgram = getCurrentProgram();
        if (activeProgram != program) {
            return "Bound program (" + program.getName()
                + ") is not the currently-active tab; current-function unavailable for this slot";
        }

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return listFunctions(program);
    }

    private String listFunctions(Program program) {
        if (program == null) return "No program loaded";
        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n",
                func.getName(),
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return decompileFunctionByAddress(program, addressStr);
    }

    private String decompileFunctionByAddress(Program program, String addressStr) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted())
                ? result.getDecompiledFunction().getC()
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return disassembleFunction(program, addressStr);
    }

    private String disassembleFunction(Program program, String addressStr) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n",
                    instr.getAddress(),
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        return setCommentAtAddress(program, addressStr, comment, commentType, transactionName);
    }

    private boolean setCommentAtAddress(Program program, String addressStr, String comment, int commentType, String transactionName) {
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    private boolean setDecompilerComment(Program program, String addressStr, String comment) {
        return setCommentAtAddress(program, addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    private boolean setDisassemblyComment(Program program, String addressStr, String comment) {
        return setCommentAtAddress(program, addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        return renameFunctionByAddress(program, functionAddrStr, newName);
    }

    private boolean renameFunctionByAddress(Program program, String functionAddrStr, String newName) {
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        return setFunctionPrototype(program, functionAddrStr, prototype);
    }

    private PrototypeResult setFunctionPrototype(Program program, String functionAddrStr, String prototype) {
        // Input validation
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() ->
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype,
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(),
                CodeUnit.PLATE_COMMENT,
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms =
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        return setLocalVariableType(program, functionAddrStr, variableName, newType);
    }

    private boolean setLocalVariableType(Program program, String functionAddrStr, String variableName, String newType) {
        // Input validation
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() ->
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr,
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName +
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return getXrefsTo(program, addressStr, offset, limit);
    }

    private String getXrefsTo(Program program, String addressStr, int offset, int limit) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();

            ReferenceIterator refIter = refManager.getReferencesTo(addr);

            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return getXrefsFrom(program, addressStr, offset, limit);
    }

    private String getXrefsFrom(Program program, String addressStr, int offset, int limit) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();

            Reference[] references = refManager.getReferencesFrom(addr);

            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();

                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }

                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return getFunctionXrefs(program, functionName, offset, limit);
    }

    private String getFunctionXrefs(Program program, String functionName, int offset, int limit) {
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);

                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();

                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }

            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return listDefinedStrings(program, offset, limit, filter);
    }

    private String listDefinedStrings(Program program, int offset, int limit, String filter) {
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();

            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";

                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }

        return paginateList(lines, offset, limit);
    }

    // ----------------------------------------------------------------------------------
    // Symbol-table endpoints (Tier 1 PR 1)
    // ----------------------------------------------------------------------------------

    private String listSymbols(int offset, int limit, String typeFilter, String sourceFilter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return listSymbols(program, offset, limit, typeFilter, sourceFilter);
    }

    /**
     * Walk every entry in the SymbolTable (the whole-program one, not just
     * defined Data), optionally filter by symbol type or source. Returns one
     * line per symbol:
     *
     * <pre>
     * &lt;address&gt; &lt;type&gt; &lt;source&gt; &lt;namespace&gt;::&lt;name&gt;
     * </pre>
     *
     * Address has no leading {@code 0x}; namespace is omitted when global.
     * Designed to be greppable from the agent side; pair with {@code to_file=true}
     * for large binaries.
     *
     * @param typeFilter case-insensitive {@link SymbolType} name, or null/empty/"all"
     * @param sourceFilter case-insensitive {@link SourceType} name, or null/empty/"all"
     */
    private String listSymbols(Program program, int offset, int limit,
                               String typeFilter, String sourceFilter) {
        if (program == null) return "No program loaded";
        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        SymbolType wantType = parseSymbolType(typeFilter);
        SourceType wantSource = parseSourceType(sourceFilter);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s == null) continue;
            if (wantType != null && s.getSymbolType() != wantType) continue;
            if (wantSource != null && s.getSource() != wantSource) continue;
            lines.add(formatSymbolLine(s));
        }
        return paginateList(lines, offset, limit);
    }

    /** Format a Symbol as "<addr> <type> <source> <namespace>::<name>". */
    private static String formatSymbolLine(Symbol s) {
        Address addr = s.getAddress();
        String addrStr = (addr != null) ? addr.toString() : "?";
        Namespace ns = s.getParentNamespace();
        String qual = (ns != null && !ns.isGlobal())
            ? ns.getName(true) + "::" + s.getName()
            : s.getName();
        return addrStr + " " + s.getSymbolType().toString()
            + " " + s.getSource().toString() + " " + qual;
    }

    /** Parse "function"/"label"/"all"/null into a {@link SymbolType}, or null for any. */
    private static SymbolType parseSymbolType(String filter) {
        if (filter == null || filter.isEmpty() || filter.equalsIgnoreCase("all")) {
            return null;
        }
        String f = filter.toUpperCase();
        switch (f) {
            case "FUNCTION":   return SymbolType.FUNCTION;
            case "LABEL":      return SymbolType.LABEL;
            case "PARAMETER":  return SymbolType.PARAMETER;
            case "LOCAL_VAR":  return SymbolType.LOCAL_VAR;
            case "GLOBAL_VAR": return SymbolType.GLOBAL_VAR;
            case "NAMESPACE":  return SymbolType.NAMESPACE;
            case "CLASS":      return SymbolType.CLASS;
            case "LIBRARY":    return SymbolType.LIBRARY;
            default:           return null;  // unrecognised → no filter
        }
    }

    /** Parse "user_defined"/"analysis"/"imported"/"default"/null. */
    private static SourceType parseSourceType(String filter) {
        if (filter == null || filter.isEmpty() || filter.equalsIgnoreCase("all")) {
            return null;
        }
        String f = filter.toUpperCase();
        switch (f) {
            case "USER_DEFINED": return SourceType.USER_DEFINED;
            case "ANALYSIS":     return SourceType.ANALYSIS;
            case "IMPORTED":     return SourceType.IMPORTED;
            case "DEFAULT":      return SourceType.DEFAULT;
            default:             return null;
        }
    }

    private String getSymbolAt(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\":\"No program loaded\"}";
        return getSymbolAt(program, addressStr);
    }

    /**
     * Return every symbol at {@code addressStr} as a JSON array. There can be
     * more than one (primary + aliases); the primary is flagged. Empty array
     * means no symbol there.
     */
    private String getSymbolAt(Program program, String addressStr) {
        if (program == null) return "{\"error\":\"No program loaded\"}";
        if (addressStr == null || addressStr.isEmpty()) {
            return "{\"error\":\"address parameter required\"}";
        }
        Address addr;
        try {
            addr = program.getAddressFactory().getAddress(addressStr);
        }
        catch (Exception e) {
            return "{\"error\":\"invalid address: " + jsonEscape(addressStr) + "\"}";
        }
        if (addr == null) return "[]";

        SymbolTable table = program.getSymbolTable();
        Symbol[] syms = table.getSymbols(addr);
        if (syms == null || syms.length == 0) return "[]";

        StringBuilder sb = new StringBuilder();
        sb.append('[');
        boolean first = true;
        for (Symbol s : syms) {
            if (s == null) continue;
            if (!first) sb.append(',');
            first = false;
            sb.append('{');
            sb.append("\"name\":\"").append(jsonEscape(s.getName())).append("\",");
            sb.append("\"address\":\"").append(s.getAddress()).append("\",");
            sb.append("\"type\":\"").append(s.getSymbolType()).append("\",");
            sb.append("\"source\":\"").append(s.getSource()).append("\",");
            sb.append("\"primary\":").append(s.isPrimary()).append(',');
            Namespace ns = s.getParentNamespace();
            sb.append("\"namespace\":\"")
              .append(jsonEscape(ns != null ? ns.getName(true) : ""))
              .append("\"");
            sb.append('}');
        }
        sb.append(']');
        return sb.toString();
    }

    private String deleteLabel(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return deleteLabel(program, addressStr, name);
    }

    /**
     * Delete a label by address, name, or both. Either parameter alone is
     * accepted; supplying both narrows the match. Wraps the removal in a
     * transaction so the operation is undoable in Ghidra's GUI.
     *
     * Returns the count of symbols removed as a short text payload.
     */
    private String deleteLabel(Program program, String addressStr, String name) {
        if (program == null) return "No program loaded";
        if ((addressStr == null || addressStr.isEmpty())
            && (name == null || name.isEmpty())) {
            return "Specify address and/or name";
        }

        SymbolTable table = program.getSymbolTable();
        List<Symbol> targets = new ArrayList<>();

        if (addressStr != null && !addressStr.isEmpty()) {
            Address addr;
            try { addr = program.getAddressFactory().getAddress(addressStr); }
            catch (Exception e) { return "invalid address: " + addressStr; }
            if (addr == null) return "invalid address: " + addressStr;
            Symbol[] at = table.getSymbols(addr);
            if (at != null) {
                for (Symbol s : at) {
                    if (s == null) continue;
                    if (name == null || name.isEmpty() || name.equals(s.getName())) {
                        targets.add(s);
                    }
                }
            }
        }
        else {
            // name-only path: walk every namespace lookup
            SymbolIterator iter = table.getSymbols(name);
            while (iter.hasNext()) {
                Symbol s = iter.next();
                if (s != null) targets.add(s);
            }
        }

        if (targets.isEmpty()) return "0 symbols matched";

        int tx = program.startTransaction("MCP delete_label");
        int removed = 0;
        try {
            for (Symbol s : targets) {
                // removeSymbolSpecial wraps the per-type rules
                // (e.g. won't kill a primary function symbol that owns a Function).
                if (s.delete()) removed++;
            }
            program.endTransaction(tx, true);
        }
        catch (Exception e) {
            program.endTransaction(tx, false);
            return "delete failed: " + e.getMessage();
        }
        return "removed " + removed + " of " + targets.size() + " matched";
    }

    // ----------------------------------------------------------------------------------
    // Function lifecycle endpoints (Tier 1 PR 2)
    // ----------------------------------------------------------------------------------

    private String createFunction(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return createFunction(program, addressStr, name);
    }

    /**
     * Create a function at {@code addressStr} using {@link CreateFunctionCmd},
     * which auto-discovers the function body via flow analysis. Optional
     * {@code name} sets the function name; if null/empty Ghidra picks
     * {@code FUN_<addr>}.
     *
     * Refuses to clobber an existing function at the address — callers should
     * {@code delete_function} first if they want to recreate.
     */
    private String createFunction(Program program, String addressStr, String name) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) {
            return "address parameter required";
        }
        Address addr;
        try { addr = program.getAddressFactory().getAddress(addressStr); }
        catch (Exception e) { return "invalid address: " + addressStr; }
        if (addr == null) return "invalid address: " + addressStr;

        Function existing = program.getFunctionManager().getFunctionAt(addr);
        if (existing != null) {
            return "function already exists at " + addr
                + " (" + existing.getName() + "); delete it first to recreate";
        }

        int tx = program.startTransaction("MCP create_function");
        try {
            String useName = (name != null && !name.isEmpty()) ? name : null;
            CreateFunctionCmd cmd = new CreateFunctionCmd(
                useName, addr, null, SourceType.USER_DEFINED);
            boolean ok = cmd.applyTo(program);
            program.endTransaction(tx, ok);
            if (!ok) {
                return "create failed: "
                    + (cmd.getStatusMsg() != null ? cmd.getStatusMsg() : "unknown");
            }
            Function created = program.getFunctionManager().getFunctionAt(addr);
            String finalName = (created != null) ? created.getName() : "?";
            return "created function " + finalName + " at " + addr;
        }
        catch (Exception e) {
            program.endTransaction(tx, false);
            return "create failed: " + e.getMessage();
        }
    }

    private String deleteFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return deleteFunction(program, addressStr);
    }

    /**
     * Remove the function at {@code addressStr} from the FunctionManager. The
     * underlying code/disassembly stays — only the function classification is
     * dropped. Wrap in a transaction so it's undoable.
     */
    private String deleteFunction(Program program, String addressStr) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) {
            return "address parameter required";
        }
        Address addr;
        try { addr = program.getAddressFactory().getAddress(addressStr); }
        catch (Exception e) { return "invalid address: " + addressStr; }
        if (addr == null) return "invalid address: " + addressStr;

        Function fn = program.getFunctionManager().getFunctionAt(addr);
        if (fn == null) return "no function at " + addr;
        String oldName = fn.getName();

        int tx = program.startTransaction("MCP delete_function");
        boolean ok;
        try {
            ok = program.getFunctionManager().removeFunction(addr);
            program.endTransaction(tx, ok);
        }
        catch (Exception e) {
            program.endTransaction(tx, false);
            return "delete failed: " + e.getMessage();
        }
        return ok
            ? "deleted function " + oldName + " at " + addr
            : "delete failed at " + addr;
    }

    private String markFunctionThunk(String addressStr, String targetAddrStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return markFunctionThunk(program, addressStr, targetAddrStr);
    }

    /**
     * Mark the function at {@code addressStr} as a thunk to the function at
     * {@code targetAddrStr}. Pass {@code targetAddrStr == "clear"} (or empty)
     * to clear the thunk flag and detach.
     *
     * Ghidra's decompiler uses thunk relationships to redirect call sites to
     * the thunked function — useful for jump-table stubs that just JMP into
     * a real function.
     */
    private String markFunctionThunk(Program program, String addressStr, String targetAddrStr) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) {
            return "address parameter required";
        }
        Address addr;
        try { addr = program.getAddressFactory().getAddress(addressStr); }
        catch (Exception e) { return "invalid address: " + addressStr; }
        if (addr == null) return "invalid address: " + addressStr;

        Function fn = program.getFunctionManager().getFunctionAt(addr);
        if (fn == null) return "no function at " + addr;

        boolean clear = targetAddrStr == null
            || targetAddrStr.isEmpty()
            || targetAddrStr.equalsIgnoreCase("clear");

        Function target = null;
        Address targetAddr = null;
        if (!clear) {
            try { targetAddr = program.getAddressFactory().getAddress(targetAddrStr); }
            catch (Exception e) { return "invalid target address: " + targetAddrStr; }
            if (targetAddr == null) return "invalid target address: " + targetAddrStr;
            target = program.getFunctionManager().getFunctionAt(targetAddr);
            if (target == null) return "no function at target " + targetAddr;
        }

        int tx = program.startTransaction("MCP mark_function_thunk");
        try {
            fn.setThunkedFunction(target);
            program.endTransaction(tx, true);
        }
        catch (Exception e) {
            program.endTransaction(tx, false);
            return "set thunk failed: " + e.getMessage();
        }
        return clear
            ? "cleared thunk at " + addr
            : "marked " + addr + " (" + fn.getName() + ") as thunk -> "
                + targetAddr + " (" + target.getName() + ")";
    }

    // ----------------------------------------------------------------------------------
    // DataType endpoints (Tier 1 PR 3)
    // ----------------------------------------------------------------------------------

    private String parseCHeader(String headerText) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\":\"No program loaded\"}";
        return parseCHeader(program, headerText);
    }

    /**
     * Parse the given C source into the program's DataTypeManager. Uses the
     * same {@link CParser} as Ghidra's GUI {@code File -> Parse C Source}.
     * CParser builds its own type maps as it parses; we then iterate those
     * maps and explicitly {@link DataTypeManager#addDataType} each one — the
     * implicit "add as you go" behaviour the API name suggests doesn't
     * actually happen.
     *
     * Forward-declared / referenced types not yet present get created as
     * opaque/undefined and listed in the response so the agent knows what to
     * fill in next. Transaction-wrapped.
     */
    private String parseCHeader(Program program, String headerText) {
        if (program == null) return "{\"error\":\"No program loaded\"}";
        if (headerText == null || headerText.isEmpty()) {
            return "{\"error\":\"header text required\"}";
        }
        DataTypeManager dtm = program.getDataTypeManager();

        int tx = program.startTransaction("MCP parse_c_header");
        boolean success = false;
        String errorMsg = null;
        String parseMessages = null;
        List<String> added = new ArrayList<>();
        try {
            CParser parser = new CParser(dtm);
            parser.parse(new ByteArrayInputStream(
                headerText.getBytes(StandardCharsets.UTF_8)));
            success = parser.didParseSucceed();
            parseMessages = parser.getParseMessages();

            // Commit each parsed type to the DTM. CParser collects them in
            // these per-kind maps but doesn't add them itself.
            ghidra.program.model.data.DataTypeConflictHandler handler =
                ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;
            commitParsedTypes(dtm, parser.getComposites(),   handler, added);
            commitParsedTypes(dtm, parser.getEnums(),        handler, added);
            commitParsedTypes(dtm, parser.getDeclarations(), handler, added);
            commitParsedTypes(dtm, parser.getTypes(),        handler, added);
            commitParsedTypes(dtm, parser.getFunctions(),    handler, added);
        }
        catch (ParseException e) {
            errorMsg = e.getMessage();
            success = false;
        }
        catch (Exception e) {
            errorMsg = "unexpected: " + e.getMessage();
            success = false;
        }
        finally {
            program.endTransaction(tx, success);
        }
        Collections.sort(added);

        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"successful\":").append(success).append(',');
        sb.append("\"added\":[");
        boolean first = true;
        for (String p : added) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(jsonEscape(p)).append('"');
        }
        sb.append("],");
        sb.append("\"added_count\":").append(added.size());
        if (parseMessages != null && !parseMessages.isEmpty()) {
            sb.append(",\"messages\":\"")
              .append(jsonEscape(parseMessages)).append('"');
        }
        if (errorMsg != null) {
            sb.append(",\"error\":\"").append(jsonEscape(errorMsg)).append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Add each entry in {@code parsedMap} to {@code dtm} using {@code handler}
     * for collision resolution, and record the final pathname of each
     * successful add in {@code addedOut}. Failures are best-effort: a type
     * that can't be added (already exists with conflicts, etc.) is skipped
     * rather than aborting the whole parse.
     */
    private static void commitParsedTypes(DataTypeManager dtm,
        java.util.Map<String, DataType> parsedMap,
        ghidra.program.model.data.DataTypeConflictHandler handler,
        List<String> addedOut)
    {
        if (parsedMap == null) return;
        for (DataType dt : parsedMap.values()) {
            if (dt == null) continue;
            try {
                DataType resolved = dtm.addDataType(dt, handler);
                if (resolved != null) {
                    String p = resolved.getPathName();
                    if (!addedOut.contains(p)) addedOut.add(p);
                }
            }
            catch (Exception e) {
                // log + skip — best-effort commit per type
                Msg.warn(GhidraMCPMultiProgramPlugin.class,
                    "parse_c_header: skipped " + dt.getName()
                        + ": " + e.getMessage());
            }
        }
    }

    /**
     * Strict type resolver for the Tier 1 PR 3 endpoints. Unlike
     * {@link #resolveDataType}, this returns {@code null} on miss instead of
     * silently falling back to {@code int}/{@code void*}. Handles trailing
     * {@code *}s as pointer wrappers (so {@code "CXWnd*"} resolves to a
     * pointer to {@code /CXWnd}).
     */
    private DataType resolveDataTypeStrict(DataTypeManager dtm, String typeName) {
        if (dtm == null || typeName == null) return null;
        String t = typeName.trim();
        if (t.isEmpty()) return null;

        // Strip and count trailing '*' for pointer levels.
        int ptrLevels = 0;
        while (t.endsWith("*")) {
            ptrLevels++;
            t = t.substring(0, t.length() - 1).trim();
        }
        if (t.isEmpty()) return null;

        DataType base = findDataTypeByNameInAllCategories(dtm, t);
        if (base == null) {
            base = dtm.getDataType("/" + t);
        }
        if (base == null && t.startsWith("/")) {
            base = dtm.getDataType(t);
        }
        if (base == null) return null;

        // Use the dtm-bound constructor so the pointer picks up the program's
        // default pointer size (8 bytes on x64, 4 on x86). Without the dtm
        // the constructor falls back to a 4-byte pointer regardless of arch.
        for (int i = 0; i < ptrLevels; i++) {
            base = new PointerDataType(base, dtm);
        }
        return base;
    }

    private String applyDataTypeAt(String addressStr, String typeName, boolean clearFirst) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return applyDataTypeAt(program, addressStr, typeName, clearFirst);
    }

    /**
     * Apply a named type from the DTM at {@code addressStr}. When
     * {@code clearFirst} is true (the default), existing code units in the
     * affected range are cleared first so the apply is idempotent. The
     * underlying {@code Listing.createData} is wrapped in a transaction.
     */
    private String applyDataTypeAt(Program program, String addressStr,
                                   String typeName, boolean clearFirst) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) {
            return "address parameter required";
        }
        if (typeName == null || typeName.isEmpty()) {
            return "type parameter required";
        }
        Address addr;
        try { addr = program.getAddressFactory().getAddress(addressStr); }
        catch (Exception e) { return "invalid address: " + addressStr; }
        if (addr == null) return "invalid address: " + addressStr;

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = resolveDataTypeStrict(dtm, typeName);
        if (dt == null) return "type not found: " + typeName;

        int len = dt.getLength();
        if (len <= 0) {
            return "type has unknown size: " + typeName;
        }

        int tx = program.startTransaction("MCP apply_data_type_at");
        try {
            if (clearFirst) {
                Address end;
                try { end = addr.add(len - 1); }
                catch (Exception e) { return "address arithmetic failed"; }
                program.getListing().clearCodeUnits(addr, end, false);
            }
            Data data = program.getListing().createData(addr, dt);
            program.endTransaction(tx, data != null);
            if (data == null) {
                return "createData returned null (conflicting data at " + addr + "?)";
            }
            return "applied " + dt.getPathName() + " at " + addr
                + " (" + len + " bytes)";
        }
        catch (Exception e) {
            program.endTransaction(tx, false);
            return "apply failed: " + e.getMessage();
        }
    }

    private String getDataType(String typeName) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\":\"No program loaded\"}";
        return getDataType(program, typeName);
    }

    /**
     * Return a JSON description of {@code typeName}. For Structures, the
     * "members" array lists every field with offset, name, type pathname,
     * length, and optional comment. For other DataTypes the response is a
     * compact descriptor.
     */
    private String getDataType(Program program, String typeName) {
        if (program == null) return "{\"error\":\"No program loaded\"}";
        if (typeName == null || typeName.isEmpty()) {
            return "{\"error\":\"name required\"}";
        }
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = resolveDataTypeStrict(dtm, typeName);
        if (dt == null) {
            return "{\"error\":\"type not found: " + jsonEscape(typeName) + "\"}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"name\":\"").append(jsonEscape(dt.getName())).append("\",");
        sb.append("\"path\":\"").append(jsonEscape(dt.getPathName())).append("\",");
        sb.append("\"kind\":\"").append(jsonEscape(dt.getClass().getSimpleName())).append("\",");
        sb.append("\"length\":").append(dt.getLength());
        if (dt instanceof Structure) {
            Structure s = (Structure) dt;
            sb.append(",\"members\":[");
            boolean first = true;
            for (DataTypeComponent c : s.getDefinedComponents()) {
                if (!first) sb.append(',');
                first = false;
                sb.append('{');
                sb.append("\"offset\":").append(c.getOffset()).append(',');
                sb.append("\"ordinal\":").append(c.getOrdinal()).append(',');
                String fname = c.getFieldName();
                sb.append("\"name\":\"").append(jsonEscape(fname != null ? fname : ""))
                  .append("\",");
                DataType ct = c.getDataType();
                sb.append("\"type\":\"")
                  .append(jsonEscape(ct != null ? ct.getPathName() : "?"))
                  .append("\",");
                sb.append("\"length\":").append(c.getLength());
                String cm = c.getComment();
                if (cm != null && !cm.isEmpty()) {
                    sb.append(",\"comment\":\"").append(jsonEscape(cm)).append('"');
                }
                sb.append('}');
            }
            sb.append(']');
        }
        sb.append('}');
        return sb.toString();
    }

    private String listDataTypes(int offset, int limit, String category,
                                 String pattern, String kind) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return listDataTypes(program, offset, limit, category, pattern, kind);
    }

    /**
     * Enumerate the DTM, optionally filtered. Output is one line per type:
     *
     * <pre>
     * &lt;path&gt; &lt;kind&gt; &lt;length&gt;
     * </pre>
     *
     * Designed for greppability; pair with {@code to_file=true} for full dumps.
     *
     * @param category category-path prefix to filter on (e.g. {@code /MyHdr})
     * @param pattern  case-insensitive substring match against the pathname
     * @param kind     case-insensitive substring of the DataType class name
     *                 (e.g. {@code structure}, {@code enum}, {@code typedef})
     */
    private String listDataTypes(Program program, int offset, int limit,
                                 String category, String pattern, String kind) {
        if (program == null) return "No program loaded";
        DataTypeManager dtm = program.getDataTypeManager();

        String catPrefix = (category != null && !category.isEmpty()) ? category : null;
        String pat = (pattern != null && !pattern.isEmpty())
            ? pattern.toLowerCase() : null;
        String kindMatch = (kind != null && !kind.isEmpty() && !kind.equalsIgnoreCase("all"))
            ? kind.toLowerCase() : null;

        List<String> lines = new ArrayList<>();
        java.util.Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (dt == null) continue;
            String path = dt.getPathName();
            if (catPrefix != null && !path.startsWith(catPrefix)) continue;
            if (pat != null && !path.toLowerCase().contains(pat)) continue;
            String dtKind = dt.getClass().getSimpleName();
            if (kindMatch != null && !dtKind.toLowerCase().contains(kindMatch)) continue;
            lines.add(path + " " + dtKind + " " + dt.getLength());
        }
        Collections.sort(lines);
        return paginateList(lines, offset, limit);
    }

    private String setStructMember(String structName, String offsetStr, String currentName,
                                   String newName, String newType, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return setStructMember(program, structName, offsetStr, currentName,
            newName, newType, comment);
    }

    /**
     * Rename and/or retype one member of {@code structName}. The member can
     * be identified by {@code offsetStr} (a parseable integer) OR by its
     * current field name; supply exactly one. Any of {@code newName},
     * {@code newType}, {@code comment} can be null/empty to leave that
     * attribute alone.
     *
     * For type changes, the new type's length must be {@code &lt;=} the
     * existing component's length — wider replacements that would clobber
     * neighbours are rejected with a clear message.
     */
    private String setStructMember(Program program, String structName, String offsetStr,
                                   String currentName, String newName, String newType,
                                   String comment) {
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "struct parameter required";

        boolean haveOffset = offsetStr != null && !offsetStr.isEmpty();
        boolean haveName   = currentName != null && !currentName.isEmpty();
        if (haveOffset == haveName) {
            return "supply exactly one of offset or current_name";
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = resolveDataTypeStrict(dtm, structName);
        if (!(dt instanceof Structure)) {
            return "not a struct (or not found): " + structName;
        }
        Structure s = (Structure) dt;

        DataTypeComponent target = null;
        if (haveOffset) {
            int off;
            try { off = (int) Long.decode(offsetStr).longValue(); }
            catch (NumberFormatException e) { return "invalid offset: " + offsetStr; }
            target = s.getComponentContaining(off);
            if (target == null || target.getOffset() != off) {
                return "no member at offset 0x" + Integer.toHexString(off);
            }
        }
        else {
            for (DataTypeComponent c : s.getDefinedComponents()) {
                String f = c.getFieldName();
                if (f != null && f.equals(currentName)) {
                    target = c;
                    break;
                }
            }
            if (target == null) return "no member named " + currentName;
        }

        DataType replacementType = null;
        if (newType != null && !newType.isEmpty()) {
            replacementType = resolveDataTypeStrict(dtm, newType);
            if (replacementType == null) return "new type not found: " + newType;
            if (replacementType.getLength() > target.getLength()) {
                return "new type (" + replacementType.getLength()
                    + " bytes) wider than existing member ("
                    + target.getLength() + " bytes); won't clobber neighbours";
            }
        }

        int tx = program.startTransaction("MCP set_struct_member");
        boolean ok = false;
        String error = null;
        try {
            String finalName = (newName != null && !newName.isEmpty())
                ? newName : target.getFieldName();
            String finalComment = (comment != null) ? comment : target.getComment();
            if (replacementType != null) {
                // Use replaceAtOffset so the slot keeps the same offset; let
                // Ghidra reflow any padding/undefined neighbors.
                s.replaceAtOffset(target.getOffset(), replacementType,
                    replacementType.getLength(), finalName, finalComment);
            }
            else {
                // Type unchanged — direct field/comment edit on the component.
                // Let any DuplicateNameException / InvalidInputException
                // bubble up to the outer catch so the transaction is always
                // ended (no early-return leak).
                if (newName != null && !newName.isEmpty()) {
                    target.setFieldName(newName);
                }
                if (comment != null) {
                    target.setComment(comment);
                }
            }
            ok = true;
        }
        catch (Exception e) {
            error = e.getMessage();
        }
        finally {
            program.endTransaction(tx, ok);
        }
        if (!ok) {
            return "set failed: " + (error != null ? error : "unknown");
        }
        return "set member at offset 0x" + Integer.toHexString(target.getOffset())
            + " in " + s.getPathName();
    }

    // ----------------------------------------------------------------------------------
    // Bulk operations (Tier 1 PR 4)
    // ----------------------------------------------------------------------------------

    /**
     * One {@code #define NAME ADDR} pair extracted from a header.
     */
    private static final class DefinePair {
        final String name;
        final long address;
        DefinePair(String name, long address) { this.name = name; this.address = address; }
    }

    /**
     * Parse {@code #define NAME ADDR} lines from a C-style header. Handles:
     * <ul>
     * <li>{@code #define DoCommand 0x140b80e10}</li>
     * <li>{@code #define DoCommand (0x140b80e10)}</li>
     * <li>{@code #define DoCommand        0X140B80E10  // comment}</li>
     * <li>plain decimal addresses (no 0x prefix)</li>
     * </ul>
     * Lines that don't match are silently skipped; the caller surfaces them
     * to the agent if needed via the line count delta.
     */
    private static final java.util.regex.Pattern DEFINE_LINE =
        java.util.regex.Pattern.compile(
            "^\\s*#\\s*define\\s+([A-Za-z_][A-Za-z0-9_]*)\\s+\\(?\\s*"
            + "(?:0[xX]([0-9A-Fa-f]+)|([0-9]+))\\s*\\)?\\s*(?:/\\*.*?\\*/|//.*)?\\s*$");

    private static List<DefinePair> parseDefinePairs(String headerText) {
        List<DefinePair> out = new ArrayList<>();
        if (headerText == null) return out;
        for (String line : headerText.split("\\r?\\n")) {
            java.util.regex.Matcher m = DEFINE_LINE.matcher(line);
            if (!m.matches()) continue;
            String name = m.group(1);
            String hex = m.group(2);
            String dec = m.group(3);
            long addr;
            try {
                addr = (hex != null)
                    ? Long.parseUnsignedLong(hex, 16)
                    : Long.parseUnsignedLong(dec, 10);
            }
            catch (NumberFormatException e) {
                continue;
            }
            out.add(new DefinePair(name, addr));
        }
        return out;
    }

    /**
     * Apply a stripping rule to a name. Currently supports trailing-suffix
     * stripping: if {@code rule} is non-empty and {@code name} ends with it,
     * remove it. Future enhancements can add prefix-strip / regex.
     */
    private static String applyNameRule(String name, String stripSuffix) {
        if (stripSuffix == null || stripSuffix.isEmpty()) return name;
        return name.endsWith(stripSuffix)
            ? name.substring(0, name.length() - stripSuffix.length())
            : name;
    }

    private String applyLabelsFromHeader(String headerText,
                                         String stripSuffix,
                                         boolean createIfMissing) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\":\"No program loaded\"}";
        return applyLabelsFromHeader(program, headerText, stripSuffix, createIfMissing);
    }

    /**
     * Bulk-apply the {@code #define NAME ADDR} pairs in {@code headerText} as
     * function renames / data labels. Mirrors the workflow of MQ-RE's
     * external ApplyEqgameLabels.py — replaces the GUI-only Jython round-trip.
     *
     * For each parsed pair:
     * <ol>
     * <li>Resolve ADDR in the program's address factory.</li>
     * <li>If a function exists at ADDR: rename the function's primary symbol
     *     to NAME (this is "function-name promotion" in the runbook).</li>
     * <li>Else if any symbol exists at ADDR: rename the primary symbol.</li>
     * <li>Else if {@code createIfMissing}: create a USER_DEFINED label.</li>
     * <li>Else: count as skipped.</li>
     * </ol>
     *
     * Wrapped in a single transaction so individual failures don't break the batch.
     */
    private String applyLabelsFromHeader(Program program, String headerText,
                                         String stripSuffix,
                                         boolean createIfMissing) {
        if (program == null) return "{\"error\":\"No program loaded\"}";
        if (headerText == null || headerText.isEmpty()) {
            return "{\"error\":\"header text required\"}";
        }
        List<DefinePair> pairs = parseDefinePairs(headerText);
        if (pairs.isEmpty()) {
            return "{\"parsed\":0,\"renamed_functions\":0,\"renamed_symbols\":0,"
                + "\"created_labels\":0,\"skipped\":0,\"errors\":[]}";
        }

        int renamedFunctions = 0;
        int renamedSymbols = 0;
        int createdLabels = 0;
        int skipped = 0;
        List<String> errors = new ArrayList<>();

        SymbolTable symTable = program.getSymbolTable();
        FunctionManager fm = program.getFunctionManager();

        int tx = program.startTransaction("MCP apply_labels_from_header");
        try {
            for (DefinePair p : pairs) {
                Address addr;
                try { addr = program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(p.address); }
                catch (Exception e) {
                    errors.add(formatBulkError(p.name, p.address,
                        "address conversion: " + e.getMessage()));
                    continue;
                }
                if (addr == null) {
                    errors.add(formatBulkError(p.name, p.address, "address null"));
                    continue;
                }
                String name = applyNameRule(p.name, stripSuffix);

                try {
                    Function fn = fm.getFunctionAt(addr);
                    if (fn != null) {
                        fn.setName(name, SourceType.USER_DEFINED);
                        renamedFunctions++;
                        continue;
                    }
                    Symbol primary = symTable.getPrimarySymbol(addr);
                    if (primary != null) {
                        primary.setName(name, SourceType.USER_DEFINED);
                        renamedSymbols++;
                        continue;
                    }
                    if (createIfMissing) {
                        symTable.createLabel(addr, name, SourceType.USER_DEFINED);
                        createdLabels++;
                    }
                    else {
                        skipped++;
                    }
                }
                catch (Exception e) {
                    errors.add(formatBulkError(p.name, p.address, e.getMessage()));
                }
            }
        }
        finally {
            program.endTransaction(tx, true);
        }

        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"parsed\":").append(pairs.size()).append(',');
        sb.append("\"renamed_functions\":").append(renamedFunctions).append(',');
        sb.append("\"renamed_symbols\":").append(renamedSymbols).append(',');
        sb.append("\"created_labels\":").append(createdLabels).append(',');
        sb.append("\"skipped\":").append(skipped).append(',');
        sb.append("\"errors\":[");
        boolean first = true;
        for (String err : errors) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(jsonEscape(err)).append('"');
        }
        sb.append("]}");
        return sb.toString();
    }

    private static String formatBulkError(String name, long addr, String msg) {
        return name + " @ 0x" + Long.toHexString(addr) + ": " + msg;
    }

    private String renameFunctionsBulk(String headerText, String stripSuffix) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\":\"No program loaded\"}";
        return renameFunctionsBulk(program, headerText, stripSuffix);
    }

    /**
     * Strict variant of apply_labels_from_header: rename function-at-address
     * only. Addresses that aren't already functions are reported in the
     * {@code missing} list, not silently labeled. Useful when the caller
     * wants to know exactly what got promoted and what didn't (e.g., for
     * driving a follow-up create_function pass on the missing entries).
     */
    private String renameFunctionsBulk(Program program, String headerText, String stripSuffix) {
        if (program == null) return "{\"error\":\"No program loaded\"}";
        if (headerText == null || headerText.isEmpty()) {
            return "{\"error\":\"header text required\"}";
        }
        List<DefinePair> pairs = parseDefinePairs(headerText);

        int renamed = 0;
        List<String> missing = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        FunctionManager fm = program.getFunctionManager();
        int tx = program.startTransaction("MCP rename_functions_bulk");
        try {
            for (DefinePair p : pairs) {
                Address addr;
                try { addr = program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(p.address); }
                catch (Exception e) {
                    errors.add(formatBulkError(p.name, p.address,
                        "address conversion: " + e.getMessage()));
                    continue;
                }
                Function fn = fm.getFunctionAt(addr);
                if (fn == null) {
                    missing.add(formatBulkError(p.name, p.address, "not a function"));
                    continue;
                }
                String name = applyNameRule(p.name, stripSuffix);
                try {
                    fn.setName(name, SourceType.USER_DEFINED);
                    renamed++;
                }
                catch (Exception e) {
                    errors.add(formatBulkError(p.name, p.address, e.getMessage()));
                }
            }
        }
        finally {
            program.endTransaction(tx, true);
        }

        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"parsed\":").append(pairs.size()).append(',');
        sb.append("\"renamed\":").append(renamed).append(',');
        sb.append("\"missing\":[");
        boolean first = true;
        for (String m : missing) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(jsonEscape(m)).append('"');
        }
        sb.append("],\"errors\":[");
        first = true;
        for (String err : errors) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(jsonEscape(err)).append('"');
        }
        sb.append("]}");
        return sb.toString();
    }

    private String setFunctionSignatureBulk(String text) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\":\"No program loaded\"}";
        return setFunctionSignatureBulk(program, text);
    }

    /**
     * Apply prototypes from a {@code &lt;address&gt;\t&lt;prototype&gt;} per
     * line input. Each prototype is processed by the same logic as
     * {@code /set_function_prototype}. Lines that don't contain a tab are
     * skipped.
     *
     * Wrapped in a single transaction.
     */
    private String setFunctionSignatureBulk(Program program, String text) {
        if (program == null) return "{\"error\":\"No program loaded\"}";
        if (text == null || text.isEmpty()) {
            return "{\"error\":\"text required\"}";
        }

        int applied = 0;
        int parsed = 0;
        List<String> errors = new ArrayList<>();

        int tx = program.startTransaction("MCP set_function_signature_bulk");
        try {
            for (String line : text.split("\\r?\\n")) {
                if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) continue;
                int tab = line.indexOf('\t');
                if (tab < 0) continue;
                String addrStr = line.substring(0, tab).trim();
                String prototype = line.substring(tab + 1).trim();
                if (addrStr.isEmpty() || prototype.isEmpty()) continue;
                parsed++;
                PrototypeResult r = setFunctionPrototype(program, addrStr, prototype);
                if (r != null && r.isSuccess()) {
                    applied++;
                }
                else {
                    errors.add(addrStr + ": "
                        + (r != null ? r.getErrorMessage() : "unknown"));
                }
            }
        }
        finally {
            program.endTransaction(tx, true);
        }

        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"parsed\":").append(parsed).append(',');
        sb.append("\"applied\":").append(applied).append(',');
        sb.append("\"errors\":[");
        boolean first = true;
        for (String e : errors) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(jsonEscape(e)).append('"');
        }
        sb.append("]}");
        return sb.toString();
    }

    // ----------------------------------------------------------------------------------
    // Bookmarks + comment readback + callgraph (Tier 1 PR 5 + 6)
    // ----------------------------------------------------------------------------------

    private String listBookmarks(int offset, int limit, String category, String type) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return listBookmarks(program, offset, limit, category, type);
    }

    /**
     * Enumerate bookmarks. Format per line: {@code <addr> <type> <category> <comment>}.
     * Filters are case-insensitive substring matches on type and category.
     */
    private String listBookmarks(Program program, int offset, int limit,
                                 String categoryFilter, String typeFilter) {
        if (program == null) return "No program loaded";
        ghidra.program.model.listing.BookmarkManager bm = program.getBookmarkManager();
        if (bm == null) return "no bookmark manager";

        String catWant  = (categoryFilter != null && !categoryFilter.isEmpty())
            ? categoryFilter.toLowerCase() : null;
        String typeWant = (typeFilter != null && !typeFilter.isEmpty()
            && !typeFilter.equalsIgnoreCase("all"))
            ? typeFilter.toLowerCase() : null;

        List<String> lines = new ArrayList<>();
        java.util.Iterator<ghidra.program.model.listing.Bookmark> it = bm.getBookmarksIterator();
        while (it.hasNext()) {
            ghidra.program.model.listing.Bookmark bk = it.next();
            if (bk == null) continue;
            String btype = bk.getTypeString();
            String cat   = bk.getCategory();
            if (typeWant != null && !btype.toLowerCase().contains(typeWant)) continue;
            if (catWant  != null && (cat == null || !cat.toLowerCase().contains(catWant))) continue;
            String cm = bk.getComment();
            lines.add(bk.getAddress() + " " + btype + " "
                + (cat != null ? cat : "-") + " "
                + (cm != null ? cm : ""));
        }
        Collections.sort(lines);
        return paginateList(lines, offset, limit);
    }

    private String addBookmark(String addressStr, String type, String category, String note) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return addBookmark(program, addressStr, type, category, note);
    }

    /**
     * Add or update a bookmark at {@code addressStr}. {@code type} is one of
     * Ghidra's bookmark types (Note, Analysis, Error, Warning, Info); custom
     * types are auto-created. {@code category} is a free-form subdivision the
     * agent can use to group related bookmarks (e.g. "verified", "deferred",
     * "needs_review").
     */
    private String addBookmark(Program program, String addressStr, String type,
                               String category, String note) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "address required";
        if (type == null || type.isEmpty()) type = "Note";
        if (category == null) category = "";
        if (note == null) note = "";
        Address addr;
        try { addr = program.getAddressFactory().getAddress(addressStr); }
        catch (Exception e) { return "invalid address: " + addressStr; }
        if (addr == null) return "invalid address: " + addressStr;

        ghidra.program.model.listing.BookmarkManager bm = program.getBookmarkManager();
        int tx = program.startTransaction("MCP add_bookmark");
        boolean ok = false;
        String error = null;
        try {
            // setBookmark auto-defines the type if it doesn't exist.
            bm.setBookmark(addr, type, category, note);
            ok = true;
        }
        catch (Exception e) { error = e.getMessage(); }
        finally { program.endTransaction(tx, ok); }
        return ok ? "added " + type + ":" + category + " bookmark at " + addr
                  : "add failed: " + (error != null ? error : "unknown");
    }

    private String deleteBookmark(String addressStr, String type, String category) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return deleteBookmark(program, addressStr, type, category);
    }

    /**
     * Delete the bookmark at {@code addressStr} matching {@code type} and
     * {@code category}. {@code category} may be empty/null to match any
     * category. {@code type} is required.
     */
    private String deleteBookmark(Program program, String addressStr,
                                  String type, String category) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "address required";
        if (type == null || type.isEmpty()) return "type required";
        Address addr;
        try { addr = program.getAddressFactory().getAddress(addressStr); }
        catch (Exception e) { return "invalid address: " + addressStr; }
        if (addr == null) return "invalid address: " + addressStr;

        ghidra.program.model.listing.BookmarkManager bm = program.getBookmarkManager();
        ghidra.program.model.listing.Bookmark[] candidates = bm.getBookmarks(addr, type);
        int removed = 0;
        int tx = program.startTransaction("MCP delete_bookmark");
        try {
            for (ghidra.program.model.listing.Bookmark bk : candidates) {
                if (bk == null) continue;
                if (category != null && !category.isEmpty()
                    && !category.equals(bk.getCategory())) continue;
                bm.removeBookmark(bk);
                removed++;
            }
        }
        finally { program.endTransaction(tx, true); }
        return "removed " + removed + " bookmark(s) at " + addr;
    }

    private String listCommentsForFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return listCommentsForFunction(program, addressStr);
    }

    /**
     * Return all comments inside the function containing {@code addressStr},
     * one line per comment as {@code <addr> <kind> <text>}. {@code kind} is
     * one of PLATE/PRE/EOL/POST/REPEATABLE. The {@code text} is single-quoted
     * with embedded newlines escaped as {@code \\n}.
     */
    private String listCommentsForFunction(Program program, String addressStr) {
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "address required";
        Address addr;
        try { addr = program.getAddressFactory().getAddress(addressStr); }
        catch (Exception e) { return "invalid address: " + addressStr; }
        if (addr == null) return "invalid address: " + addressStr;

        Function fn = program.getFunctionManager().getFunctionContaining(addr);
        if (fn == null) return "no function at " + addr;

        Listing listing = program.getListing();
        ghidra.program.model.address.AddressSetView body = fn.getBody();
        int[] kinds = new int[] {
            ghidra.program.model.listing.CodeUnit.PLATE_COMMENT,
            ghidra.program.model.listing.CodeUnit.PRE_COMMENT,
            ghidra.program.model.listing.CodeUnit.EOL_COMMENT,
            ghidra.program.model.listing.CodeUnit.POST_COMMENT,
            ghidra.program.model.listing.CodeUnit.REPEATABLE_COMMENT,
        };
        String[] kindNames = new String[] { "PLATE", "PRE", "EOL", "POST", "REPEATABLE" };

        List<String> lines = new ArrayList<>();
        ghidra.program.model.address.AddressIterator it = body.getAddresses(true);
        while (it.hasNext()) {
            Address a = it.next();
            for (int i = 0; i < kinds.length; i++) {
                String c = listing.getComment(kinds[i], a);
                if (c != null && !c.isEmpty()) {
                    lines.add(a + " " + kindNames[i] + " '"
                        + c.replace("\\", "\\\\").replace("\n", "\\n") + "'");
                }
            }
        }
        if (lines.isEmpty()) return "no comments in function " + fn.getName();
        return String.join("\n", lines);
    }

    private String getCallgraph(String addressStr, int depth, String direction) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\":\"No program loaded\"}";
        return getCallgraph(program, addressStr, depth, direction);
    }

    /**
     * Walk the callgraph from the function at {@code addressStr} up to
     * {@code depth} levels deep. {@code direction} is "callees" (functions
     * this calls), "callers" (functions that call this), or "both".
     *
     * Returns a JSON envelope: {@code {root, direction, depth, nodes: [...]}}.
     * Each node is {@code {address, name, depth, parents: [addresses]}}; the
     * parents list is the call edges that brought you to this node.
     */
    private String getCallgraph(Program program, String addressStr, int depth, String direction) {
        if (program == null) return "{\"error\":\"No program loaded\"}";
        if (addressStr == null || addressStr.isEmpty()) {
            return "{\"error\":\"address required\"}";
        }
        if (depth <= 0) depth = 1;
        if (depth > 6) depth = 6;
        String dir = (direction == null || direction.isEmpty())
            ? "callees" : direction.toLowerCase();

        Address addr;
        try { addr = program.getAddressFactory().getAddress(addressStr); }
        catch (Exception e) { return "{\"error\":\"invalid address\"}"; }
        if (addr == null) return "{\"error\":\"invalid address\"}";

        Function root = program.getFunctionManager().getFunctionAt(addr);
        if (root == null) return "{\"error\":\"no function at " + addr + "\"}";

        // BFS up to depth. Each node records its depth + the set of parents
        // by which we discovered it (so the agent can see multiple call
        // paths converging).
        Map<Address, Integer> depthOf = new LinkedHashMap<>();
        Map<Address, List<Address>> parentsOf = new HashMap<>();
        Map<Address, Function> fnOf = new HashMap<>();
        depthOf.put(root.getEntryPoint(), 0);
        fnOf.put(root.getEntryPoint(), root);

        List<Function> frontier = new ArrayList<>();
        frontier.add(root);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        for (int d = 1; d <= depth; d++) {
            List<Function> next = new ArrayList<>();
            for (Function f : frontier) {
                java.util.Set<Function> neighbours = new java.util.HashSet<>();
                try {
                    if (dir.equals("callees") || dir.equals("both")) {
                        neighbours.addAll(f.getCalledFunctions(monitor));
                    }
                    if (dir.equals("callers") || dir.equals("both")) {
                        neighbours.addAll(f.getCallingFunctions(monitor));
                    }
                }
                catch (Exception e) { /* skip on monitor errors */ }
                for (Function n : neighbours) {
                    if (n == null) continue;
                    Address na = n.getEntryPoint();
                    parentsOf.computeIfAbsent(na, k -> new ArrayList<>())
                        .add(f.getEntryPoint());
                    if (!depthOf.containsKey(na)) {
                        depthOf.put(na, d);
                        fnOf.put(na, n);
                        next.add(n);
                    }
                }
            }
            frontier = next;
            if (frontier.isEmpty()) break;
        }

        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"root\":\"").append(root.getEntryPoint()).append("\",");
        sb.append("\"root_name\":\"").append(jsonEscape(root.getName())).append("\",");
        sb.append("\"direction\":\"").append(dir).append("\",");
        sb.append("\"depth\":").append(depth).append(',');
        sb.append("\"nodes\":[");
        boolean first = true;
        for (Map.Entry<Address, Integer> e : depthOf.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            Address a = e.getKey();
            Function f = fnOf.get(a);
            sb.append('{');
            sb.append("\"address\":\"").append(a).append("\",");
            sb.append("\"name\":\"").append(jsonEscape(f != null ? f.getName() : "?"))
              .append("\",");
            sb.append("\"depth\":").append(e.getValue()).append(',');
            sb.append("\"parents\":[");
            List<Address> ps = parentsOf.get(a);
            if (ps != null) {
                boolean firstP = true;
                for (Address pa : ps) {
                    if (!firstP) sb.append(',');
                    firstP = false;
                    sb.append('"').append(pa).append('"');
                }
            }
            sb.append(']');
            sb.append('}');
        }
        sb.append("]}");
        return sb.toString();
    }

    // ----------------------------------------------------------------------------------
    // Script execution endpoints (PR_SCOPE_RUN_SCRIPT.md)
    //
    // /list_scripts:  walk Ghidra's known script source directories, return
    //                 every script with metadata (name, path, language, category,
    //                 description). Filterable by category/pattern/language.
    // /run_script:    execute a script by name OR a posted-inline Python body.
    //                 Captures stdout/stderr/exit_code/runtime. Inherits the
    //                 Tier 0 to_file=true contract so giant stdout doesn't
    //                 jam the bridge.
    // ----------------------------------------------------------------------------------

    /** Dir name under the project for staging inline script bodies. */
    private static final String INLINE_SCRIPTS_DIRNAME = ".mcp_inline_scripts";

    /** Path-safety regex — inline filenames are only ever {@code inline-mcp-XXXXXXXX.py}. */
    private static final java.util.regex.Pattern INLINE_SCRIPT_NAME =
        java.util.regex.Pattern.compile("^inline-mcp-[0-9a-f]{8}\\.py$");

    /** Hard cap on captured stdout before forcing to_file. Protects MCP transport. */
    private static final int INLINE_STDOUT_MAX = 50 * 1024 * 1024;  // 50 MB

    private String listScripts(int offset, int limit, String categoryFilter,
                               String patternFilter, String languageFilter) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\":\"No program loaded\"}";
        return listScripts(program, offset, limit, categoryFilter, patternFilter, languageFilter);
    }

    /**
     * Walk every known Ghidra script directory and return one JSON object per
     * script. Filters are substring matches; null/empty means no filter.
     */
    private String listScripts(Program program, int offset, int limit,
                               String categoryFilter, String patternFilter,
                               String languageFilter) {
        if (program == null) return "{\"error\":\"No program loaded\"}";

        String catWant  = (categoryFilter != null && !categoryFilter.isEmpty())
            ? categoryFilter.toLowerCase() : null;
        String patWant  = (patternFilter != null && !patternFilter.isEmpty())
            ? patternFilter.toLowerCase() : null;
        String langWant = (languageFilter != null && !languageFilter.isEmpty()
            && !languageFilter.equalsIgnoreCase("all"))
            ? languageFilter.toLowerCase() : null;

        List<String> entries = new ArrayList<>();
        for (ResourceFile dir : GhidraScriptUtil.getScriptSourceDirectories()) {
            if (dir == null || !dir.isDirectory()) continue;
            ResourceFile[] kids = dir.listFiles();
            if (kids == null) continue;
            for (ResourceFile rf : kids) {
                if (rf == null || rf.isDirectory()) continue;
                String name = rf.getName();
                if (name == null) continue;
                // Only files Ghidra can run.
                if (GhidraScriptUtil.getProvider(rf) == null) continue;
                ScriptInfo info;
                try { info = GhidraScriptUtil.newScriptInfo(rf); }
                catch (Exception e) { continue; }
                String[] cats = info.getCategory();
                String catStr = (cats != null && cats.length > 0)
                    ? String.join("/", cats) : "";
                String lang = info.getRuntimeEnvironmentName();
                String desc = info.getDescription();
                String path = rf.getAbsolutePath();

                if (catWant != null && !catStr.toLowerCase().contains(catWant)) continue;
                if (patWant != null && !name.toLowerCase().contains(patWant)
                    && !path.toLowerCase().contains(patWant)) continue;
                if (langWant != null
                    && (lang == null || !lang.toLowerCase().contains(langWant))) continue;

                StringBuilder sb = new StringBuilder();
                sb.append('{');
                sb.append("\"name\":\"").append(jsonEscape(name)).append("\",");
                sb.append("\"path\":\"").append(jsonEscape(path)).append("\",");
                sb.append("\"language\":\"").append(jsonEscape(lang != null ? lang : "")).append("\",");
                sb.append("\"category\":\"").append(jsonEscape(catStr)).append("\",");
                sb.append("\"description\":\"").append(jsonEscape(desc != null ? desc : "")).append('"');
                sb.append('}');
                entries.add(sb.toString());
            }
        }
        Collections.sort(entries);

        // Pagination over the JSON-object array.
        int total = entries.size();
        int from = Math.max(0, offset);
        int to = (limit > 0) ? Math.min(total, from + limit) : total;
        StringBuilder out = new StringBuilder();
        out.append("{\"total\":").append(total).append(',');
        out.append("\"offset\":").append(from).append(',');
        out.append("\"limit\":").append(to - from).append(',');
        out.append("\"scripts\":[");
        for (int i = from; i < to; i++) {
            if (i > from) out.append(',');
            out.append(entries.get(i));
        }
        out.append("]}");
        return out.toString();
    }

    /**
     * Stage an inline Python body as a temp file under
     * {@code <projectDir>/.mcp_inline_scripts/}. Filename is
     * {@code inline-mcp-<8hex>.py} for path-safety. Caller is responsible for
     * deleting in a finally block.
     */
    private File stageInlineScript(Program program, String body) throws IOException {
        File projectDir = program.getDomainFile().getProjectLocator().getProjectDir();
        File stagingDir = new File(projectDir, INLINE_SCRIPTS_DIRNAME);
        if (!stagingDir.exists() && !stagingDir.mkdirs()) {
            throw new IOException("could not create staging dir: " + stagingDir);
        }
        // Opportunistic sweep of stale orphans (> 1h).
        long now = System.currentTimeMillis();
        File[] kids = stagingDir.listFiles();
        if (kids != null) {
            for (File k : kids) {
                if (INLINE_SCRIPT_NAME.matcher(k.getName()).matches()
                    && now - k.lastModified() > 3600_000L) {
                    k.delete();
                }
            }
        }
        String uuid = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        File staged = new File(stagingDir, "inline-mcp-" + uuid + ".py");
        try (BufferedWriter w = new BufferedWriter(new FileWriter(staged))) {
            w.write(body);
        }
        // Make sure GhidraScriptUtil can find it: it relies on the dir being
        // in the script-source path. We add it on first use; idempotent.
        boolean known = false;
        for (ResourceFile d : GhidraScriptUtil.getScriptSourceDirectories()) {
            if (d != null && d.equals(new ResourceFile(stagingDir))) {
                known = true; break;
            }
        }
        if (!known) {
            try {
                GhidraScriptUtil.getBundleHost().add(new ResourceFile(stagingDir), true, false);
            }
            catch (Exception e) {
                Msg.warn(this, "could not register staging dir: " + e.getMessage());
            }
        }
        return staged;
    }

    private String runScript(HttpExchange exchange, String scriptName, String scriptBody,
                             String[] args, boolean toFile, String txName) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\":\"No program loaded\"}";
        return runScript(exchange, program, scriptName, scriptBody, args, toFile, txName);
    }

    /**
     * Run a Ghidra script — by name (installed under any script source dir)
     * or by raw {@code scriptBody} (staged as inline Python under
     * {@code <projectDir>/.mcp_inline_scripts/}, deleted in finally). Captures
     * stdout + stderr; reports exit_code (0 on success, non-zero on script
     * exception) and runtime_ms.
     *
     * Transaction-wrapped: script mutations are undoable from the Ghidra GUI.
     */
    private String runScript(HttpExchange exchange, Program program, String scriptName,
                             String scriptBody, String[] args, boolean toFile, String txName) {
        if (program == null) return "{\"error\":\"No program loaded\"}";
        boolean haveName = (scriptName != null && !scriptName.isEmpty());
        boolean haveBody = (scriptBody != null && !scriptBody.isEmpty());
        if (haveName == haveBody) {
            return "{\"error\":\"supply exactly one of script_name or script_body\"}";
        }

        File stagedFile = null;
        boolean cleanupStaged = false;
        ResourceFile srcFile;
        try {
            if (haveBody) {
                try { stagedFile = stageInlineScript(program, scriptBody); }
                catch (IOException e) {
                    return "{\"error\":\"inline staging failed: "
                        + jsonEscape(e.getMessage()) + "\"}";
                }
                cleanupStaged = true;
                srcFile = new ResourceFile(stagedFile);
                scriptName = stagedFile.getName();
            }
            else {
                srcFile = GhidraScriptUtil.findScriptByName(scriptName);
                if (srcFile == null) {
                    return "{\"error\":\"script not found: "
                        + jsonEscape(scriptName) + "\"}";
                }
            }
        }
        catch (Exception e) {
            if (cleanupStaged && stagedFile != null) stagedFile.delete();
            return "{\"error\":\"resolution failed: "
                + jsonEscape(e.getMessage()) + "\"}";
        }

        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(srcFile);
        if (provider == null) {
            if (cleanupStaged && stagedFile != null) stagedFile.delete();
            return "{\"error\":\"no script provider for: "
                + jsonEscape(scriptName) + "\"}";
        }

        StringWriter stdoutBuf = new StringWriter();
        StringWriter stderrBuf = new StringWriter();
        PrintWriter outPw = new PrintWriter(stdoutBuf);
        PrintWriter errPw = new PrintWriter(stderrBuf);
        int exitCode = 0;
        long t0 = System.currentTimeMillis();
        String exceptionTrace = null;

        try {
            GhidraScript script;
            try {
                script = provider.getScriptInstance(srcFile, errPw);
            }
            catch (Exception e) {
                errPw.println("LOAD_EXCEPTION: " + e);
                e.printStackTrace(errPw);
                outPw.flush(); errPw.flush();
                if (cleanupStaged && stagedFile != null) stagedFile.delete();
                return scriptResponseEnvelope(exchange, scriptName, 2,
                    System.currentTimeMillis() - t0,
                    stdoutBuf.toString(), stderrBuf.toString(), toFile);
            }
            if (script == null) {
                errPw.println("LOAD: provider returned null script instance");
                outPw.flush(); errPw.flush();
                if (cleanupStaged && stagedFile != null) stagedFile.delete();
                return scriptResponseEnvelope(exchange, scriptName, 2,
                    System.currentTimeMillis() - t0,
                    stdoutBuf.toString(), stderrBuf.toString(), toFile);
            }
            if (args != null) script.setScriptArgs(args);

            GhidraState state = new GhidraState(tool, tool.getProject(),
                program, null, null, null);
            String txLabel = (txName != null && !txName.isEmpty())
                ? txName : "MCP run_script " + scriptName;
            int tx = program.startTransaction(txLabel);
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
            if (cleanupStaged && stagedFile != null) {
                stagedFile.delete();
            }
        }

        long runtimeMs = System.currentTimeMillis() - t0;
        String stdoutStr = stdoutBuf.toString();
        String stderrStr = stderrBuf.toString();

        // PyGhidra script provider catches Python exceptions internally and
        // prints the traceback to the stdout PrintWriter. That defeats the
        // exit_code semantics ("did the script work?"). Reclassify after the
        // fact: if a Python traceback marker appears in stdout, treat as
        // failure, move the traceback to stderr.
        if (exitCode == 0 && stdoutStr.contains("Traceback (most recent call last)")) {
            int tbIdx = stdoutStr.indexOf("Traceback (most recent call last)");
            String trace = stdoutStr.substring(tbIdx);
            stdoutStr = stdoutStr.substring(0, tbIdx);
            stderrStr = (stderrStr.isEmpty() ? "" : stderrStr + "\n") + trace;
            exitCode = 1;
        }

        return scriptResponseEnvelope(exchange, scriptName, exitCode, runtimeMs,
            stdoutStr, stderrStr, toFile);
    }

    /**
     * Build the JSON envelope for a script response. If {@code toFile} is true
     * (or stdout exceeds {@link #INLINE_STDOUT_MAX} regardless of request),
     * stdout spools to disk via the existing Tier 0 DumpManager and the
     * response contains the fetch URL instead of the body.
     */
    private String scriptResponseEnvelope(HttpExchange exchange, String scriptName,
                                          int exitCode, long runtimeMs,
                                          String stdout, String stderr, boolean toFile) {
        boolean forceSpool = stdout.length() > INLINE_STDOUT_MAX;
        if (toFile || forceSpool) {
            DumpManager dm = getOrCreateDumpManager();
            if (dm == null) {
                // No program -> no dump manager. Fall back to inline; honesty over politeness.
                return scriptResponseInline(scriptName, exitCode, runtimeMs, stdout, stderr,
                    forceSpool ? "stdout was force-spooled but DumpManager unavailable" : null);
            }
            try {
                String uuid = dm.spool("script", stdout);
                long bytes = stdout.getBytes(StandardCharsets.UTF_8).length;
                long lines = DumpManager.countLines(stdout);
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                sb.append("\"script\":\"").append(jsonEscape(scriptName)).append("\",");
                sb.append("\"exit_code\":").append(exitCode).append(',');
                sb.append("\"runtime_ms\":").append(runtimeMs).append(',');
                String host = (exchange != null)
                    ? exchange.getRequestHeaders().getFirst("Host") : null;
                if (host == null || host.isEmpty()) host = "localhost:" + boundPort;
                sb.append("\"stdout_url\":\"http://").append(host)
                  .append("/dump/").append(uuid).append("\",");
                sb.append("\"stdout_uuid\":\"").append(uuid).append("\",");
                sb.append("\"stdout_bytes\":").append(bytes).append(',');
                sb.append("\"stdout_lines\":").append(lines).append(',');
                sb.append("\"stderr\":\"").append(jsonEscape(stderr)).append('"');
                if (forceSpool && !toFile) {
                    sb.append(",\"note\":\"stdout exceeded ")
                      .append(INLINE_STDOUT_MAX)
                      .append(" bytes; force-spooled\"");
                }
                sb.append('}');
                return sb.toString();
            }
            catch (Exception e) {
                Msg.error(this, "script stdout spool failed: " + e.getMessage());
                return scriptResponseInline(scriptName, exitCode, runtimeMs, stdout, stderr,
                    "spool failed: " + e.getMessage());
            }
        }
        return scriptResponseInline(scriptName, exitCode, runtimeMs, stdout, stderr, null);
    }

    private String scriptResponseInline(String scriptName, int exitCode,
                                        long runtimeMs, String stdout,
                                        String stderr, String note) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"script\":\"").append(jsonEscape(scriptName)).append("\",");
        sb.append("\"exit_code\":").append(exitCode).append(',');
        sb.append("\"runtime_ms\":").append(runtimeMs).append(',');
        sb.append("\"stdout\":\"").append(jsonEscape(stdout)).append("\",");
        sb.append("\"stderr\":\"").append(jsonEscape(stderr)).append('"');
        if (note != null) sb.append(",\"note\":\"").append(jsonEscape(note)).append('"');
        sb.append('}');
        return sb.toString();
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;

        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }

    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive)
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    // ----------------------------------------------------------------------------------
    // Spool-to-disk plumbing (Tier 0)
    // See PR_SCOPE_TIER0.md for the design.
    // ----------------------------------------------------------------------------------

    private void sendJson(HttpExchange exchange, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendStatus(HttpExchange exchange, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /**
     * Lazy DumpManager — built against the program currently bound to this
     * tool. Returns null if no program is loaded (caller should surface a
     * JSON error to the agent).
     */
    private synchronized DumpManager getOrCreateDumpManager() {
        Program p = getCurrentProgram();
        if (p == null) return null;
        if (dumpManager == null || dumpManagerProgram != p) {
            try {
                dumpManager = new DumpManager(p);
                dumpManagerProgram = p;
            }
            catch (IOException e) {
                Msg.error(this, "Failed to initialise DumpManager for "
                    + p.getName() + ": " + e.getMessage());
                dumpManager = null;
                dumpManagerProgram = null;
            }
        }
        return dumpManager;
    }

    /**
     * Spool {@code body} and respond with a small JSON envelope containing the
     * fetch URL the agent should curl. If {@code toFile} is false, behave as
     * the legacy text response.
     */
    private void respondMaybeSpool(HttpExchange exchange, boolean toFile,
                                   String endpointTag, String body) throws IOException {
        if (!toFile) {
            sendResponse(exchange, body);
            return;
        }
        DumpManager dm = getOrCreateDumpManager();
        if (dm == null) {
            sendJson(exchange,
                "{\"error\":\"no program loaded; cannot spool\"}");
            return;
        }
        try {
            String uuid = dm.spool(endpointTag, body);
            long lines = DumpManager.countLines(body);
            long bytes = body.getBytes(StandardCharsets.UTF_8).length;
            sendJson(exchange, buildSpoolEnvelope(exchange, uuid, endpointTag, bytes, lines));
        }
        catch (IOException e) {
            Msg.error(this, "Spool write failed: " + e.getMessage());
            sendJson(exchange, "{\"error\":\"spool write failed: "
                + jsonEscape(e.getMessage()) + "\"}");
        }
    }

    /**
     * Build the JSON envelope the agent receives after a successful spool.
     * URL host comes from the request's {@code Host:} header so the agent
     * gets a URL it can actually reach, whatever interface the plugin bound on.
     */
    private String buildSpoolEnvelope(HttpExchange exchange, String uuid, String endpointTag,
                                      long bytes, long lines) {
        String host = exchange.getRequestHeaders().getFirst("Host");
        if (host == null || host.isEmpty()) {
            host = "localhost:" + boundPort;
        }
        return "{"
            + "\"url\":\"http://" + host + "/dump/" + uuid + "\","
            + "\"uuid\":\"" + uuid + "\","
            + "\"endpoint\":\"" + endpointTag + "\","
            + "\"bytes\":" + bytes + ","
            + "\"lines\":" + lines + ","
            + "\"ttl_seconds\":" + (DumpManager.TTL_MS / 1000L)
            + "}";
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else          sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Handle {@code GET /dump/{uuid}} (stream) or {@code DELETE /dump/{uuid}} (nuke). */
    private void handleDumpById(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String uuid = path.substring("/dump/".length());
        // Strip any trailing slash or query that snuck past the context match.
        int slash = uuid.indexOf('/');
        if (slash >= 0) uuid = uuid.substring(0, slash);

        DumpManager dm = getOrCreateDumpManager();
        if (dm == null) {
            sendStatus(exchange, 404, "no program loaded");
            return;
        }

        if ("DELETE".equals(exchange.getRequestMethod())) {
            boolean ok = dm.delete(uuid);
            sendStatus(exchange, ok ? 200 : 404, ok ? "deleted" : "not found");
            return;
        }

        File spool = dm.resolve(uuid);
        if (spool == null) {
            sendStatus(exchange, 404, "not found");
            return;
        }

        Map<String, String> qparams = parseQueryParams(exchange);
        boolean deleteAfter = "true".equals(qparams.get("delete_after"));

        String rangeHeader = exchange.getRequestHeaders().getFirst("Range");
        if (rangeHeader != null && rangeHeader.startsWith("bytes=")) {
            long[] bounds = parseRange(rangeHeader, spool.length());
            if (bounds == null) {
                sendStatus(exchange, 416, "range not satisfiable");
                return;
            }
            long len = bounds[1] - bounds[0] + 1;
            exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
            exchange.getResponseHeaders().set("Content-Range",
                "bytes " + bounds[0] + "-" + bounds[1] + "/" + spool.length());
            exchange.sendResponseHeaders(206, len);
            try (OutputStream os = exchange.getResponseBody()) {
                DumpManager.streamRange(spool, bounds[0], bounds[1], os);
            }
        }
        else {
            exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
            exchange.sendResponseHeaders(200, spool.length());
            try (OutputStream os = exchange.getResponseBody()) {
                DumpManager.streamTo(spool, os);
            }
        }

        if (deleteAfter) {
            dm.delete(uuid);
        }
    }

    /** Parse a single-range {@code Range: bytes=N-M} header. Returns null if unparseable. */
    private static long[] parseRange(String header, long fileLength) {
        try {
            String spec = header.substring("bytes=".length()).trim();
            // Reject multi-range (commas) — overkill for our use case.
            if (spec.indexOf(',') >= 0) return null;
            int dash = spec.indexOf('-');
            if (dash < 0) return null;
            String fromStr = spec.substring(0, dash).trim();
            String toStr = spec.substring(dash + 1).trim();
            long from, to;
            if (fromStr.isEmpty()) {
                // Suffix range: bytes=-N (last N bytes)
                long n = Long.parseLong(toStr);
                if (n <= 0) return null;
                from = Math.max(0, fileLength - n);
                to = fileLength - 1;
            }
            else {
                from = Long.parseLong(fromStr);
                to = toStr.isEmpty() ? fileLength - 1 : Long.parseLong(toStr);
            }
            if (from < 0 || to >= fileLength || from > to) return null;
            return new long[] { from, to };
        }
        catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Handle {@code GET /dump} (no uuid) — list active spools as a JSON array.
     */
    private void handleDumpList(HttpExchange exchange) throws IOException {
        DumpManager dm = getOrCreateDumpManager();
        if (dm == null) {
            sendJson(exchange, "[]");
            return;
        }
        try {
            List<Map<String, Object>> entries = dm.list();
            StringBuilder sb = new StringBuilder();
            sb.append('[');
            boolean first = true;
            for (Map<String, Object> e : entries) {
                if (!first) sb.append(',');
                first = false;
                sb.append('{');
                sb.append("\"uuid\":\"").append(e.get("uuid")).append("\",");
                sb.append("\"endpoint\":\"").append(e.get("endpoint")).append("\",");
                sb.append("\"bytes\":").append(e.get("bytes")).append(',');
                sb.append("\"lines\":").append(e.get("lines")).append(',');
                sb.append("\"age_seconds\":").append(e.get("age_seconds"));
                sb.append('}');
            }
            sb.append(']');
            sendJson(exchange, sb.toString());
        }
        catch (IOException e) {
            sendJson(exchange, "{\"error\":\"list failed: "
                + jsonEscape(e.getMessage()) + "\"}");
        }
    }

    // ---- Program open --------------------------------------------------------

    private String openProgramFromProject(String projectPath) {
        if (projectPath == null || projectPath.isBlank())
            return "{\"error\":\"path is required\"}";

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) return "{\"error\":\"No project open\"}";

        String fullPath = projectPath.startsWith("/") ? projectPath : "/" + projectPath;
        DomainFile file = project.getProjectData().getFile(fullPath);
        if (file == null)
            return "{\"error\":\"File not found: " + jsonEscape(fullPath) + "\"}";

        AtomicBoolean success = new AtomicBoolean(false);
        String[] errorHolder = {null};
        try {
            SwingUtilities.invokeAndWait(() -> {
                ProgramManager pm = tool.getService(ProgramManager.class);
                if (pm == null) { errorHolder[0] = "ProgramManager not available"; return; }
                Program p = pm.openProgram(file);
                success.set(p != null);
                if (p == null) errorHolder[0] = "openProgram returned null";
            });
        }
        catch (InvocationTargetException | InterruptedException e) {
            return "{\"error\":" + jsonString(e.getMessage()) + "}";
        }
        if (!success.get())
            return "{\"error\":" + jsonString(errorHolder[0] != null ? errorHolder[0] : "open failed") + "}";
        return "{\"opened\":" + jsonString(fullPath) + "}";
    }

    // ---- Version Tracking endpoints ------------------------------------------

    private VTSession vtOpenSession(String sessionPath) throws Exception {
        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) throw new IllegalStateException("No project open");
        ghidra.framework.model.ProjectData pd = project.getProjectData();
        String fullPath = sessionPath.startsWith("/") ? sessionPath : "/" + sessionPath;
        DomainFile file = pd.getFile(fullPath);
        if (file == null)
            throw new IllegalArgumentException("Session not found: " + fullPath);
        if (!VTSessionContentHandler.CONTENT_TYPE.equals(file.getContentType()))
            throw new IllegalArgumentException("Not a VT session: " + fullPath);
        return (VTSession) file.getDomainObject(this, false, false, new ConsoleTaskMonitor());
    }

    private String vtListSessions() {
        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) return "{\"error\":\"No project open\"}";
        try {
            List<String> paths = new ArrayList<>();
            collectVtSessionPaths(project.getProjectData().getRootFolder(), paths);
            StringBuilder sb = new StringBuilder("{\"sessions\":[");
            for (int i = 0; i < paths.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(jsonString(paths.get(i)));
            }
            return sb.append("]}").toString();
        }
        catch (Exception e) {
            return "{\"error\":" + jsonString(e.getMessage()) + "}";
        }
    }

    private void collectVtSessionPaths(DomainFolder folder, List<String> out) {
        for (DomainFile f : folder.getFiles()) {
            if (VTSessionContentHandler.CONTENT_TYPE.equals(f.getContentType()))
                out.add(f.getPathname());
        }
        for (DomainFolder sub : folder.getFolders())
            collectVtSessionPaths(sub, out);
    }

    private String vtCreateSession(String sessionName, String sourcePath, String destPath) {
        if (sessionName == null || sessionName.isBlank())
            return "{\"error\":\"name is required\"}";
        if (sourcePath == null || sourcePath.isBlank())
            return "{\"error\":\"source_program is required\"}";
        if (destPath == null || destPath.isBlank())
            return "{\"error\":\"dest_program is required\"}";

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) return "{\"error\":\"No project open\"}";

        String srcFull  = sourcePath.startsWith("/") ? sourcePath : "/" + sourcePath;
        String destFull = destPath.startsWith("/")   ? destPath   : "/" + destPath;

        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        ghidra.framework.model.ProjectData pd = project.getProjectData();
        DomainFile sourceFile = pd.getFile(srcFull);
        DomainFile destFile   = pd.getFile(destFull);
        if (sourceFile == null)
            return "{\"error\":\"source not found: " + jsonEscape(srcFull) + "\"}";
        if (destFile == null)
            return "{\"error\":\"dest not found: " + jsonEscape(destFull) + "\"}";

        Program sourceProgram = null;
        Program destProgram   = null;
        VTSession session     = null;
        try {
            sourceProgram = (Program) sourceFile.getDomainObject(this, false, false, monitor);
            destProgram   = (Program) destFile.getDomainObject(this, false, false, monitor);
            if (!destProgram.canSave())
                return "{\"error\":\"dest program is read-only\"}";

            DomainFolder root = pd.getRootFolder();
            if (root.getFile(sessionName) != null)
                return "{\"error\":\"session already exists: " + jsonEscape(sessionName) + "\"}";

            session = new VTSessionDB(sessionName, sourceProgram, destProgram, this);
            root.createFile(sessionName, session, monitor);
            session.save();
            return "{\"created\":" + jsonString(sessionName)
                + ",\"source\":" + jsonString(srcFull)
                + ",\"dest\":" + jsonString(destFull) + "}";
        }
        catch (Exception e) {
            return "{\"error\":" + jsonString(e.getMessage()) + "}";
        }
        finally {
            if (session != null)      session.release(this);
            if (sourceProgram != null) sourceProgram.release(this);
            if (destProgram != null)   destProgram.release(this);
        }
    }

    private VTProgramCorrelatorFactory vtCorrelatorForName(String name) {
        switch (name.toLowerCase().trim()) {
            case "exact_bytes":        return new ExactMatchBytesProgramCorrelatorFactory();
            case "exact_instructions": return new ExactMatchInstructionsProgramCorrelatorFactory();
            case "exact_data":         return new ExactDataMatchProgramCorrelatorFactory();
            case "duplicate":          return new DuplicateFunctionMatchProgramCorrelatorFactory();
            case "reference":          return new CombinedFunctionAndDataReferenceProgramCorrelatorFactory();
            case "similar_symbol":     return new SimilarSymbolNameProgramCorrelatorFactory();
            default:                   return null;
        }
    }

    private String vtRunCorrelators(String sessionPath, String algorithms) {
        if (sessionPath == null || sessionPath.isBlank())
            return "{\"error\":\"session is required\"}";

        List<String> algoList = new ArrayList<>();
        if (algorithms == null || algorithms.isBlank()) {
            algoList.add("exact_bytes");
            algoList.add("exact_instructions");
            algoList.add("exact_data");
            algoList.add("duplicate");
        }
        else {
            for (String a : algorithms.split(",")) {
                String t = a.trim();
                if (!t.isEmpty()) algoList.add(t);
            }
        }

        VTSession session = null;
        try {
            session = vtOpenSession(sessionPath);
            Program srcProg  = session.getSourceProgram();
            Program destProg = session.getDestinationProgram();
            AddressSetView srcAddrs  = srcProg.getMemory().getLoadedAndInitializedAddressSet();
            AddressSetView destAddrs = destProg.getMemory().getLoadedAndInitializedAddressSet();
            ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

            StringBuilder results = new StringBuilder("[");
            boolean first = true;
            int tx = session.startTransaction("Run correlators via MCP");
            try {
                for (String algo : algoList) {
                    VTProgramCorrelatorFactory factory = vtCorrelatorForName(algo);
                    if (factory == null) {
                        if (!first) results.append(",");
                        first = false;
                        results.append("{\"algorithm\":").append(jsonString(algo))
                               .append(",\"error\":\"unknown algorithm\"}");
                        continue;
                    }
                    VTOptions options = factory.createDefaultOptions();
                    VTProgramCorrelator correlator = factory.createCorrelator(
                        srcProg, srcAddrs, destProg, destAddrs, options);
                    VTMatchSet matchSet = correlator.correlate(session, monitor);
                    int count = (matchSet != null) ? matchSet.getMatchCount() : 0;
                    if (!first) results.append(",");
                    first = false;
                    results.append("{\"algorithm\":").append(jsonString(algo))
                           .append(",\"matches\":").append(count).append("}");
                }
            }
            finally {
                session.endTransaction(tx, true);
                session.save();
            }
            results.append("]");
            return "{\"correlators\":" + results + "}";
        }
        catch (Exception e) {
            return "{\"error\":" + jsonString(e.getMessage()) + "}";
        }
        finally {
            if (session != null) session.release(this);
        }
    }

    private String vtListMatches(String sessionPath, String minScoreStr,
                                  String statusFilter, int offset, int limit) {
        if (sessionPath == null || sessionPath.isBlank())
            return "{\"error\":\"session is required\"}";

        VTSession session = null;
        try {
            session = vtOpenSession(sessionPath);
            double minScore = 0.0;
            if (minScoreStr != null && !minScoreStr.isBlank())
                minScore = Double.parseDouble(minScoreStr);

            List<String> entries = new ArrayList<>();
            for (VTMatchSet ms : session.getMatchSets()) {
                for (VTMatch match : ms.getMatches()) {
                    VTAssociation assoc = match.getAssociation();
                    VTAssociationStatus s = assoc.getStatus();
                    if (statusFilter != null && !statusFilter.equalsIgnoreCase("all")) {
                        if (!s.name().equalsIgnoreCase(statusFilter)) continue;
                    }
                    double score = match.getSimilarityScore().getScore();
                    if (score < minScore) continue;
                    entries.add("{\"src\":" + jsonString(match.getSourceAddress().toString())
                        + ",\"dst\":" + jsonString(match.getDestinationAddress().toString())
                        + ",\"score\":" + score
                        + ",\"confidence\":" + match.getConfidenceScore().getScore()
                        + ",\"status\":" + jsonString(s.name())
                        + ",\"type\":" + jsonString(assoc.getType().name())
                        + "}");
                }
            }

            int total = entries.size();
            List<String> page = entries.subList(
                Math.min(offset, total), Math.min(offset + limit, total));
            StringBuilder sb = new StringBuilder("{\"total\":").append(total)
                .append(",\"offset\":").append(offset)
                .append(",\"matches\":[");
            for (int i = 0; i < page.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(page.get(i));
            }
            return sb.append("]}").toString();
        }
        catch (Exception e) {
            return "{\"error\":" + jsonString(e.getMessage()) + "}";
        }
        finally {
            if (session != null) session.release(this);
        }
    }

    private String vtAcceptMatches(String sessionPath, String minScoreStr) {
        if (sessionPath == null || sessionPath.isBlank())
            return "{\"error\":\"session is required\"}";

        VTSession session = null;
        try {
            session = vtOpenSession(sessionPath);
            double minScore = 0.0;
            if (minScoreStr != null && !minScoreStr.isBlank())
                minScore = Double.parseDouble(minScoreStr);

            int accepted = 0, skipped = 0;
            int tx = session.startTransaction("Accept matches via MCP");
            try {
                for (VTMatchSet ms : session.getMatchSets()) {
                    for (VTMatch match : ms.getMatches()) {
                        VTAssociation assoc = match.getAssociation();
                        if (assoc.getStatus() != VTAssociationStatus.AVAILABLE) {
                            skipped++;
                            continue;
                        }
                        if (match.getSimilarityScore().getScore() < minScore) {
                            skipped++;
                            continue;
                        }
                        assoc.setAccepted();
                        accepted++;
                    }
                }
            }
            finally {
                session.endTransaction(tx, true);
                session.save();
            }
            return "{\"accepted\":" + accepted + ",\"skipped\":" + skipped + "}";
        }
        catch (Exception e) {
            return "{\"error\":" + jsonString(e.getMessage()) + "}";
        }
        finally {
            if (session != null) session.release(this);
        }
    }

    private boolean vtMarkupTypeWanted(VTMarkupType markupType, Set<String> wanted) {
        if (wanted.contains("function_name") && markupType == FunctionNameMarkupType.INSTANCE) return true;
        if (wanted.contains("label") && markupType == LabelMarkupType.INSTANCE) return true;
        if (wanted.contains("function_signature") && markupType == FunctionSignatureMarkupType.INSTANCE) return true;
        if (wanted.contains("data_type") && markupType == DataTypeMarkupType.INSTANCE) return true;
        if (wanted.contains("eol_comment") && markupType == EolCommentMarkupType.INSTANCE) return true;
        if (wanted.contains("plate_comment") && markupType == PlateCommentMarkupType.INSTANCE) return true;
        return false;
    }

    private String vtApplyMarkups(String sessionPath, String typesStr) {
        if (sessionPath == null || sessionPath.isBlank())
            return "{\"error\":\"session is required\"}";

        Set<String> wantedTypes = new HashSet<>();
        if (typesStr == null || typesStr.isBlank()) {
            wantedTypes.add("function_name");
            wantedTypes.add("label");
        }
        else {
            for (String t : typesStr.split(","))
                wantedTypes.add(t.trim().toLowerCase());
        }

        VTSession session = null;
        try {
            session = vtOpenSession(sessionPath);
            ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
            int applied = 0, failed = 0, skipped = 0;
            int tx = session.startTransaction("Apply markups via MCP");
            try {
                for (VTMatchSet ms : session.getMatchSets()) {
                    for (VTMatch match : ms.getMatches()) {
                        VTAssociation assoc = match.getAssociation();
                        if (assoc.getStatus() != VTAssociationStatus.ACCEPTED) continue;
                        for (VTMarkupItem item : assoc.getMarkupItems(monitor)) {
                            if (!vtMarkupTypeWanted(item.getMarkupType(), wantedTypes)) {
                                skipped++;
                                continue;
                            }
                            if (!item.canApply()) {
                                skipped++;
                                continue;
                            }
                            try {
                                item.apply(VTMarkupItemApplyActionType.REPLACE, null);
                                applied++;
                            }
                            catch (VersionTrackingApplyException e) {
                                failed++;
                            }
                        }
                    }
                }
            }
            finally {
                session.endTransaction(tx, true);
                try { session.getDestinationProgram().save("VT markups via MCP", monitor); }
                catch (Exception ignore) {}
                session.save();
            }
            return "{\"applied\":" + applied + ",\"failed\":" + failed + ",\"skipped\":" + skipped + "}";
        }
        catch (Exception e) {
            return "{\"error\":" + jsonString(e.getMessage()) + "}";
        }
        finally {
            if (session != null) session.release(this);
        }
    }

    @Override
    public void dispose() {
        // Tear down this tool's HTTP server.
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server on port " + boundPort + "...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null;
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }

        super.dispose();
    }
}
