package com.krakty.ghidramcp;

import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Assigns HTTP server slots to currently-loaded Ghidra programs based on:
 *   1. Filename pattern (eqgame.exe / eqmain.dll / eqgraphics.dll)
 *   2. Leading MM-DD-YYYY date prefix in the program name
 *
 * Per pattern family there are exactly two slots: a "primary" and an "old".
 * The newest-dated program in a family takes the primary slot; the second-
 * newest takes the -old slot. Anything beyond two, or any program lacking a
 * parseable date prefix, gets no port (caller is expected to log a warning).
 */
public final class SlotAssigner {

    /** Date prefix at the very start of a program name, e.g. "04-15-2026-..." */
    private static final Pattern DATE_PREFIX = Pattern.compile("^(\\d{2})-(\\d{2})-(\\d{4})-.*");

    /** A single slot definition: a name pattern plus its primary / old port pair. */
    public static final class SlotFamily {
        public final String slotName;          // e.g. "eqgame"
        public final Pattern namePattern;      // applied to Program.getName()
        public final int primaryPort;
        public final int oldPort;

        public SlotFamily(String slotName, Pattern namePattern, int primaryPort, int oldPort) {
            this.slotName = slotName;
            this.namePattern = namePattern;
            this.primaryPort = primaryPort;
            this.oldPort = oldPort;
        }
    }

    /** Result of assigning a single program to a slot. */
    public static final class Assignment {
        public final Program program;
        public final String slotName;     // "eqgame", "eqgame-old", etc.
        public final int port;
        public final String datePrefix;   // "MM-DD-YYYY", or "" if none

        public Assignment(Program program, String slotName, int port, String datePrefix) {
            this.program = program;
            this.slotName = slotName;
            this.port = port;
            this.datePrefix = datePrefix;
        }
    }

    /** A program that matched a family but did not get a slot (3rd or later, or unparseable date). */
    public static final class Unassigned {
        public final Program program;
        public final String reason;

        public Unassigned(Program program, String reason) {
            this.program = program;
            this.reason = reason;
        }
    }

    public static final class AssignmentResult {
        public final List<Assignment> assignments = new ArrayList<>();
        public final List<Unassigned> unassigned = new ArrayList<>();
    }

    /** The default slot pool: eqgame 8090/8093, eqmain 8091/8094, eqgraphics 8092/8095. */
    public static List<SlotFamily> defaultFamilies() {
        List<SlotFamily> families = new ArrayList<>();
        families.add(new SlotFamily(
            "eqgame",
            Pattern.compile("(?i).*eqgame.*\\.exe"),
            8090, 8093));
        families.add(new SlotFamily(
            "eqmain",
            Pattern.compile("(?i).*eqmain.*\\.dll"),
            8091, 8094));
        families.add(new SlotFamily(
            "eqgraphics",
            Pattern.compile("(?i).*eqgraphics.*\\.dll"),
            8092, 8095));
        return families;
    }

    /**
     * Compute slot assignments from scratch given the currently-loaded programs.
     */
    public static AssignmentResult assign(List<Program> openPrograms, List<SlotFamily> families) {
        AssignmentResult result = new AssignmentResult();

        // Group programs by family. A program is bucketed into the FIRST family whose
        // name pattern it matches, so a program that somehow matches two patterns
        // (shouldn't happen with the defaults) is not double-assigned.
        Map<SlotFamily, List<Program>> matchedByFamily = new LinkedHashMap<>();
        for (SlotFamily fam : families) {
            matchedByFamily.put(fam, new ArrayList<>());
        }

        for (Program p : openPrograms) {
            String name = effectiveName(p);
            for (SlotFamily fam : families) {
                if (fam.namePattern.matcher(name).matches()) {
                    matchedByFamily.get(fam).add(p);
                    break;
                }
            }
        }

        // Within each family, sort newest-first by date prefix. Programs whose name
        // does not begin with a parseable MM-DD-YYYY get the "no slot" treatment
        // regardless of how many other programs are in the family.
        for (Map.Entry<SlotFamily, List<Program>> e : matchedByFamily.entrySet()) {
            SlotFamily fam = e.getKey();
            List<Program> matched = e.getValue();

            // Sort matched programs: dated ones first (newest-first by date prefix),
            // then undated ones by name. This way dated programs always win the
            // primary slot when present, but undated programs still get slots when
            // they're the only ones (or fill remaining capacity).
            Collections.sort(matched, new Comparator<Program>() {
                @Override
                public int compare(Program a, Program b) {
                    String da = comparableDate(effectiveName(a)); // "0000-00-00" if no prefix
                    String db = comparableDate(effectiveName(b));
                    int dateCmp = db.compareTo(da); // descending; sentinel sorts last
                    if (dateCmp != 0) return dateCmp;
                    return effectiveName(a).compareTo(effectiveName(b)); // stable tiebreak
                }
            });

            for (int i = 0; i < matched.size(); i++) {
                Program p = matched.get(i);
                String prefix = extractDatePrefix(effectiveName(p));
                if (prefix == null) prefix = "";
                if (i == 0) {
                    result.assignments.add(new Assignment(
                        p, fam.slotName, fam.primaryPort, prefix));
                } else if (i == 1) {
                    result.assignments.add(new Assignment(
                        p, fam.slotName + "-old", fam.oldPort, prefix));
                } else {
                    result.unassigned.add(new Unassigned(
                        p,
                        "no slot available in family '" + fam.slotName +
                        "' (primary + old already filled by newer-dated programs)"));
                }
            }
        }

        return result;
    }

    /**
     * Returns the program's effective display name for slot matching.
     * Prefers the DomainFile name (the project-tree name, which the user may have
     * renamed for visual distinctness, e.g. "04-15-2026-LIVE-eqgame.exe") and
     * falls back to Program.getName() if no DomainFile is available.
     */
    public static String effectiveName(Program p) {
        try {
            ghidra.framework.model.DomainFile df = p.getDomainFile();
            if (df != null) {
                String n = df.getName();
                if (n != null && !n.isEmpty()) return n;
            }
        } catch (Exception ignored) { /* fall through to Program.getName() */ }
        return p.getName();
    }

    /** Returns "MM-DD-YYYY" if the program name starts with one, else null. */
    public static String extractDatePrefix(String programName) {
        if (programName == null) return null;
        Matcher m = DATE_PREFIX.matcher(programName);
        if (!m.matches()) return null;
        return m.group(1) + "-" + m.group(2) + "-" + m.group(3);
    }

    /**
     * Returns "YYYY-MM-DD" for direct lexicographic comparison, or "0000-00-00"
     * if the prefix is absent (caller normally filters those out before sorting).
     */
    private static String comparableDate(String programName) {
        Matcher m = DATE_PREFIX.matcher(programName);
        if (!m.matches()) return "0000-00-00";
        return m.group(3) + "-" + m.group(1) + "-" + m.group(2);
    }

    private SlotAssigner() { /* static utility */ }
}
