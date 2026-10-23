package card42.test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Source-layout guard (docs/specs/common/architecture.md §2): enforces
 * the host module topology, the intra-emv layering and the library/CLI split.
 *
 * <ul>
 *   <li>{@code common} imports no other host module;</li>
 *   <li>{@code emv.lib} and {@code emv.crypto} import {@code common} only;</li>
 *   <li>{@code emv.oda} imports {@code common}/{@code emv.lib};</li>
 *   <li>{@code emv.kernel} imports {@code common}/{@code emv.lib}/{@code emv.crypto}/{@code emv.oda};</li>
 *   <li>{@code emv.report} imports {@code common}/{@code emv.lib}/{@code emv.kernel}/{@code emv.crypto}/{@code emv.oda};</li>
 *   <li>{@code emv.app} imports {@code common}/{@code emv.lib}/{@code emv.kernel}/{@code emv.report}/{@code emv.crypto}/{@code emv.oda};</li>
 *   <li>{@code emv.cli} imports any emv module plus {@code common};</li>
 *   <li>{@code emrtd.lib} imports {@code common} only;</li>
 *   <li>{@code emrtd.cli} imports {@code common}/{@code emrtd.lib}.</li>
 * </ul>
 *
 * <p>No library module may import a CLI module, so the library jars
 * ({@code card42-emv.jar} / {@code card42-emrtd.jar}) stay consumable without
 * the CLI jars (see docs/specs/common/toolchain.md §2).
 *
 * <p>Run from the repository root (as {@code make test-unit} does); the check
 * is skipped when {@code host} is not found.
 *
 * <p>Project-layout coverage, not an EMV/ICAO/BSI/CPS clause.
 */
final class LayeringTest {

    private static final Pattern IMPORT = Pattern.compile(
            "^import\\s+(?:static\\s+)?(card42\\.host[\\w.]*);", Pattern.MULTILINE);
    /** Fully-qualified references (the import scan alone misses these). */
    private static final Pattern REFERENCE = Pattern.compile("\\bcard42\\.host[\\w.]*");

    private LayeringTest() {
    }

    static void run() throws Exception {
        System.out.println("Layering");

        Path host = Path.of("host");
        Asserts.check(Files.isDirectory(host),
                "LayeringTest must run from the repository root (host/ not found)");
        List<String> violations = new ArrayList<String>();
        try (Stream<Path> files = Files.walk(host)) {
            files.filter(p -> p.toString().endsWith(".java")).forEach(p -> {
                String module = moduleOfPath(p.toString());
                if (module == null) {
                    return;
                }
                String source;
                try {
                    source = Files.readString(p);
                } catch (Exception e) {
                    violations.add(p + " (unreadable)");
                    return;
                }
                String code = stripComments(source);
                Matcher m = IMPORT.matcher(code);
                while (m.find()) {
                    checkReference(p, module, m.group(1), violations);
                }
                Matcher ref = REFERENCE.matcher(code);
                while (ref.find()) {
                    checkReference(p, module, ref.group(), violations);
                }
            });
        }
        Asserts.check(violations.isEmpty(), "module layering violations: " + violations);
    }

    private static void checkReference(Path file, String module, String reference,
                                       List<String> violations) {
        String target = moduleOfPackage(reference);
        // Intra-module references are always fine; only a dependency on another
        // module is constrained by the layering rules.
        if (target != null && !target.equals(module)
                && !allowed(module).contains(target)) {
            String violation = file + ": " + module + " -> " + reference;
            if (!violations.contains(violation)) {
                violations.add(violation);
            }
        }
    }

    /** Removes block and line comments so docs/strings cannot hide a reference. */
    private static String stripComments(String source) {
        String noBlocks = source.replaceAll("(?s)/\\*.*?\\*/", " ");
        return noBlocks.replaceAll("//[^\\n]*", " ");
    }

    /** The module of a host source path, or null for paths outside the modules. */
    private static String moduleOfPath(String path) {
        String p = path.replace('\\', '/');
        if (p.startsWith("host/common/")) {
            return "common";
        }
        if (p.startsWith("host/emv/lib/")) {
            return "emv.lib";
        }
        if (p.startsWith("host/emv/kernel/")) {
            return "emv.kernel";
        }
        if (p.startsWith("host/emv/report/")) {
            return "emv.report";
        }
        if (p.startsWith("host/emv/app/")) {
            return "emv.app";
        }
        if (p.startsWith("host/emv/cli/")) {
            return "emv.cli";
        }
        if (p.startsWith("host/emv/crypto/")) {
            return "emv.crypto";
        }
        if (p.startsWith("host/emv/oda/")) {
            return "emv.oda";
        }
        if (p.startsWith("host/emrtd/cli/") || p.startsWith("host/emrtd/tools/")) {
            return "emrtd.cli";
        }
        if (p.startsWith("host/emrtd/")) {
            return "emrtd.lib";
        }
        return null;
    }

    /** The module an imported package belongs to. */
    private static String moduleOfPackage(String pkg) {
        if (pkg.startsWith("card42.host.emv.kernel")) {
            return "emv.kernel";
        }
        if (pkg.startsWith("card42.host.emv.report")) {
            return "emv.report";
        }
        if (pkg.startsWith("card42.host.emv.app")) {
            return "emv.app";
        }
        if (pkg.startsWith("card42.host.emv.cli")) {
            return "emv.cli";
        }
        if (pkg.startsWith("card42.host.emv.lib")) {
            return "emv.lib";
        }
        if (pkg.startsWith("card42.host.emv.crypto")) {
            return "emv.crypto";
        }
        if (pkg.startsWith("card42.host.emv.oda")) {
            return "emv.oda";
        }
        if (pkg.startsWith("card42.host.emv")) {
            return "emv.lib";
        }
        if (pkg.startsWith("card42.host.emrtd.cli")
                || pkg.startsWith("card42.host.emrtd.tools")) {
            return "emrtd.cli";
        }
        if (pkg.startsWith("card42.host.emrtd")) {
            return "emrtd.lib";
        }
        if (pkg.startsWith("card42.host.common")) {
            return "common";
        }
        return null;
    }

    /** The modules a module may import. */
    private static List<String> allowed(String module) {
        switch (module) {
        case "common":
            return java.util.Collections.emptyList();
        case "emv.lib":
        case "emv.crypto":
            return java.util.Arrays.asList("common");
        case "emv.oda":
            return java.util.Arrays.asList("common", "emv.lib");
        case "emv.kernel":
            return java.util.Arrays.asList("common", "emv.lib", "emv.crypto", "emv.oda");
        case "emv.report":
            return java.util.Arrays.asList("common", "emv.lib", "emv.kernel",
                    "emv.crypto", "emv.oda");
        case "emv.app":
            return java.util.Arrays.asList("common", "emv.lib", "emv.kernel", "emv.report",
                    "emv.crypto", "emv.oda");
        case "emv.cli":
            return java.util.Arrays.asList("common", "emv.lib", "emv.kernel", "emv.report",
                    "emv.app", "emv.crypto", "emv.oda");
        case "emrtd.lib":
            return java.util.Arrays.asList("common");
        case "emrtd.cli":
            return java.util.Arrays.asList("common", "emrtd.lib");
        default:
            return java.util.Collections.emptyList();
        }
    }
}
