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
 * the three-module topology and the intra-emv layering.
 *
 * <ul>
 *   <li>{@code common} imports no other host module;</li>
 *   <li>{@code emv.lib} and {@code emv.crypto} import {@code common} only;</li>
 *   <li>{@code emv.oda} imports {@code common}/{@code emv.lib};</li>
 *   <li>{@code emv.kernel} imports {@code common}/{@code emv.lib}/{@code emv.crypto}/{@code emv.oda};</li>
 *   <li>{@code emv.report} imports {@code common}/{@code emv.lib}/{@code emv.kernel}/{@code emv.crypto}/{@code emv.oda};</li>
 *   <li>{@code emv.app} imports {@code common}/{@code emv.lib}/{@code emv.kernel}/{@code emv.report}/{@code emv.crypto}/{@code emv.oda};</li>
 *   <li>{@code emv.cli} imports any emv module plus {@code common};</li>
 *   <li>{@code emrtd} imports {@code common} only (plus its own module).</li>
 * </ul>
 *
 * <p>Run from the repository root (as {@code make test-unit} does); the check
 * is skipped when {@code host} is not found.
 *
 * <p>Project-layout coverage, not an EMV/ICAO/BSI/CPS clause.
 */
final class LayeringTest {

    private static final Pattern IMPORT = Pattern.compile("^import\\s+(card42\\.host[\\w.]*);",
            Pattern.MULTILINE);

    private LayeringTest() {
    }

    static void run() throws Exception {
        System.out.println("Layering");

        Path host = Path.of("host");
        if (!Files.isDirectory(host)) {
            System.out.println("  skip (host not found; run from the repo root)");
            return;
        }
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
                Matcher m = IMPORT.matcher(source);
                while (m.find()) {
                    String target = moduleOfPackage(m.group(1));
                    // Intra-module imports are always fine; only a dependency on
                    // another module is constrained by the layering rules.
                    if (target != null && !target.equals(module)
                            && !allowed(module).contains(target)) {
                        violations.add(p + ": " + module + " -> " + m.group(1));
                    }
                }
            });
        }
        Asserts.check(violations.isEmpty(), "module layering violations: " + violations);
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
        if (p.startsWith("host/emrtd/")) {
            return "emrtd";
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
        if (pkg.startsWith("card42.host.emrtd")) {
            return "emrtd";
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
        default: // emrtd
            return java.util.Arrays.asList("common");
        }
    }
}
