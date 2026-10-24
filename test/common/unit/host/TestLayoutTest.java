package card42.test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Source-layout guard for the test tree: EMV suites must not reference eMRTD
 * classes and vice versa; the shared runner/support must live under
 * {@code test/common}.
 *
 * <p>All suites share package {@code card42.test}, so the compiler cannot
 * enforce this ownership; the directory is the marker and this guard keeps it
 * honest.  Run from the repository root (as {@code make test-unit} does); the
 * check is skipped when {@code test} is not found.
 *
 * <p>Project-layout coverage, not an EMV/ICAO/BSI/CPS clause.
 */
final class TestLayoutTest {

    private TestLayoutTest() {
    }

    static void run() throws Exception {
        System.out.println("TestLayout");

        Path test = Path.of("test");
        Asserts.check(Files.isDirectory(test),
                "TestLayoutTest must run from the repository root (test/ not found)");
        if (!Files.isDirectory(test)) {
            return;
        }

        List<String> violations = new ArrayList<String>();
        scan(test.resolve("emv"), "card42.emrtd", violations);
        scan(test.resolve("emrtd"), "card42.emv", violations);
        Asserts.check(violations.isEmpty(), "test module ownership: " + violations);

        Asserts.check(!Files.exists(test.resolve("emv/unit/UnitTests.java")),
                "the shared unit runner lives in test/common/unit");
        Asserts.check(Files.exists(test.resolve("common/unit/UnitTests.java")),
                "test/common/unit/UnitTests.java exists");
        Asserts.check(!Files.exists(test.resolve("emv/unit/support")),
                "shared unit support lives in test/common/unit/support");
        Asserts.check(Files.exists(test.resolve("common/unit/support/Asserts.java")),
                "test/common/unit/support/Asserts.java exists");
        Asserts.check(!Files.exists(test.resolve("emv/integration/support")),
                "shared integration support lives in test/common/integration/support");
        Asserts.check(Files.exists(test.resolve("common/integration/support/Checks.java")),
                "test/common/integration/support/Checks.java exists");
    }

    private static void scan(Path root, String forbidden, List<String> violations) throws Exception {
        if (!Files.isDirectory(root)) {
            return;
        }
        try (Stream<Path> files = Files.walk(root)) {
            files.filter(p -> p.toString().endsWith(".java")).forEach(p -> {
                try {
                    String code = stripComments(Files.readString(p));
                    if (code.contains(forbidden)) {
                        violations.add(p + " -> " + forbidden);
                    }
                } catch (Exception e) {
                    violations.add(p + " (unreadable)");
                }
            });
        }
    }

    /** Removes block and line comments so docs/strings cannot hide a reference. */
    private static String stripComments(String source) {
        String noBlocks = source.replaceAll("(?s)/\\*.*?\\*/", " ");
        return noBlocks.replaceAll("//[^\\n]*", " ");
    }
}
