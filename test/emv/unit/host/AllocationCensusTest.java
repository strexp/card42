package card42.test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Card-side allocation census (docs/specs/common/architecture.md §2, risks.md §2):
 * a source-layout guard that the number of card-side allocations never grows.
 *
 * <p>Java Card heap is scarce, so the project's rule is that a responsibility
 * split must be heap-neutral: a class may be split into {@code static} helpers
 * or its methods moved into an already-allocated collaborator, but no new
 * object/array allocation (transient or persistent) may appear on the card side
 * (docs/specs/common/risks.md).  This test counts, over {@code card/}:
 *
 * <ul>
 *   <li>every {@code new} (object construction and array allocation);</li>
 *   <li>every transient-buffer allocation ({@code makeByteArray} /
 *       {@code makeTransient});</li>
 * </ul>
 *
 * and fails when either count exceeds the ceiling below.  The ceilings are a
 * snapshot ceiling, not an exact value: a change that <em>removes</em> an
 * allocation passes, and a change that <em>adds</em> one must be justified and
 * the ceiling raised deliberately (with a matching NVM-baseline note).  The
 * runtime counterpart is {@code NvmBaselineTest}'s transient-footprint check.
 *
 * <p>Run from the repository root (as {@code make test-unit} does); the check is
 * skipped when {@code card} is not found.
 *
 * <p>Project-layout coverage, not an EMV/ICAO/BSI/CPS clause.
 */
final class AllocationCensusTest {

    /**
     * Ceiling of card-side {@code new} expressions (objects + arrays).  The
     * 2026-10-22 LDS2 extended-Le READ RECORD support adds the two persistent
     * 1 KB record/envelope buffers in {@code EmrtdScratch} (only allocated for
     * an LDS2 role); see docs/specs/common/risks.md §2 and docs/specs/emrtd/
     * emrtd.md §11.
     */
    private static final int NEW_CEILING = 253;
    /** Ceiling of card-side transient-buffer allocations. */
    private static final int TRANSIENT_CEILING = 47;
    /**
     * Ceiling of platform allocations that are not spelled {@code new} in the
     * source ({@code KeyBuilder.buildKey}, {@code Cipher.getInstance}, ...).
     * They still consume persistent or transient heap, so they are tracked
     * separately; this is a snapshot, not a full heap model.
     */
    private static final int PLATFORM_CEILING = 60;

    private static final Pattern NEW = Pattern.compile("\\bnew\\b");
    private static final Pattern TRANSIENT =
            Pattern.compile("makeByteArray|makeTransient");
    private static final Pattern PLATFORM =
            Pattern.compile("KeyBuilder\\.buildKey|Cipher\\.getInstance"
                    + "|Signature\\.getInstance|RandomData\\.getInstance"
                    + "|MessageDigest\\.getInstance|KeyPair\\(");

    private AllocationCensusTest() {
    }

    static void run() throws Exception {
        System.out.println("AllocationCensus");

        Path card = Path.of("card");
        if (!Files.isDirectory(card)) {
            System.out.println("  skip (card not found; run from the repo root)");
            return;
        }
        int news = 0;
        int transients = 0;
        int platforms = 0;
        List<Path> files = new ArrayList<Path>();
        try (Stream<Path> paths = Files.walk(card)) {
            paths.filter(p -> p.toString().endsWith(".java")).forEach(files::add);
        }
        for (Path p : files) {
            String source = stripComments(Files.readString(p));
            news += count(NEW, source);
            transients += count(TRANSIENT, source);
            platforms += count(PLATFORM, source);
        }

        Asserts.check(news <= NEW_CEILING,
                "card-side allocations " + news + " within the ceiling " + NEW_CEILING
                + " (a responsibility split must be heap-neutral; raise the ceiling"
                + " only with a matching risks.md note)");
        Asserts.check(transients <= TRANSIENT_CEILING,
                "card-side transient allocations " + transients + " within the ceiling "
                + TRANSIENT_CEILING + " (add no transient buffer)");
        Asserts.check(platforms <= PLATFORM_CEILING,
                "card-side platform allocations " + platforms + " within the ceiling "
                + PLATFORM_CEILING + " (KeyBuilder/getInstance allocations still use heap)");
        if (news <= NEW_CEILING && transients <= TRANSIENT_CEILING
                && platforms <= PLATFORM_CEILING) {
            System.out.println("  ok   " + files.size() + " card files: " + news
                    + " allocations, " + transients + " transient, " + platforms
                    + " platform (ceiling " + NEW_CEILING + " / " + TRANSIENT_CEILING
                    + " / " + PLATFORM_CEILING + ")");
        }
    }

    private static int count(Pattern p, String source) {
        Matcher m = p.matcher(source);
        int n = 0;
        while (m.find()) {
            n++;
        }
        return n;
    }

    /** Removes block and line comments so they do not count as allocations. */
    private static String stripComments(String source) {
        String s = source.replaceAll("(?s)/\\*.*?\\*/", "");
        return s.replaceAll("//[^\\n]*", "");
    }
}
