package card42.test;

/**
 * Runner for the pure-JVM unit tests (docs/specs/common/toolchain.md §6).  It
 * does not need the Java Card simulator: the card-side classes are linked
 * against the small {@code javacard.framework.Util}/{@code ISOException} stubs
 * in test/common/stubs and the host-side classes run directly.  Exits non-zero
 * when any suite failed so {@code make test-unit} can gate on it.
 *
 * <p>The suites are grouped by ownership:
 * {@link CommonSuites} (host/common and card/common primitives, source-layout
 * guards, the cross-module NVM baseline), {@link EmvSuites} and
 * {@link EmrtdSuites}.  All files still share package {@code card42.test}; the
 * directory is the ownership marker.
 *
 * <p>Usage: {@code UnitTests [all|common|emv|emrtd]}.  The per-module modes
 * always run the common guards; {@code all} is the default and the CI gate.
 */
public final class UnitTests {

    private UnitTests() {
    }

    public static void main(String[] args) throws Exception {
        String mode = args.length == 0 ? "all" : args[0];
        if ("all".equals(mode)) {
            CommonSuites.runAll();
            EmvSuites.run();
            EmrtdSuites.run();
        } else if ("common".equals(mode)) {
            CommonSuites.runAll();
        } else if ("emv".equals(mode)) {
            CommonSuites.runGuards();
            EmvSuites.run();
        } else if ("emrtd".equals(mode)) {
            CommonSuites.runGuards();
            EmrtdSuites.run();
        } else {
            System.out.println("usage: UnitTests [all|common|emv|emrtd]");
            System.exit(2);
        }

        System.out.println();
        System.out.println(Asserts.checks() + " checks, " + Asserts.failures() + " failure(s)");
        if (Asserts.failures() > 0) {
            System.out.println("UNIT TESTS FAILED");
            System.exit(1);
        }
        System.out.println("ALL UNIT TESTS PASSED");
    }
}
