package card42.test;

/**
 * Shared pure-JVM suites: host/common primitives, card/common primitives, the
 * cross-cutting source-layout guards and the EMV+eMRTD NVM baseline.
 *
 * <p>They run once for the whole project, independent of the EMV/eMRTD module.
 * Module-specific suites are listed in {@link EmvSuites} and {@link EmrtdSuites}.
 */
final class CommonSuites {

    private CommonSuites() {
    }

    /** Runs every common suite (used by {@code make test-unit} and {@code common}). */
    static void runAll() throws Exception {
        System.out.println();
        System.out.println("== common: codec / util / transport ==");
        TagsTest.run();
        HexTest.run();
        BcdTest.run();
        TerminalT0Test.run();

        System.out.println();
        System.out.println("== common: card primitives ==");
        TlvTest.run();
        ConstantTimeTest.run();
        CardCryptoVectorTest.run();
        AesCmacVectorTest.run();

        runGuards();

        System.out.println();
        System.out.println("== common: nvm ==");
        NvmBaselineTest.run();
    }

    /**
     * Runs only the source-layout / allocation guards.  The per-module modes
     * ({@code emv}, {@code emrtd}) include them so a module run still checks the
     * shared invariants.
     */
    static void runGuards() throws Exception {
        System.out.println();
        System.out.println("== common: guards ==");
        LayeringTest.run();
        AllocationCensusTest.run();
        TestLayoutTest.run();
    }
}
