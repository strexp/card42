package card42.test;

/**
 * eMRTD-only pure-JVM suites.  Shared helpers live in {@code test/common/unit};
 * EMV suites live in {@link EmvSuites}.
 */
final class EmrtdSuites {

    private EmrtdSuites() {
    }

    static void run() throws Exception {
        System.out.println();
        System.out.println("== emrtd: card ==");
        EmrtdCryptoTest.run();
        EmrtdLds2Test.run();
        EmrtdCommandTest.run();
        EmrtdPersoStreamTest.run();
        EmrtdTaCardTest.run();

        System.out.println();
        System.out.println("== emrtd: host ==");
        EmrtdHostTest.run();
        EmrtdHostNegativeTest.run();
        LdsCommonTest.run();
        MrzTest.run();
        DgBiometricTest.run();
        DgTextTest.run();
        MrvTest.run();
        EmrtdCliTest.run();
        PassportReportTest.run();
        Lds2SampleTest.run();
        Lds2VerifierTest.run();
        EmrtdCardAccessTest.run();
        EmrtdTaTest.run();
    }
}
