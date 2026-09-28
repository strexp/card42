package card42.test;

/**
 * Runner for the pure-JVM unit tests (docs/specs/common/toolchain.md §6).  It does not need
 * the Java Card simulator: the card-side classes are linked against the small
 * {@code javacard.framework.Util}/{@code ISOException} stubs in test/common/stubs
 * and the host-side classes run directly.  Exits non-zero on the first failing
 * suite so {@code make test-unit} can gate on it.
 *
 * <p>The suites live in functional subdirectories but share package
 * {@code card42.test} (see README.md): card-side suites under
 * {@code test/emv/unit/card/} ({@code tlv/}, {@code data/}, {@code state/},
 * {@code risk/}, {@code perso/}, {@code crypto/}) and host-only suites under
 * {@code test/emv/unit/host/} ({@code codec/}, {@code crypto/}, {@code perso/},
 * {@code clearing/}, {@code kernel/}).
 * All assertions are reported through {@link Asserts} (in {@code test/emv/unit/support/}).
 */
public final class UnitTests {

    private UnitTests() {
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== tlv ==");
        TlvTest.run();
        DgiTest.run();
        DolReaderTest.run();

        System.out.println();
        System.out.println("== card (data / state / risk / perso) ==");
        RecordStoreTest.run();
        RecordBuilderTest.run();
        InstallParametersTest.run();
        ProtocolStateTest.run();
        StaticDataTest.run();
        DirectoryBuilderTest.run();
        DirectoryRecordsTest.run();
        CardRiskManagementTest.run();
        IadCvrTest.run();
        TransactionLogTest.run();
        OfflineRiskTest.run();
        PersoErrorsTest.run();
        PersoRulesTest.run();
        EmrtdCryptoTest.run();
        EmrtdLds2Test.run();
        EmrtdCommandTest.run();
        EmrtdPersoStreamTest.run();
        EmrtdHostTest.run();
        EmrtdHostNegativeTest.run();
        EmrtdCliTest.run();
        PassportReportTest.run();
        EmrtdCardAccessTest.run();

        System.out.println();
        System.out.println("== host ==");
        LayeringTest.run();
        TagsTest.run();
        TagPolicyTest.run();
        ResponsesTest.run();
        HexTest.run();
        TerminalT0Test.run();
        ClearingHostTest.run();
        ReceiptTest.run();
        PersoScriptTest.run();
        SdaTest.run();
        OdaVerifierTest.run();
        TerminalConfigTest.run();
        TerminalDolTest.run();
        BcdTest.run();
        TerminalActionAnalysisTest.run();
        ApplicationSelectionTest.run();
        PseSelectionTest.run();
        PpseSelectionTest.run();
        EntryPointTest.run();
        EntryPointConfigTest.run();
        OutcomeTest.run();
        CvmListTest.run();
        CvmListPerformerTest.run();
        OfflinePinCvmTest.run();
        OnlinePinSignatureCvmTest.run();
        ProcessingRestrictionsTest.run();
        TerminalRiskManagementTest.run();
        IssuerScriptProcessorTest.run();
        CliTest.run();

        System.out.println();
        System.out.println("== crypto ==");
        EmvKeysTest.run();
        AcCryptoTest.run();
        AcVectorTest.run();
        AesVectorTest.run();
        SmCryptoTest.run();
        CardCryptoVectorTest.run();
        ArpcVectorTest.run();
        SecureMessagingTest.run();
        ConstantTimeTest.run();

        System.out.println();
        System.out.println("== nvm ==");
        NvmBaselineTest.run();

        System.out.println();
        System.out.println(Asserts.checks() + " checks, " + Asserts.failures() + " failure(s)");
        if (Asserts.failures() > 0) {
            System.out.println("UNIT TESTS FAILED");
            System.exit(1);
        }
        System.out.println("ALL UNIT TESTS PASSED");
    }
}
