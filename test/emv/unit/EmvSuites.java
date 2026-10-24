package card42.test;

/**
 * EMV-only pure-JVM suites.  Shared helpers live in {@code test/common/unit};
 * eMRTD suites live in {@link EmrtdSuites}.
 */
final class EmvSuites {

    private EmvSuites() {
    }

    static void run() throws Exception {
        System.out.println();
        System.out.println("== emv: tlv ==");
        DgiTest.run();
        DolReaderTest.run();
        TlvTagsTest.run();

        System.out.println();
        System.out.println("== emv: card (data / state / risk / perso) ==");
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

        System.out.println();
        System.out.println("== emv: host ==");
        TagPolicyTest.run();
        ResponsesTest.run();
        ClearingHostTest.run();
        ReceiptTest.run();
        PersoScriptTest.run();
        SdaTest.run();
        OdaVerifierTest.run();
        TerminalConfigTest.run();
        TerminalDolTest.run();
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
        System.out.println("== emv: crypto ==");
        EmvKeysTest.run();
        AcCryptoTest.run();
        AcVectorTest.run();
        AesVectorTest.run();
        ScriptSessionTest.run();
        ArpcVectorTest.run();
        SecureMessagingTest.run();
    }
}
