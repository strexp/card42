package card42.host.emv.kernel.data;

/**
 * Cardholder Verification Method codes and results (EMV v4.4 Book 3 Table 43,
 * Book 4 §6.3.4.5 Table 33).  These are EMV data values, so they live with the
 * terminal data model rather than in the CVM processing logic
 * ({@code kernel.analysis.CvmList}); the presentation layer and any other
 * module can use them without depending on the analysis package.
 */
public final class Cvm {

    private Cvm() {
    }

    // CVM codes (EMV v4.4 Book 3 Table 43).
    public static final int CVM_FAIL = 0x00;
    public static final int CVM_PLAINTEXT_PIN_ICC = 0x01;
    public static final int CVM_ONLINE_PIN = 0x02;
    public static final int CVM_PLAINTEXT_PIN_SIGNATURE = 0x03;
    public static final int CVM_ENCIPHERED_PIN_ICC = 0x04;
    public static final int CVM_ENCIPHERED_PIN_SIGNATURE = 0x05;
    public static final int CVM_SIGNATURE = 0x1E;
    public static final int CVM_NO_CVM = 0x1F;

    // CVM Results byte 3 (EMV v4.4 Book 4 §6.3.4.5, Table 33).
    public static final int RESULT_UNKNOWN = 0x00;
    public static final int RESULT_FAILED = 0x01;
    public static final int RESULT_SUCCESSFUL = 0x02;

    /** 'No CVM performed' in CVM Results byte 1 (EMV v4.4 Book 4 §6.3.4.5). */
    public static final int NO_CVM_PERFORMED = 0x3F;
}
