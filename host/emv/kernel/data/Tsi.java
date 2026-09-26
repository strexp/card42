package card42.host.emv.kernel.data;

/**
 * Transaction Status Information (tag '9B') bit masks
 * (EMV v4.4 Book 3 Annex C6, Table 47).
 *
 * <p>The TSI records which processing functions the terminal actually
 * performed; it is reported to the issuer alongside the TVR.
 */
public final class Tsi {

    public static final int ODA_PERFORMED = 0x80;
    public static final int CVM_PERFORMED = 0x40;
    public static final int CARD_RISK_MANAGEMENT_PERFORMED = 0x20;
    public static final int ISSUER_AUTH_PERFORMED = 0x10;
    public static final int TERMINAL_RISK_MANAGEMENT_PERFORMED = 0x08;
    public static final int SCRIPT_PROCESSING_PERFORMED = 0x04;

    /** Length of the TSI (two bytes, EMV v4.4 Book 3 Annex A / Annex C6 Table 47). */
    public static final int LENGTH = 2;

    private Tsi() {
    }

    /** Sets the given mask in the TSI. */
    public static void set(byte[] tsi, int mask) {
        tsi[0] |= (byte) mask;
    }

    /** True when the given mask is set in the TSI. */
    public static boolean isSet(byte[] tsi, int mask) {
        return (tsi[0] & mask) != 0;
    }

    /** A new all-zero TSI. */
    public static byte[] blank() {
        return new byte[LENGTH];
    }
}
