package card42.host.emv.kernel.data;

/**
 * Terminal Verification Results (tag '95') bit masks and helpers
 * (EMV v4.4 Book 3 Annex C5, Table 46).
 *
 * <p>The TVR is a five-byte bitmap built up by the terminal during offline data
 * authentication, processing restrictions, cardholder verification and terminal
 * risk management.  It is the input of Terminal Action Analysis (see
 * {@link TerminalActionAnalysis}) and it is carried to the card in the CDOL1
 * data of the first GENERATE AC.
 *
 * <p>The constants below are the bit masks within a single TVR byte; pass the
 * zero-based byte index to {@link #set} / {@link #isSet}.
 */
public final class Tvr {

    // --- Byte 1: offline data authentication (EMV v4.4 Book 3 Table 46). ----
    public static final int ODA_NOT_PERFORMED = 0x80;
    public static final int SDA_FAILED = 0x40;
    public static final int ICC_DATA_MISSING = 0x20;
    public static final int CARD_ON_EXCEPTION_FILE = 0x10;
    public static final int DDA_FAILED = 0x08;
    public static final int CDA_FAILED = 0x04;
    public static final int SDA_SELECTED = 0x02;
    public static final int XDA_SELECTED = 0x01;

    // --- Byte 2: processing restrictions. -----------------------------------
    public static final int APPLICATION_VERSION_MISMATCH = 0x80;
    public static final int EXPIRED_APPLICATION = 0x40;
    public static final int APPLICATION_NOT_YET_EFFECTIVE = 0x20;
    public static final int SERVICE_NOT_ALLOWED = 0x10;
    public static final int NEW_CARD = 0x08;

    // --- Byte 3: cardholder verification. -----------------------------------
    public static final int CVM_NOT_SUCCESSFUL = 0x80;
    public static final int UNRECOGNISED_CVM = 0x40;
    public static final int PIN_TRY_LIMIT_EXCEEDED = 0x20;
    public static final int PIN_PAD_NOT_PRESENT = 0x10;
    public static final int PIN_NOT_ENTERED = 0x08;
    public static final int ONLINE_PIN_ENTERED = 0x04;

    // --- Byte 4: terminal risk management. ----------------------------------
    public static final int FLOOR_LIMIT_EXCEEDED = 0x80;
    public static final int LOWER_OFFLINE_LIMIT_EXCEEDED = 0x40;
    public static final int UPPER_OFFLINE_LIMIT_EXCEEDED = 0x20;
    public static final int RANDOM_SELECTION = 0x10;
    public static final int MERCHANT_FORCED_ONLINE = 0x08;
    /** b2: a selected biometric type is not supported (EMV v4.4 Book 3 §10.5). */
    public static final int BIOMETRIC_TYPE_NOT_SUPPORTED = 0x02;

    // --- Byte 5: issuer / script processing. --------------------------------
    public static final int DEFAULT_TDOL_USED = 0x80;
    public static final int ISSUER_AUTH_FAILED = 0x40;
    public static final int SCRIPT_FAILED_BEFORE_FINAL_AC = 0x20;
    public static final int SCRIPT_FAILED_AFTER_FINAL_AC = 0x10;

    /** Length of the TVR (five bytes, EMV v4.4 Book 3 §10.7). */
    public static final int LENGTH = 5;

    private Tvr() {
    }

    /** Sets the given mask in byte {@code index} of the TVR. */
    public static void set(byte[] tvr, int index, int mask) {
        if (index >= 0 && index < tvr.length) {
            tvr[index] |= (byte) mask;
        }
    }

    /** True when the given mask is set in byte {@code index} of the TVR. */
    public static boolean isSet(byte[] tvr, int index, int mask) {
        return index >= 0 && index < tvr.length && (tvr[index] & mask) != 0;
    }

    /**
     * True when at least one bit is shared between the TVR and the action code
     * {@code code} (the terminal action analysis intersection, EMV v4.4 Book 3
     * §10.7).  An action code shorter than the TVR only matches its leading
     * bytes, a longer one has no effect on the trailing bits.
     */
    public static boolean intersects(byte[] tvr, byte[] code) {
        int n = Math.min(tvr.length, code.length);
        for (int i = 0; i < n; i++) {
            if ((tvr[i] & code[i]) != 0) {
                return true;
            }
        }
        return false;
    }

    /** A new all-zero TVR. */
    public static byte[] blank() {
        return new byte[LENGTH];
    }
}
