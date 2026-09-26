package card42.emv;

import card42.common.*;

import javacard.framework.Util;

/* The CCD Issuer Application Data (IAD) of EMV v4.4 Book 3 Annex C §C9, Format
 * Code 'A'.
 *
 * A CCD-compliant application returns a fixed 32-byte IAD:
 *
 *   byte  1      Length Indicator ('0F')
 *   byte  2      Common Core Identifier (CCI): Format Code 'A', CV '5' -> 'A5'
 *   byte  3      Derivation Key Index (DKI)
 *   bytes 4-8    Card Verification Results (CVR)
 *   bytes 9-16   Counters (issuer / payment-system discretionary)
 *   byte  17     Length Indicator ('0F')
 *   bytes 18-32  Issuer Discretionary Data (15 bytes)
 *
 * The CVR is transaction-dependent (it records the cryptograms returned and
 * the risk-management results), so the card rewrites bytes 4-8 before every
 * GENERATE AC.  This class owns the layout constants and the small CVR
 * assembly; the individual bits are aggregated from EMVProtocolState,
 * OfflineRisk, OwnerPIN and SecureMessaging by the applet (EMV v4.4 Book 3 Annex C §C9).
 *
 * @author card42
 */

public final class Iad {

    private Iad() {
    }

    /** Fixed length of a Format Code 'A' IAD. */
    public static final short LENGTH = (short) 32;

    /** Byte 1: length of the EMVCo-defined part of the IAD. */
    public static final byte LENGTH_INDICATOR = (byte) 0x0F;

    /** Common Core Identifier: Format Code 'A' (b8-b5) and CV '5' (b4-b1). */
    public static final byte CCI_FC_A_CV_5 = (byte) 0xA5;

    public static final short OFF_CVR = (short) 3;
    public static final short CVR_LENGTH = (short) 5;
    public static final short OFF_DISCRETIONARY_LENGTH = (short) 16;

    /** CVR byte 1: cryptogram type returned in the second GENERATE AC. */
    public static final byte CVR1_AC2_TC = (byte) 0x40;
    public static final byte CVR1_AC2_NOT_REQUESTED = (byte) 0x80;
    /** CVR byte 1: cryptogram type returned in the first GENERATE AC. */
    public static final byte CVR1_AC1_TC = (byte) 0x10;
    public static final byte CVR1_AC1_ARQC = (byte) 0x20;
    /** CVR byte 1 flags. */
    public static final byte CVR1_CDA_PERFORMED = (byte) 0x08;
    public static final byte CVR1_DDA_PERFORMED = (byte) 0x04;
    public static final byte CVR1_ISSUER_AUTH_NOT_PERFORMED = (byte) 0x02;
    public static final byte CVR1_ISSUER_AUTH_FAILED = (byte) 0x01;

    /** CVR byte 2 flags (the PIN try counter occupies b8-b5). */
    public static final byte CVR2_PIN_PERFORMED = (byte) 0x08;
    public static final byte CVR2_PIN_FAILED = (byte) 0x04;
    public static final byte CVR2_PIN_TRY_LIMIT_EXCEEDED = (byte) 0x02;
    public static final byte CVR2_LAST_ONLINE_NOT_COMPLETED = (byte) 0x01;

    /** CVR byte 4 flags (the script command count occupies b8-b5). */
    public static final byte CVR4_SCRIPT_FAILED = (byte) 0x08;
    public static final byte CVR4_ODA_FAILED_PREVIOUS = (byte) 0x04;
    public static final byte CVR4_GO_ONLINE_NEXT = (byte) 0x02;
    public static final byte CVR4_UNABLE_TO_GO_ONLINE = (byte) 0x01;

    /**
     * Assembles CVR byte 1 (EMV v4.4 Book 3 Annex C §C9.3): the AC type codes
     * (b8-b7 = second AC, b6-b5 = first AC) and the status flags.  firstCode and
     * secondCode are the two-bit values returned by AcProcessor.acTypeCode
     * (0 = AAC, 1 = TC, 2 = ARQC); the first AC response passes 2 as secondCode
     * for "second GENERATE AC not requested".
     */
    public static byte cvrByte1(byte firstCode, byte secondCode, boolean cda,
            boolean dda, boolean issuerAuthNotPerformed, boolean issuerAuthFailed) {
        byte b1 = (byte) ((secondCode << 6) | (firstCode << 4));
        if (cda) {
            b1 |= CVR1_CDA_PERFORMED;
        }
        if (dda) {
            b1 |= CVR1_DDA_PERFORMED;
        }
        if (issuerAuthNotPerformed) {
            b1 |= CVR1_ISSUER_AUTH_NOT_PERFORMED;
        }
        if (issuerAuthFailed) {
            b1 |= CVR1_ISSUER_AUTH_FAILED;
        }
        return b1;
    }

    /** Writes the CVR (5 bytes) into the IAD at OFF_CVR. */
    public static void setCvr(byte[] iad, short off, byte[] cvr, short cvrOff) {
        Util.arrayCopyNonAtomic(cvr, cvrOff, iad, (short) (off + OFF_CVR),
                CVR_LENGTH);
    }
}
