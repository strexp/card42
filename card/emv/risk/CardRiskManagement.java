package card42.emv;

import card42.common.*;

/* Card Action Analysis (EMV v4.4 Book 3 §10.8).
 *
 * EMV leaves the card's own risk management algorithm to the issuer, but the
 * Common Core Definitions describe the standard use of the Issuer Action Codes
 * (IAC) against the Terminal Verification Results (TVR): the card's IACs mirror
 * the TVR and specify, bit by bit, when a transaction must be declined or sent
 * online.  card42 follows that method (Card Action Analysis, EMV v4.4 Book 3 §10.8; the
 * bit-wise comparison itself is the Terminal Action Analysis method of §10.7)
 * so that the IACs personalised into the card actually change the returned
 * cryptogram.
 *
 * The terminal requests a cryptogram (TC / ARQC / AAC) and the card may only
 * downgrade it, never upgrade it (EMV v4.4 Book 3 section 9.3): a card decision of TC
 * against an ARQC request still returns an ARQC.
 *
 * @author card42
 */

public final class CardRiskManagement {

    private CardRiskManagement() {
    }

    /**
     * Card Action Analysis, in the EMV v4.4 Book 3 §10.8 order (the IAC/TVR comparison
     * follows the Terminal Action Analysis method of §10.7):
     *
     *   TVR & IAC-Denial  -> AAC  (decline offline)
     *   TVR & IAC-Online  -> ARQC (complete online)
     *   TVR & IAC-Default -> AAC  (reject if it cannot go online)
     *   otherwise         -> TC   (approve offline)
     *
     * An IAC shorter than the TVR only matches its leading bytes; an IAC longer
     * than the TVR has no effect on the trailing bits.
     */
    public static byte decide(byte[] tvr, short tvrOff, short tvrLen,
                              byte[] iacDenial, short denialLen,
                              byte[] iacOnline, short onlineLen,
                              byte[] iacDefault, short defaultLen) {
        if (intersects(tvr, tvrOff, tvrLen, iacDenial, denialLen)) {
            return EMVCodes.AAC_CODE;
        }
        if (intersects(tvr, tvrOff, tvrLen, iacOnline, onlineLen)) {
            return EMVCodes.ARQC_CODE;
        }
        if (intersects(tvr, tvrOff, tvrLen, iacDefault, defaultLen)) {
            return EMVCodes.AAC_CODE;
        }
        return EMVCodes.TC_CODE;
    }

    /**
     * Caps the card decision to the cryptogram the terminal requested: the card
     * may only downgrade (EMV v4.4 Book 3 section 9.3), never upgrade.  Both arguments
     * are CID type codes (EMVCodes.AAC_CODE / EMVCodes.TC_CODE / EMVCodes.ARQC_CODE).
     */
    public static byte capToRequest(byte requested, byte decided) {
        return rank(decided) <= rank(requested) ? decided : requested;
    }

    /** True if any TVR bit is also set in the corresponding IAC bit. */
    private static boolean intersects(byte[] a, short aOff, short aLen,
                                      byte[] b, short bLen) {
        short n = aLen < bLen ? aLen : bLen;
        for (short i = 0; i < n; i++) {
            if ((a[(short) (aOff + i)] & b[i]) != 0) {
                return true;
            }
        }
        return false;
    }

    /** Hierarchy rank: TC (highest) > ARQC > AAC (lowest). */
    private static short rank(byte cid) {
        if (cid == EMVCodes.TC_CODE) {
            return 3;
        }
        if (cid == EMVCodes.ARQC_CODE) {
            return 2;
        }
        return 1; // AAC
    }
}
