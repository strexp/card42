package card42.host.emv.kernel.analysis;

import card42.host.emv.kernel.data.Tvr;

/**
 * Terminal Action Analysis (EMV v4.4 Book 3 §10.7).
 *
 * <p>The terminal compares the TVR with its own Terminal Action Codes and with
 * the card's Issuer Action Codes (when present) to decide which cryptogram to
 * request in GENERATE AC.  The codes are processed in pairs and in the fixed
 * order Denial, Online, Default:
 *
 * <pre>
 *   TVR &amp; (TAC-Denial | IAC-Denial) -&gt; request AAC  (reject offline)
 *   TVR &amp; (TAC-Online | IAC-Online) -&gt; request ARQC (go online)
 *   otherwise                       -&gt; request TC   (approve offline)
 *   TAC/IAC-Default                 -&gt; only when the terminal is unable to go
 *                                      online: AAC when triggered, else TC
 * </pre>
 *
 * <p>The card may only downgrade the requested cryptogram (EMV v4.4 Book 3
 * §9.3), so the kernel's request is an upper bound; the card's own Card Action
 * Analysis can turn an ARQC request into an AAC but never into a TC.
 */
public final class TerminalActionAnalysis {

    /** Cryptogram Information Data codes (EMV v4.4 Book 3 Table 14). */
    public static final byte AAC = (byte) 0x00;
    public static final byte TC = (byte) 0x40;
    public static final byte ARQC = (byte) 0x80;

    /** Default of an absent TAC or IAC-Denial: all bits 0 (EMV v4.4 Book 3 §10.7). */
    private static final byte[] ALL_ZERO = Tvr.blank();

    /** Default of an absent IAC-Online or IAC-Default: all bits 1 (EMV v4.4 Book 3 §10.7). */
    private static final byte[] ALL_ONES = allOnes();

    private TerminalActionAnalysis() {
    }

    /**
     * The cryptogram to request in the first GENERATE AC by a terminal that is
     * able to go online (EMV v4.4 Book 3 §10.7).  The Denial pair is processed
     * first, then the Online pair; when neither triggers, the terminal approves
     * the transaction offline and requests a TC.
     *
     * @param tvr        the Terminal Verification Results
     * @param tacDenial  TAC-Denial (terminal source, all-zero default)
     * @param tacOnline  TAC-Online (terminal source, all-zero default)
     * @param iacDenial  IAC-Denial read from the card, or null (all-zero default)
     * @param iacOnline  IAC-Online read from the card, or null (all-one default)
     */
    public static byte firstAcOnlineCapable(byte[] tvr,
            byte[] tacDenial, byte[] tacOnline, byte[] iacDenial, byte[] iacOnline) {
        if (intersects(tvr, tacDenial, ALL_ZERO) || intersects(tvr, iacDenial, ALL_ZERO)) {
            return AAC;
        }
        if (intersects(tvr, tacOnline, ALL_ZERO) || intersects(tvr, iacOnline, ALL_ONES)) {
            return ARQC;
        }
        return TC;
    }

    /**
     * The cryptogram to request in the first GENERATE AC by an offline-only
     * terminal (EMV v4.4 Book 3 §10.7 option 2): the Denial pair is processed
     * first, then the Default pair (the Online pair is skipped because the
     * terminal cannot go online); when neither triggers, a TC is requested.
     *
     * @param tacDenial  TAC-Denial (terminal source, all-zero default)
     * @param iacDenial  IAC-Denial read from the card, or null (all-zero default)
     * @param tacDefault TAC-Default (terminal source, all-zero default)
     * @param iacDefault IAC-Default read from the card, or null (all-one default)
     */
    public static byte firstAcOfflineOnly(byte[] tvr, byte[] tacDenial, byte[] iacDenial,
            byte[] tacDefault, byte[] iacDefault) {
        if (intersects(tvr, tacDenial, ALL_ZERO) || intersects(tvr, iacDenial, ALL_ZERO)) {
            return AAC;
        }
        if (intersects(tvr, tacDefault, ALL_ZERO) || intersects(tvr, iacDefault, ALL_ONES)) {
            return AAC;
        }
        return TC;
    }

    /**
     * The decision for the second GENERATE AC when the terminal could not go
     * online (EMV v4.4 Book 3 §10.7): the Default pair is reprocessed, an AAC
     * when triggered and a TC otherwise.  This is the TC-vs-AAC request; the
     * card may still downgrade the TC to an AAC.
     *
     * @param tacDefault TAC-Default (terminal source, all-zero default)
     * @param iacDefault IAC-Default read from the card, or null (all-one default)
     */
    public static byte unableToGoOnline(byte[] tvr,
            byte[] tacDefault, byte[] iacDefault) {
        return (intersects(tvr, tacDefault, ALL_ZERO)
                || intersects(tvr, iacDefault, ALL_ONES)) ? AAC : TC;
    }

    /**
     * True when the TVR and the action code share a bit.  An absent action code
     * (null) is replaced by its EMV v4.4 Book 3 §10.7 default ({@code missingDefault});
     * a code shorter than the TVR only matches its leading bytes.
     */
    private static boolean intersects(byte[] tvr, byte[] code, byte[] missingDefault) {
        return Tvr.intersects(tvr, code != null ? code : missingDefault);
    }

    /** A new array of {@link Tvr#LENGTH} bytes, all bits set to 1. */
    private static byte[] allOnes() {
        byte[] ones = new byte[Tvr.LENGTH];
        java.util.Arrays.fill(ones, (byte) 0xFF);
        return ones;
    }
}
