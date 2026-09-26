package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* MANAGE SECURITY ENVIRONMENT / GENERAL AUTHENTICATE for Chip Authentication
 * (BSI TR-03110-3 A.4/B.2, ICAO Doc 9303-11 §6.2).
 *
 * The 3DES CA profile authenticates with MSE:SET KAT (P1=41, P2=A6) carrying
 * DO'91' = the terminal's ephemeral ECDH public key and an optional DO'84' key
 * id.  The new secure-messaging keys are stored in the applet and applied after
 * the response to this command has been wrapped with the old keys.
 *
 * @author card42
 */

public final class Mse {

    /** Reusable TLV search result; a per-command array would leak persistent memory. */
    private static final short[] FIND = new short[2];

    private Mse() {
    }

    /** MSE:Set KAT (Chip Authentication) or MSE:Set AT (PACE). */
    public static short process(EmrtdApplet applet, byte p1, byte p2,
                                byte[] data, short off, short len) {
        if ((p1 & 0x7F) != (EmrtdTags.MSE_P1_SET_COMPUTATION & 0x7F)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if ((p2 & 0xFF) == (EmrtdTags.MSE_P2_AT & 0xFF)) {
            applet.pace.mseSetAt(data, off, len);
            applet.useSecureMessaging(applet.pace.isAes());
            return 0;
        }
        if ((p2 & 0xFF) != (EmrtdTags.MSE_P2_KAT & 0xFF)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short[] result = FIND;
        if (!Lds2Record.find(data, off, len, EmrtdTags.DO_CA_PUBLIC_KEY, result)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        applet.chipAuth.deriveSessionKeys(data, result[0], result[1],
                applet.caEnc, (short) 0, applet.caMac, (short) 0);
        applet.caPending = true;
        return 0;
    }

    /** GENERAL AUTHENTICATE (86) runs the PACE steps. */
    public static short generalAuthenticate(EmrtdApplet applet, byte[] data, short off, short len) {
        return applet.pace.generalAuthenticate(applet, data, off, len, applet.response);
    }
}
