package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* INTERNAL AUTHENTICATE: Active Authentication (ICAO Doc 9303-11 §5.1).  Signs
 * the 8-byte challenge with the AA private key.
 *
 * @author card42
 */

public final class InternalAuthenticate {

    private InternalAuthenticate() {
    }

    public static short process(EmrtdApplet applet, byte[] data, short off, short len) {
        if (!applet.aa.isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (len != 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        return applet.aa.sign(data, off, (short) 8, applet.response, (short) 0);
    }
}
