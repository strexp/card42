package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* PSO:Verify Certificate (INS 0x2A, P1/P2 0x00BE): verifies a CV certificate
 * against the key selected by MSE:Set DST and imports its public key (ICAO Doc
 * 9303-11 §7.1.5.2, BSI TR-03110-3 A.7.2).
 *
 * @author card42
 */

public final class PsoVerifyCertificate {

    private PsoVerifyCertificate() {
    }

    public static short process(EmrtdApplet applet, byte[] data, short off, short len) {
        if (applet.ta == null) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        applet.ta.psoVerifyCertificate(data, off, len);
        return 0;
    }
}
