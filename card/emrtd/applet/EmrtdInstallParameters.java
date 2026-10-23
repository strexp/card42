package card42.emrtd;

import card42.common.InstallParams;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* Install parameters of an eMRTD applet instance (Java Card 3.0.5 JCRE §11.2.1).
 *
 * The instance AID selects the role: the ICAO LDS1 DF name
 * (A0 00 00 02 47 10 01) is the LDS1 application; the LDS2 DF names
 * (A0 00 00 02 47 20 xx) are the Travel Records, Visa Records and Additional
 * Biometrics applications (Doc 9303-10 §5).  An AID outside this set is
 * rejected at install time instead of silently falling back to a role; a
 * mistyped AID must not create a Biometrics application.
 *
 * The shared (L,V) parsing and AID fallback live in
 * {@link card42.common.InstallParams}.
 *
 * @author card42
 */

public final class EmrtdInstallParameters extends InstallParams {

    public static final byte ROLE_LDS1 = (byte) 0x01;
    public static final byte ROLE_LDS2_TRAVEL = (byte) 0x02;
    public static final byte ROLE_LDS2_VISA = (byte) 0x03;
    public static final byte ROLE_LDS2_BIOMETRICS = (byte) 0x04;

    /** The role of this instance from its AID (LDS1 or an LDS2 application). */
    public byte role() {
        if (instanceAidEquals(EmrtdTags.DF_NAME_LDS1)) {
            return ROLE_LDS1;
        }
        if (instanceAidEquals(EmrtdTags.DF_NAME_TRAVEL)) {
            return ROLE_LDS2_TRAVEL;
        }
        if (instanceAidEquals(EmrtdTags.DF_NAME_VISA)) {
            return ROLE_LDS2_VISA;
        }
        if (instanceAidEquals(EmrtdTags.DF_NAME_BIOMETRICS)) {
            return ROLE_LDS2_BIOMETRICS;
        }
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return 0; // unreachable
    }
}
