package card42.emrtd;

import javacard.framework.AID;
import javacard.framework.Util;

/* Install parameters of an eMRTD applet instance (Java Card 3.0.5 JCRE §11.2.1).
 *
 * The instance AID selects the role: the ICAO LDS1 DF name
 * (A0 00 00 02 47 10 01) is the LDS1 application; the LDS2 DF names
 * (A0 00 00 02 47 20 xx) are the Travel Records, Visa Records and Additional
 * Biometrics applications (Doc 9303-10 §5).  The applet data in the install
 * parameters may override the role, mirroring the EMV install path.
 *
 * @author card42
 */

public final class EmrtdInstallParameters {

    public static final byte ROLE_LDS1 = (byte) 0x01;
    public static final byte ROLE_LDS2_TRAVEL = (byte) 0x02;
    public static final byte ROLE_LDS2_VISA = (byte) 0x03;
    public static final byte ROLE_LDS2_BIOMETRICS = (byte) 0x04;

    private final byte[] currentAid = new byte[(short) 16];
    private short currentAidLength;
    private final byte[] installAid = new byte[(short) 16];
    private short installAidLength;
    private final byte[] installData = new byte[(short) 8];
    private short installDataLength;

    public void capture(byte[] buffer, short offset, short length) {
        short end = (short) (offset + length);
        short p = offset;
        short l = (short) (buffer[p] & 0x7F);
        p++;
        installAidLength = l > installAid.length ? (short) installAid.length : l;
        Util.arrayCopyNonAtomic(buffer, p, installAid, (short) 0, installAidLength);
        p += l;
        if (p < end) {
            l = (short) (buffer[p] & 0x7F);
            p = (short) (p + 1 + l);
        }
        if (p < end) {
            l = (short) (buffer[p] & 0x7F);
            p++;
            installDataLength = l > installData.length ? (short) installData.length : l;
            Util.arrayCopyNonAtomic(buffer, p, installData, (short) 0, installDataLength);
        }
    }

    public void setCurrentAid(AID aid) {
        if (aid != null) {
            currentAidLength = aid.getBytes(currentAid, (short) 0);
        }
    }

    /** The instance AID bytes (the DF name), or null when none was captured. */
    public byte[] aid() {
        if (currentAidLength > 0) {
            return currentAid;
        }
        return installAid;
    }

    public short aidLength() {
        return currentAidLength > 0 ? currentAidLength : installAidLength;
    }

    /** The role of this instance from its AID (LDS1 or an LDS2 application). */
    public byte role() {
        if (aidEquals(currentAid, currentAidLength, EmrtdTags.DF_NAME_LDS1)
                || aidEquals(installAid, installAidLength, EmrtdTags.DF_NAME_LDS1)) {
            return ROLE_LDS1;
        }
        if (aidEquals(currentAid, currentAidLength, EmrtdTags.DF_NAME_TRAVEL)
                || aidEquals(installAid, installAidLength, EmrtdTags.DF_NAME_TRAVEL)) {
            return ROLE_LDS2_TRAVEL;
        }
        if (aidEquals(currentAid, currentAidLength, EmrtdTags.DF_NAME_VISA)
                || aidEquals(installAid, installAidLength, EmrtdTags.DF_NAME_VISA)) {
            return ROLE_LDS2_VISA;
        }
        return ROLE_LDS2_BIOMETRICS;
    }

    private static boolean aidEquals(byte[] aid, short aidLength, byte[] candidate) {
        if (aidLength != (short) candidate.length) {
            return false;
        }
        return Util.arrayCompare(aid, (short) 0, candidate, (short) 0, aidLength) == 0;
    }
}
