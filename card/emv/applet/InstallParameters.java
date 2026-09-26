package card42.emv;

import card42.common.*;

import javacard.framework.AID;
import javacard.framework.Util;

/* The install parameters of an applet instance (Java Card 3.0.5 JCRE §11.2.1).
 *
 * The parameters are encoded as (L,V) instance AID || (L,V) control info ||
 * (L,V) applet data (see docs/specs/common/research-notes.md §3).  The instance AID can
 * also be read from JCSystem.getAID() once the applet is selected; the applet
 * data is what a concrete applet may use to override the role derived from the
 * AID.
 *
 * @author card42
 */

public class InstallParameters {

    /* The AID of this instance, as reported by JCSystem.getAID().  Never longer
     * than 16 bytes (the maximum AID length). */
    private final byte[] currentAid = new byte[(short) 16];
    private short currentAidLength;

    /* The instance AID carried in the install parameters, used as a fallback
     * when JCSystem.getAID() is not available. */
    private final byte[] installAid = new byte[(short) 16];
    private short installAidLength;

    /* The applet data carried in the install parameters, if any. */
    private final byte[] installData = new byte[(short) 8];
    private short installDataLength;

    /**
     * Captures the instance AID and applet data from the install parameters.
     */
    public void capture(byte[] buffer, short offset, short length) {
        short end = (short) (offset + length);
        short p = offset;
        short l;

        // (L,V) instance AID
        l = (short) (buffer[p] & 0x7F);
        p++;
        installAidLength = l > installAid.length ? (short) installAid.length : l;
        Util.arrayCopyNonAtomic(buffer, p, installAid, (short) 0, installAidLength);
        p += l;

        // (L,V) control info
        if (p < end) {
            l = (short) (buffer[p] & 0x7F);
            p = (short) (p + 1 + l);
        }

        // (L,V) applet data
        if (p < end) {
            l = (short) (buffer[p] & 0x7F);
            p++;
            installDataLength = l > installData.length ? (short) installData.length : l;
            Util.arrayCopyNonAtomic(buffer, p, installData, (short) 0, installDataLength);
        }
    }

    /** Records the AID of the applet context, from JCSystem.getAID(). */
    public void setCurrentAid(AID aid) {
        if (aid != null) {
            currentAidLength = aid.getBytes(currentAid, (short) 0);
        }
    }

    /** True if the resolved instance AID (or the install AID) equals candidate. */
    public boolean instanceAidEquals(byte[] candidate) {
        return aidEquals(currentAid, currentAidLength, candidate)
                || aidEquals(installAid, installAidLength, candidate);
    }

    private static boolean aidEquals(byte[] aid, short aidLength, byte[] candidate) {
        if (aidLength != (short) candidate.length) {
            return false;
        }
        // The AID is public, so the short-circuiting Util.arrayCompare is fine
        // here; secret comparisons go through ConstantTime
        // (docs/specs/common/cryptography.md §9).
        return Util.arrayCompare(aid, (short) 0, candidate, (short) 0, aidLength) == 0;
    }

    /** The applet data from the install parameters (may be empty). */
    public byte[] getInstallData() {
        return installData;
    }

    public short getInstallDataLength() {
        return installDataLength;
    }

    /**
     * Resolves a one-byte role/directory code from the applet data of the
     * install parameters (docs/specs/common/research-notes.md §3).  Returns roleA when the first
     * applet data byte is validA, roleB when it is validB, and fallback
     * otherwise (including when no applet data is present).
     */
    public byte roleFromInstallData(byte validA, byte roleA,
            byte validB, byte roleB, byte fallback) {
        if (getInstallDataLength() >= 1) {
            byte r = getInstallData()[0];
            if (r == validA) {
                return roleA;
            }
            if (r == validB) {
                return roleB;
            }
        }
        return fallback;
    }
}
