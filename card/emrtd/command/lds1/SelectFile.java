package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* SELECT FILE (ISO/IEC 7816-4 §7.1.1, ICAO Doc 9303-10 §5): P1=02 selects an
 * EF by FID under the current DF, P2=0C returns no FCI.  A SELECT by name
 * (P1=04) that reaches the applet did not match the DF name.
 *
 * The MF forms (P1=00 with no data, or P1=00/02 with FID 3F00) are also served:
 * EF.CardAccess belongs to the master file (Doc 9303-10 §3.11.3).  FID 011C is
 * overloaded: it is the MF EF.CardAccess before secure messaging (readable in
 * the clear) and the DF EF.CVCA (Doc 9303-11 Annex K.2, PACE read) afterwards.
 *
 * @author card42
 */

public final class SelectFile {

    private SelectFile() {
    }

    public static short process(EmrtdApplet applet, byte[] data, short off, short len,
                                byte[] apduBuffer) {
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0xFF);
        if (p1 == 0x04) {
            // SELECT by DF name inside secure messaging (the JCRE cannot match
            // a wrapped SELECT): resolve against this instance's DF name.
            return applet.selectByName(data, off, len);
        }
        if (len == 0) {
            // SELECT MF without a data field (ISO/IEC 7816-4 §7.1.1).
            if (p1 == EmrtdTags.SELECT_P1_BY_FID) {
                selectMf(applet);
                return 0;
            }
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (len != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short fid = Util.getShort(data, off);
        if (fid == EmrtdTags.FID_MF) {
            selectMf(applet);
            return 0;
        }
        // FID 011C is EF.CardAccess in the master file (Doc 9303-10 §3.11.3) and
        // EF.CVCA in the LDS1 DF (Doc 9303-11 Annex K.2).  Before secure
        // messaging 011C is EF.CardAccess, readable in the clear so a reader can
        // learn the PACE parameters (this is what real readers select right after
        // the eMRTD application); once PACE is established it is EF.CVCA (PACE
        // read).  A SELECT MF also forces the master-file EF.CardAccess.
        if (fid == EmrtdTags.FID_CARD_ACCESS && (!applet.smEstablished || applet.atMf)) {
            applet.atMf = false;
            applet.catalog.selectMf();
            applet.selectedMf = LdsMfStore.file(fid);
            return 0;
        }
        // Master-file EF.CardSecurity (Doc 9303-10 §3.11.4): after SELECT MF,
        // FID 011D is the MF EF.CardSecurity, not the DF's EF.SOD.
        if (applet.atMf && fid == EmrtdTags.FID_CARD_SECURITY) {
            // EF.CardSecurity read access is PACE (Doc 9303-10 §3.11.4 Table 34).
            applet.requirePace();
            applet.atMf = false;
            applet.catalog.selectMf();
            applet.selectedMf = LdsMfStore.file(fid);
            return 0;
        }
        applet.atMf = false;
        applet.selectedMf = null;
        applet.catalog.select(fid);
        return 0;
    }

    /** SELECT MF: clears the current EF and marks the master-file context. */
    private static void selectMf(EmrtdApplet applet) {
        applet.atMf = true;
        applet.selectedMf = null;
        applet.catalog.selectMf();
    }
}
