package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* LDS2 file commands (ICAO Doc 9303-10 §3.11.4): SELECT by DF name or by FID,
 * and READ BINARY of an LDS2 transparent EF or a master-file EF.
 *
 * The LDS2 file system is separate from the LDS1 catalog (Lds2FileSystem) and
 * from the master-file EFs (LdsMfStore).  EF.CardAccess, EF.ATR/INFO and
 * EF.DIR are public; EF.CardSecurity and every DF file require PACE
 * (Doc 9303-11 §1.2 Note 2 / §4.2 step 3, Doc 9303-10 §3.11.4 Table 34).
 *
 * @author card42
 */

public final class Lds2File {

    private Lds2File() {
    }

    /** SELECT (P1=04 by DF name, otherwise a two-byte FID) in an LDS2 session. */
    public static short select(EmrtdApplet applet, byte[] data, short off, short len,
                               byte[] apduBuffer) {
        if (apduBuffer[ISO7816.OFFSET_P1] == 0x04) {
            // SELECT by DF name inside secure messaging (see
            // EmrtdApplet.selectByName).
            return applet.selectByName(data, off, len);
        }
        if (len == 0 || (len == 2 && Util.getShort(data, off) == EmrtdTags.FID_MF)) {
            // SELECT MF: clear the current EF/DF so a following SELECT 011C
            // resolves to the master-file EF.CardAccess (ISO/IEC 7816-4 §7.1.1).
            applet.selectedMf = null;
            applet.lds2.clearSelection();
            return 0;
        }
        if (len != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short fid = Util.getShort(data, off);
        Lds2TransparentFile mf = LdsMfStore.file(fid);
        if (mf != null) {
            // EF.CardAccess, EF.ATR/INFO and EF.DIR are selectable/readable
            // before PACE (ALWAYS, Doc 9303-10 §3.11.3 Table 32 / §3.11.1/2);
            // EF.CardSecurity needs PACE (§3.11.4 Table 34).
            if (!isPublicMf(fid)) {
                applet.requirePace();
            }
            applet.selectedMf = mf;
            applet.lds2.clearSelection();
            return 0;
        }
        // Every DF file needs PACE and, when a Terminal Authentication trust
        // point is personalized, the LDS2 read authorization; Travel/Visa
        // EF.Certificates use b3 while the record/transparent EFs use b1
        // (Doc 9303-10 §5.4.2 Table 96/97/98).
        applet.requireLds2Access(applet.lds2ReadBit(fid));
        applet.selectedMf = null;
        applet.lds2.select(fid);
        return 0;
    }

    /** READ BINARY of an LDS2 transparent EF or the selected master-file EF. */
    public static short readBinary(EmrtdApplet applet, short le, byte[] apduBuffer) {
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0xFF);
        short p2 = (short) (apduBuffer[ISO7816.OFFSET_P2] & 0xFF);
        Lds2TransparentFile file;
        short offset;
        if ((p1 & EmrtdTags.READ_P1_SFI) != 0) {
            // Short EF identifier form (Doc 9303-10 §3.6.3.2 Table 5); a valid
            // SFI also sets that EF as current (ISO/IEC 7816-4 §6.1.2).
            short sfi = (short) (p1 & EmrtdTags.SFI_MASK);
            file = applet.lds2.transparentBySfi(sfi);
            if (file != null) {
                applet.selectedMf = null;
                applet.lds2.selectTransparent(file);
            } else {
                file = LdsMfStore.fileBySfi(sfi);
                if (file != null) {
                    applet.selectedMf = file;
                    applet.lds2.clearSelection();
                }
            }
            offset = p2;
            if (file == null) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND); // 6A82
            }
        } else {
            file = applet.selectedMf != null ? applet.selectedMf
                    : applet.lds2.getSelectedTransparent();
            offset = (short) (((p1 & 0x7F) << 8) | p2);
            if (file == null) {
                // 6986: command not allowed, no current EF (ISO/IEC 7816-4 §6.1.5).
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
        }
        // EF.CardAccess, EF.ATR/INFO and EF.DIR are readable before PACE;
        // EF.CardSecurity (master file) needs PACE (Doc 9303-10 §3.11.4
        // Table 34), the DF transparent EFs need PACE and, when a
        // Terminal Authentication trust point is present, the read
        // authorization (§5.4).
        if (!isPublicMf(file.getFid())) {
            if (applet.selectedMf != null) {
                applet.requirePace();
            } else {
                applet.requireLds2Access(EmrtdApplet.LDS2_READ_BIT);
            }
        }
        short want = le <= 0 ? (short) 256 : le;
        short cap = applet.sm.maxResponseData();
        if (want > cap) {
            want = cap;
        }
        short available = (short) (file.getLength() - offset);
        if (available < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        short n = want < available ? want : available;
        file.read(offset, n, applet.response, (short) 0);
        return n;
    }

    /** True for the master-file EFs readable before PACE (ALWAYS). */
    private static boolean isPublicMf(short fid) {
        return fid == EmrtdTags.FID_CARD_ACCESS
                || fid == EmrtdTags.FID_ATR_INFO
                || fid == EmrtdTags.FID_DIR;
    }
}
