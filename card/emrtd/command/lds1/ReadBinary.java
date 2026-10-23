package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* READ BINARY (ISO/IEC 7816-4 §6.1.1, ICAO Doc 9303-10 §3.6.3): reads a
 * window of an LDS1 transparent EF.  Two address forms are supported:
 *
 *   - P1 b8 = 0: P1P2 is the 15-bit offset into the currently selected EF
 *     (Doc 9303-10 §3.6.3.1 Table 4);
 *   - P1 b8 = 1: b5..b1 of P1 carry the short EF identifier and P2 is the
 *     8-bit offset, no SELECT required (Doc 9303-10 §3.6.3.2 Table 5); the
 *     addressed EF also becomes the current EF (ISO/IEC 7816-4 §6.1.2), which
 *     is what lets a reader continue a large EF with offset reads after its SFI
 *     prefix reads.  This form is MANDATORY for the eMRTD.
 *
 * The length is the Le and is capped so an SM-wrapped response fits the
 * 256-byte APDU buffer.
 *
 * @author card42
 */

public final class ReadBinary {

    private ReadBinary() {
    }

    public static short process(EmrtdApplet applet, short le, byte[] apduBuffer) {
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0xFF);
        short p2 = (short) (apduBuffer[ISO7816.OFFSET_P2] & 0xFF);
        LdsFile file;
        short offset;
        if ((p1 & EmrtdTags.READ_P1_SFI) == 0 && applet.selectedMf != null) {
            return readSelectedMf(applet, p1, p2, le);
        }
        if ((p1 & EmrtdTags.READ_P1_SFI) != 0
                && (short) (p1 & EmrtdTags.SFI_MASK)
                        == (EmrtdTags.FID_CARD_ACCESS & EmrtdTags.SFI_MASK)
                && !applet.smEstablished) {
            // Short-EF-identifier read of EF.CardAccess (SFI 0x1C) before PACE:
            // the master-file EF.CardAccess, readable in the clear.
            applet.selectedMf = null;
            return readMfFile(applet,
                    LdsMfStore.fileBySfi((short) (p1 & EmrtdTags.SFI_MASK)), p2, le);
        }
        if ((p1 & EmrtdTags.READ_P1_SFI) != 0) {
            // A valid SFI sets that EF as the current EF, so a master-file EF
            // selected earlier is no longer current.
            applet.selectedMf = null;
            // A valid SFI also sets that EF as the current EF (ISO/IEC 7816-4
            // §6.1.2), so the offset READ BINARYs that follow the SFI prefix
            // reads of a large EF need no SELECT.
            file = applet.catalog.selectBySfi((short) (p1 & EmrtdTags.SFI_MASK));
            offset = p2;
            if (file == null) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND); // 6A82
            }
        } else {
            file = applet.catalog.getSelected();
            offset = (short) (((p1 & 0x7F) << 8) | p2);
            if (file == null) {
                // 6986: command not allowed, no current EF (ISO/IEC 7816-4 §6.1.5).
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
        }

        boolean smActive = smProtected(applet, apduBuffer);
        short want = le <= 0 ? (short) 256 : le;
        short cap = applet.sm.maxResponseData();
        if (want > cap) {
            // The SM envelope (or, in the clear, the short response buffer) is
            // bounded by the 256-byte APDU, so never hand read() a larger window.
            want = cap;
        }
        if (!isPublic(file.getFid()) && !smActive) {
            // DG1/DG2/.../DG16 and EF.SOD are only served inside secure
            // messaging (ICAO Doc 9303-10 §5.2, Doc 9303-11 §9.8): a plain
            // read returns 6982.  EF.COM, EF.DG15 and EF.CardAccess stay
            // readable in the clear.
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        // DG3/DG4 additionally require the Terminal Authentication ePassport
        // CHAT bit once a trust point is personalized (Doc 9303-10 §5.4.2).
        applet.requireLds1ChatAccess(file.getFid());
        if (file.getFid() == EmrtdTags.FID_CVCA) {
            return readCvca(applet, offset, want);
        }
        short available = (short) (file.getLength() - offset);
        if (available < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        short n = want < available ? want : available;
        file.read(offset, n, applet.response, (short) 0);
        return n;
    }

    /**
     * Reads a window of the master-file EF.CardSecurity selected in an LDS1
     * session (Doc 9303-10 §3.11.4).  Read access is PACE (Table 34), so the
     * command is refused with 6982 until PACE has completed.
     */
    private static short readSelectedMf(EmrtdApplet applet, short p1, short p2, short le) {
        if (applet.selectedMf.getFid() != EmrtdTags.FID_CARD_ACCESS) {
            // EF.CardSecurity read access is PACE (Doc 9303-10 §3.11.4); the
            // master-file EF.CardAccess stays readable in the clear, so a
            // terminal can learn the PACE parameters before running PACE.
            applet.requirePace();
        }
        short offset = (short) (((p1 & 0x7F) << 8) | p2);
        return readMfFile(applet, applet.selectedMf, offset, le);
    }

    /** Reads a window of a master-file transparent EF (EF.CardAccess/CardSecurity). */
    private static short readMfFile(EmrtdApplet applet, Lds2TransparentFile file,
                                    short offset, short le) {
        if (file == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
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

    /**
     * EF.CVCA (ICAO Doc 9303-11 Annex K.2): the CVCA CARs, most recent first,
     * 36 octets padded with 0x00, generated from the personalized trust points
     * (and any runtime link certificate).  It is not a stored EF, so the content
     * is written straight into the response buffer.
     */
    private static short readCvca(EmrtdApplet applet, short offset, short want) {
        short total = applet.ta.cvca(applet.response, (short) 0);
        short available = (short) (total - offset);
        if (available < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        short n = want < available ? want : available;
        if (offset > 0) {
            Util.arrayCopyNonAtomic(applet.response, offset, applet.response, (short) 0, n);
        }
        return n;
    }

    /**
     * Files a reader may read without secure messaging: EF.COM and EF.DG15
     * (public document/AA data).  EF.CardAccess is a master-file EF served in
     * clear by {@link #readSelectedMf}; every other LDS1 EF (including
     * EF.CVCA, PACE only) requires secure messaging.
     */
    private static boolean isPublic(short fid) {
        return fid == EmrtdTags.FID_COM
                || fid == EmrtdTags.FID_DG15;
    }

    /** True when this command arrived wrapped in an established SM session. */
    private static boolean smProtected(EmrtdApplet applet, byte[] apduBuffer) {
        return applet.smEstablished
                && (apduBuffer[ISO7816.OFFSET_CLA] & SecureMessaging.SM_CLA_MASK) != 0;
    }
}
