package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

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

    /**
     * Largest plaintext READ BINARY window whose secure-messaging envelope fits
     * a 256-byte short APDU: 0x87 (tag + 0x81 length + indicator + M2-padded
     * data) + 0x99 (4) + 0x8E (10) &lt;= 256.  With 231 (0xE7) bytes of plaintext
     * the padded block is 232 and the envelope is 250 bytes; 232 would already
     * need 258.  The old 0xE0 cap wasted 7 bytes on every read of a large EF.
     */
    static final short SM_RESPONSE_MAX = (short) 0xE7;

    private ReadBinary() {
    }

    public static short process(EmrtdApplet applet, short le, byte[] apduBuffer) {
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0xFF);
        short p2 = (short) (apduBuffer[ISO7816.OFFSET_P2] & 0xFF);
        LdsFile file;
        short offset;
        if ((p1 & EmrtdTags.READ_P1_SFI) != 0) {
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
        if (want > SM_RESPONSE_MAX) {
            // The SM envelope (or, in the clear, the short response buffer) is
            // bounded by the 256-byte APDU, so never hand read() a larger window.
            want = SM_RESPONSE_MAX;
        }
        if (!isPublic(file.getFid()) && !smActive) {
            // DG1/DG2/.../DG16 and EF.SOD are only served inside secure
            // messaging (ICAO Doc 9303-10 §5.2, Doc 9303-11 §9.8): a plain
            // read returns 6982.  EF.COM, EF.DG15 and EF.CardAccess stay
            // readable in the clear.
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
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
     * Files a reader may read without secure messaging: EF.COM and EF.DG15
     * (public document/AA data) and EF.CardAccess (PACE/CA negotiation).  Every
     * other LDS1 EF requires BAC/PACE secure messaging.
     */
    private static boolean isPublic(short fid) {
        return fid == EmrtdTags.FID_COM
                || fid == EmrtdTags.FID_DG15
                || fid == EmrtdTags.FID_CARD_ACCESS;
    }

    /** True when this command arrived wrapped in an established SM session. */
    private static boolean smProtected(EmrtdApplet applet, byte[] apduBuffer) {
        return applet.smEstablished
                && (apduBuffer[ISO7816.OFFSET_CLA] & SecureMessaging.SM_CLA_MASK) != 0;
    }
}
