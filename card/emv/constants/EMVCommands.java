package card42.emv;

/* The EMV command INS bytes (EMV v4.4 Book 3 §6.3.2 Table 3) plus the STORE
 * DATA P1 flag, split out of the former EMVConstants constant interface so a
 * class depends on the command codes only when it handles commands.
 *
 * SELECT (A4) and EXTERNAL AUTHENTICATE (82) are defined by
 * {@link javacard.framework.ISO7816} and are not repeated here.
 *
 * @author card42
 */

public final class EMVCommands {

    private EMVCommands() {
    }

    public static final byte INS_GENERATE_AC = (byte) 0xAE;
    public static final byte INS_GET_DATA = (byte) 0xCA;
    public static final byte INS_GET_PROCESSING_OPTIONS = (byte) 0xA8;
    public static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
    public static final byte INS_VERIFY = (byte) 0x20;
    public static final byte INS_GET_CHALLENGE = (byte) 0x84;
    public static final byte INS_READ_RECORD = (byte) 0xB2;
    /** SEND POI INFORMATION (EMV Contactless Book B v2.12 Annex C). */
    public static final byte INS_SEND_POI_INFORMATION = (byte) 0x1A;

    // post-issuance commands
    public static final byte INS_APPLICATION_BLOCK = (byte) 0x1E;
    public static final byte INS_APPLICATION_UNBLOCK = (byte) 0x18;
    public static final byte INS_CARD_BLOCK = (byte) 0x16;
    public static final byte INS_PIN_CHANGE_UNBLOCK = (byte) 0x24;

    // STORE DATA P1 flags (GP semantics, see docs/specs/emv/personalization.md §1)
    public static final byte STORE_DATA_LAST_BLOCK = (byte) 0x80; // bit8: 1 = last block
}
