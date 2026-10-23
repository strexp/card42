package card42.emrtd;

import javacard.framework.Util;

/* The master-file elementary files shared by every eMRTD application.
 *
 * EF.CardAccess (011C) and EF.CardSecurity (011D) are contained in the master
 * file, not in an LDS2 application DF (ICAO Doc 9303-10 §3.11.3/§3.11.4): an
 * LDS2 application reads them from the MF.  EF.ATR/INFO (2F01) and EF.DIR
 * (2F00) are also master-file files and are conditionally REQUIRED when an
 * optional LDS2 application is present (§3.11.1/§3.11.2).  The store is static
 * so all applet instances of this package see the same MF files, exactly as on
 * a card with a single master file.
 *
 * The files are created lazily: the Java Card converter does not allow object
 * allocation in a class initializer, so {@link #init()} runs on first use.
 *
 * @author card42
 */

public final class LdsMfStore {

    /**
     * EF.ATR/INFO content for LDS2 (Doc 9303-10 §3.11.1 Table 29):
     * DO'47' card capabilities (full DF name, short EF id, record number;
     * one-byte data unit; command chaining, extended Lc/Le, extended length
     * information) and DO'7F66' extended length (max command/response 4096).
     */
    private static final byte[] ATR_INFO = {
        (byte) 0x47, 0x03, (byte) 0x8C, 0x01, (byte) 0xE0,
        0x7F, 0x66, 0x08, 0x02, 0x02, 0x10, 0x00, 0x02, 0x02, 0x10, 0x00 };

    private static Lds2TransparentFile cardAccess;
    private static Lds2TransparentFile cardSecurity;
    private static Lds2TransparentFile atrInfo;
    private static Lds2TransparentFile dir;
    /** Reused EF.DIR assembly buffer (61 09 4F 07 <AID> templates). */
    private static final byte[] dirBuf = new byte[128];
    private static short dirLength;

    private LdsMfStore() {
    }

    private static void init() {
        if (cardAccess == null) {
            cardAccess = new Lds2TransparentFile(EmrtdTags.FID_CARD_ACCESS);
        }
        if (cardSecurity == null) {
            // EF.CardSecurity embeds the DSC certificate chain; its size is
            // taken from the DGI header at personalization time rather than a
            // fixed budget (docs/specs/emrtd/emrtd.md §2/§8).
            cardSecurity = new Lds2TransparentFile(EmrtdTags.FID_CARD_SECURITY);
        }
        if (atrInfo == null) {
            atrInfo = new Lds2TransparentFile(EmrtdTags.FID_ATR_INFO);
            atrInfo.set(ATR_INFO, (short) 0, (short) ATR_INFO.length);
        }
        if (dir == null) {
            dir = new Lds2TransparentFile(EmrtdTags.FID_DIR);
        }
    }

    /** The MF transparent EF with the given FID (011C/011D/2F01/2F00), or null. */
    public static Lds2TransparentFile file(short fid) {
        init();
        if (fid == EmrtdTags.FID_CARD_ACCESS) {
            return cardAccess;
        }
        if (fid == EmrtdTags.FID_CARD_SECURITY) {
            return cardSecurity;
        }
        if (fid == EmrtdTags.FID_ATR_INFO) {
            return atrInfo;
        }
        if (fid == EmrtdTags.FID_DIR) {
            return dir;
        }
        return null;
    }

    /** The MF transparent EF with the given short EF identifier, or null. */
    public static Lds2TransparentFile fileBySfi(short sfi) {
        init();
        if (sfi == (short) 0x01) {
            return atrInfo; // EF.ATR/INFO (Table 28)
        }
        if (sfi == (short) 0x1E) {
            return dir; // EF.DIR (Table 30)
        }
        if (sfi == (short) (EmrtdTags.FID_CARD_ACCESS & EmrtdTags.SFI_MASK)) {
            return cardAccess;
        }
        if (sfi == (short) (EmrtdTags.FID_CARD_SECURITY & EmrtdTags.SFI_MASK)) {
            return cardSecurity;
        }
        return null;
    }

    /**
     * Appends an application template {@code 61 { 4F <AID> }} to EF.DIR
     * (Doc 9303-10 §3.11.2 Table 31).  Called once per applet instance so the
     * directory lists every application the card hosts.
     */
    public static void addDirectoryEntry(byte[] aid, short aidLen) {
        init();
        if ((short) (dirLength + aidLen + 4) > (short) dirBuf.length) {
            return;
        }
        dirBuf[dirLength++] = 0x61;
        dirBuf[dirLength++] = (byte) (aidLen + 2);
        dirBuf[dirLength++] = 0x4F;
        dirBuf[dirLength++] = (byte) aidLen;
        Util.arrayCopyNonAtomic(aid, (short) 0, dirBuf, dirLength, aidLen);
        dirLength += aidLen;
        dir.set(dirBuf, (short) 0, dirLength);
    }
}
