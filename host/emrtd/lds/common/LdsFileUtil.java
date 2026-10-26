package card42.host.emrtd.lds.common;

import card42.host.common.codec.TlvCursor;

/**
 * LDS1/LDS2 file identifier / outer-tag mapping (ICAO Doc 9303-10 §4.6/§4.7 for
 * LDS1 and §5.1–§5.3 for LDS2), the host mirror of the card's
 * {@code card42.emrtd.EmrtdTags} (H0.2/H7.6).
 */
public final class LdsFileUtil {

    // LDS1 elementary files (Doc 9303-10 §4.6).
    public static final int FID_DG1 = 0x0101;
    public static final int FID_DG2 = 0x0102;
    public static final int FID_DG11 = 0x010B;
    public static final int FID_DG12 = 0x010C;
    public static final int FID_DG14 = 0x010E;
    public static final int FID_DG15 = 0x010F;
    public static final int FID_CVCA = 0x011C;
    public static final int FID_SOD = 0x011D;
    public static final int FID_COM = 0x011E;

    // LDS2 elementary files (Doc 9303-10 §3.11/§5).
    public static final int FID_CARD_ACCESS = 0x011C;
    public static final int FID_CARD_SECURITY = 0x011D;
    public static final int FID_CERTIFICATES = 0x011A;
    /** EF.EntryRecords (Travel Records): 0101. */
    public static final int FID_RECORDS = 0x0101;
    /** EF.ExitRecords (Travel Records): 0102. */
    public static final int FID_EXIT_RECORDS = 0x0102;
    /** EF.VisaRecords (Visa Records): 0103 (Doc 9303-10 §5.2.3 Table 89). */
    public static final int FID_VISA_RECORDS = 0x0103;
    /** EF.Biometrics1 (Additional Biometrics): 0201 (Doc 9303-10 §5.3.3). */
    public static final int FID_BIOMETRICS = 0x0201;
    /** EF.ATR/INFO in the master file: 2F01 (Doc 9303-10 §3.11.1). */
    public static final int FID_ATR_INFO = 0x2F01;
    /** EF.DIR in the master file: 2F00 (Doc 9303-10 §3.11.2). */
    public static final int FID_DIR = 0x2F00;

    // LDS2 application DF names (Doc 9303-10 §5).
    public static final String AID_TRAVEL = "A0000002472001";
    public static final String AID_VISA = "A0000002472002";
    public static final String AID_BIOMETRICS = "A0000002472003";

    private LdsFileUtil() {
    }

    /** The FID of data group {@code dg} (1-16). */
    public static int dgFid(int dg) {
        return 0x0100 + dg;
    }

    /** The outer application tag of a data group (Doc 9303-10 §4.7). */
    public static int dgTag(int dg) {
        switch (dg) {
        case 1:
            return 0x61;
        case 2:
            return 0x75;
        case 3:
            return 0x63;
        case 4:
            return 0x76;
        case 5:
            return 0x65;
        case 6:
            return 0x66;
        case 7:
            return 0x67;
        case 8:
            return 0x68;
        case 9:
            return 0x69;
        case 10:
            return 0x6A;
        case 11:
            return 0x6B;
        case 12:
            return 0x6C;
        case 13:
            return 0x6D;
        case 14:
            return 0x6E;
        case 15:
            return 0x6F;
        case 16:
            return 0x70;
        default:
            return 0;
        }
    }

    /**
     * The encoded data group (tag || length || value) inside a read EF.
     *
     * <p>An EF can be larger than the data group it carries: some issuers
     * allocate a fixed-size file and leave the bytes after the outer TLV
     * untouched (observed on PRC passports, where EF.DG11 is 208 bytes while
     * DG11 is a 31-byte object).  The SOD signs the data group, never the EF
     * padding, so Passive Authentication and any other comparison must hash
     * the bytes returned here.
     *
     * @throws IllegalArgumentException when the EF is empty, its first object
     *     is truncated, or its tag is not the tag of {@code dg}
     */
    public static byte[] encodedDataGroup(int dg, byte[] ef) {
        int expectedTag = dgTag(dg);
        if (expectedTag == 0) {
            throw new IllegalArgumentException("not an LDS1 data group: " + dg);
        }
        if (ef == null || ef.length == 0) {
            throw new IllegalArgumentException("DG" + dg + " EF is empty");
        }
        TlvCursor cursor = new TlvCursor(ef);
        if (cursor.next() != TlvCursor.Status.OK) {
            throw new IllegalArgumentException("DG" + dg + " outer TLV is truncated");
        }
        if (cursor.tag() != expectedTag) {
            throw new IllegalArgumentException(String.format(
                    "DG%d outer tag is %02X, expected %02X", dg, cursor.tag(), expectedTag));
        }
        return cursor.encoded();
    }

    /** The FID of an elementary file by its outer tag, or 0. */
    public static int fidForTag(int tag) {
        switch (tag) {
        case 0x61:
            return FID_DG1;
        case 0x75:
            return FID_DG2;
        case 0x6F:
            return FID_DG15;
        case 0x60:
            return FID_COM;
        case 0x77:
            return FID_SOD;
        default:
            return 0;
        }
    }

    /** The data group number of an outer tag (1-16), or 0. */
    public static int dgForTag(int tag) {
        for (int dg = 1; dg <= 16; dg++) {
            if (dgTag(dg) == tag) {
                return dg;
            }
        }
        return 0;
    }

    /**
     * The short EF identifier of an LDS2 FID.  LDS2 file identifiers are
     * {@code 0x01 || SFI} (Doc 9303-10 §5.1), so the SFI is the low byte.
     */
    public static int sfi(int fid) {
        return fid & 0x1F;
    }
}
