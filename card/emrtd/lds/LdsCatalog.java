package card42.emrtd;

import card42.common.Tlv;

/* The LDS1 file store plus its data-group index (ICAO Doc 9303-10 §5).
 *
 * The catalog wraps {@link LdsFileSystem}, records which data groups have been
 * stored and, when the personalizer did not send EF.COM explicitly, builds
 * EF.COM from that index.  This is the on-card COM index:
 * the COM data-group list always agrees with the files actually present.
 *
 * @author card42
 */

public final class LdsCatalog {

    /**
     * EF.COM version fields (Doc 9303-10 §4.6.1 Table 35): {@code 5F01} is the
     * 4-byte LDS version {@code "aabb"} and {@code 5F36} the 6-byte Unicode
     * version {@code "aabbcc"}.  There is no {@code 5F37} in EF.COM.
     */
    private static final byte[] LDS_VERSION_1_7 = { 0x30, 0x31, 0x30, 0x37 };
    private static final byte[] UNICODE_VERSION_4_0_1 =
            { 0x30, 0x34, 0x30, 0x30, 0x30, 0x31 };

    /** Bit i (0-based) marks data group i+1 present. */
    private static final short[] DG_BITS = {
        (short) 0x0001, (short) 0x0002, (short) 0x0004, (short) 0x0008,
        (short) 0x0010, (short) 0x0020, (short) 0x0040, (short) 0x0080,
        (short) 0x0100, (short) 0x0200, (short) 0x0400, (short) 0x0800,
        (short) 0x1000, (short) 0x2000, (short) 0x4000, (short) 0x8000 };

    private final LdsFileSystem files;
    private short dataGroupMask;
    private boolean comStored;

    public LdsCatalog() {
        files = new LdsFileSystem();
    }

    public void select(short fid) {
        files.select(fid);
    }

    /** Selects the master file: clears the current EF (see {@link LdsFileSystem}). */
    public void selectMf() {
        files.selectMf();
    }

    public LdsFile getSelected() {
        return files.getSelected();
    }

    /** The EF with the given short EF identifier, or null (SFI READ BINARY). */
    public LdsFile getBySfi(short sfi) {
        return files.getBySfi(sfi);
    }

    /**
     * Selects the EF with the given short EF identifier as the current EF, or
     * null when the SFI is unknown (ISO/IEC 7816-4 §6.1.2).
     */
    public LdsFile selectBySfi(short sfi) {
        return files.selectBySfi(sfi);
    }

    /** Stores the value of a DGI/FID and updates the data-group index. */
    public void store(short fid, byte[] src, short off, short len) {
        LdsFile file = files.get(fid);
        if (file == null) {
            return;
        }
        file.set(src, off, len);
        markPresent(fid);
    }

    /**
     * The LDS1 transparent EF with the given FID, or null when the FID is not
     * an LDS1 file.  Used by the streaming personalization path, which writes
     * the value in chunks via {@link LdsFile#beginSet()} / {@link LdsFile#append}.
     */
    public LdsFile file(short fid) {
        return files.get(fid);
    }

    /** Marks a data group (or EF.COM) present in the on-card index. */
    public void markPresent(short fid) {
        if (fid >= EmrtdTags.FID_DG1 && fid <= EmrtdTags.FID_DG16) {
            dataGroupMask = (short) (dataGroupMask | DG_BITS[(short) (fid - EmrtdTags.FID_DG1)]);
        } else if (fid == EmrtdTags.FID_COM) {
            comStored = true;
        }
    }

    /** The presence bitmask of data groups 1-16 (bit 0 = DG1). */
    public short dataGroupMask() {
        return dataGroupMask;
    }

    /**
     * Builds EF.COM from the index when the personalizer did not send one.
     * Called after the last personalization block.
     */
    public void finalizeCatalog() {
        if (comStored) {
            return;
        }
        LdsFile com = files.get(EmrtdTags.FID_COM);
        if (com == null) {
            return;
        }
        byte[] list = new byte[32];
        short listLength = 0;
        for (short dg = 1; dg <= 16; dg++) {
            if ((dataGroupMask & DG_BITS[(short) (dg - 1)]) == 0) {
                continue;
            }
            short tag = tagForDg(dg);
            if (tag > 0xFF) {
                list[listLength++] = (byte) (tag >> 8);
            }
            list[listLength++] = (byte) tag;
        }
        byte[] body = new byte[64];
        short p = 0;
        p = Tlv.append((short) 0x5F01, LDS_VERSION_1_7, (short) 0, (short) 4, body, p);
        p = Tlv.append((short) 0x5F36, UNICODE_VERSION_4_0_1, (short) 0, (short) 6, body, p);
        p = Tlv.append((short) 0x5C, list, (short) 0, listLength, body, p);

        byte[] comBytes = new byte[64];
        short n = Tlv.append((short) 0x60, body, (short) 0, p, comBytes, (short) 0);
        com.set(comBytes, (short) 0, n);
    }

    /** The outer tag of data group dg (Doc 9303-10 §4.7). */
    private static short tagForDg(short dg) {
        switch (dg) {
        case 1:
            return EmrtdTags.TAG_DG1;
        case 2:
            return EmrtdTags.TAG_DG2;
        case 3:
            return (short) 0x63;
        case 4:
            return (short) 0x76;
        case 5:
            return (short) 0x65;
        case 6:
            return (short) 0x66;
        case 7:
            return (short) 0x67;
        case 8:
            return (short) 0x68;
        case 9:
            return (short) 0x69;
        case 10:
            return (short) 0x6A;
        case 11:
            return (short) 0x6B;
        case 12:
            return (short) 0x6C;
        case 13:
            return (short) 0x6D;
        case 14:
            return (short) 0x6E;
        case 15:
            return EmrtdTags.TAG_DG15;
        default:
            return (short) 0x70; // DG16
        }
    }
}
