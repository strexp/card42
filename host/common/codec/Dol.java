package card42.host.common.codec;

/**
 * BER-TLV DOL (Data Object List) parsing shared by the EMV terminal data model
 * and the Entry Point: a DOL is a sequence of (tag, length) entries; the value
 * is supplied by the terminal, so only the tag/length walk is generic.
 *
 * <p>These are pure static helpers; they carry no EMV policy.  The policy of
 * which terminal value fills a tag stays in {@code TerminalDol}.
 */
public final class Dol {

    private Dol() {
    }

    /** Total value length described by a DOL definition (tag+length entries). */
    public static int dataLength(byte[] dol) {
        int p = 0;
        int total = 0;
        while (p < dol.length) {
            int b = dol[p] & 0xFF;
            p += (b & 0x1F) == 0x1F ? 2 : 1;
            if (p >= dol.length) {
                throw new IllegalArgumentException("truncated DOL tag");
            }
            int lb = dol[p] & 0xFF;
            int lLen = (lb & 0x80) == 0 ? 1 : 1 + (lb & 0x7F);
            if (p + lLen > dol.length) {
                throw new IllegalArgumentException("truncated DOL length");
            }
            int len = 0;
            if ((lb & 0x80) == 0) {
                len = lb;
            } else {
                for (int i = 0; i < lLen - 1; i++) {
                    len = (len << 8) | (dol[p + 1 + i] & 0xFF);
                }
            }
            total += len;
            p += lLen;
        }
        return total;
    }

    /** Offset of the value of {@code tag} in a DOL definition, or -1. */
    public static int valueOffset(byte[] dol, int tag) {
        int p = 0;
        int offset = 0;
        while (p < dol.length) {
            int b = dol[p] & 0xFF;
            int t;
            int tagLen;
            if ((b & 0x1F) == 0x1F) {
                if (p + 1 >= dol.length) {
                    return -1;
                }
                t = (b << 8) | (dol[p + 1] & 0xFF);
                tagLen = 2;
            } else {
                t = b;
                tagLen = 1;
            }
            p += tagLen;
            if (p >= dol.length) {
                return -1;
            }
            int lb = dol[p] & 0xFF;
            int lLen;
            int len;
            if ((lb & 0x80) == 0) {
                lLen = 1;
                len = lb;
            } else {
                lLen = 1 + (lb & 0x7F);
                if (p + lLen > dol.length) {
                    return -1;
                }
                len = 0;
                for (int i = 0; i < lLen - 1; i++) {
                    len = (len << 8) | (dol[p + 1 + i] & 0xFF);
                }
            }
            if (t == tag) {
                return offset;
            }
            offset += len;
            p += lLen;
        }
        return -1;
    }

    /** True when a DOL definition contains the given tag. */
    public static boolean contains(byte[] dol, int tag) {
        return valueOffset(dol, tag) >= 0;
    }
}
