package card42.host.common.codec;

import java.util.ArrayList;
import java.util.List;

/**
 * Minimal DER (X.690) reader for the eMRTD Passive Authentication objects
 * (CMS SignedData, LDS Security Object, X.509).  It handles single-byte tags
 * and definite lengths, which is all the LDS1 SOD uses.
 */
public final class Der {

    /** One parsed tag-length-value. */
    public static final class Tlv {
        public final int tag;
        public final int start;
        public final int valueOffset;
        public final int valueLength;
        public final int end;

        Tlv(int tag, int start, int valueOffset, int valueLength, int end) {
            this.tag = tag;
            this.start = start;
            this.valueOffset = valueOffset;
            this.valueLength = valueLength;
            this.end = end;
        }
    }

    private Der() {
    }

    public static Tlv read(byte[] buf, int off) {
        int tag = buf[off] & 0xFF;
        int p = off + 1;
        int len = buf[p] & 0xFF;
        p++;
        if ((len & 0x80) != 0) {
            int n = len & 0x7F;
            len = 0;
            for (int i = 0; i < n; i++) {
                len = (len << 8) | (buf[p++] & 0xFF);
            }
        }
        return new Tlv(tag, off, p, len, p + len);
    }

    public static List<Tlv> children(byte[] buf, Tlv parent) {
        List<Tlv> out = new ArrayList<Tlv>();
        int p = parent.valueOffset;
        int end = parent.end;
        while (p < end) {
            Tlv child = read(buf, p);
            out.add(child);
            p = child.end;
        }
        return out;
    }

    public static byte[] value(byte[] buf, Tlv t) {
        return java.util.Arrays.copyOfRange(buf, t.valueOffset, t.end);
    }

    public static byte[] encoded(byte[] buf, Tlv t) {
        return java.util.Arrays.copyOfRange(buf, t.start, t.end);
    }

    public static int intValue(byte[] buf, Tlv t) {
        int v = 0;
        for (int i = t.valueOffset; i < t.end; i++) {
            v = (v << 8) | (buf[i] & 0xFF);
        }
        return v;
    }

    /** The dotted-decimal form of an OBJECT IDENTIFIER TLV. */
    public static String oid(byte[] buf, Tlv t) {
        if (t.valueLength == 0) {
            return "";
        }
        StringBuilder b = new StringBuilder();
        int first = buf[t.valueOffset] & 0xFF;
        b.append(first / 40).append('.').append(first % 40);
        long value = 0;
        for (int i = t.valueOffset + 1; i < t.end; i++) {
            value = (value << 7) | (buf[i] & 0x7F);
            if ((buf[i] & 0x80) == 0) {
                b.append('.').append(value);
                value = 0;
            }
        }
        return b.toString();
    }
}
