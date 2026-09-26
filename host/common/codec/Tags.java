package card42.host.common.codec;

import java.util.Arrays;

/**
 * Host-side BER-TLV search over EMV response buffers.
 *
 * It is the read-side counterpart of the card's {@code card42.Tlv} reader and
 * understands one- and two-byte tags, short and long-form lengths and nested
 * constructed templates.  The EMV Book 3 §7.5 sourcing/format policy that
 * selects among these objects lives in {@link TagPolicy}.
 */
public final class Tags {

    private Tags() {
    }

    /** Finds the first value of tag in a BER-TLV buffer, or null. */
    public static byte[] find(byte[] buf, int tag) {
        return find(buf, 0, buf.length, tag);
    }

    /** Finds the first value of tag in buf[off..off+len), or null (H0.4). */
    public static byte[] find(byte[] buf, int off, int len, int tag) {
        return findValue(buf, off, len, tag);
    }

    /** True when value is a well-formed list of (tag, length) DOL entries. */
    public static boolean isWellFormedDol(byte[] value) {
        int p = 0;
        while (p < value.length) {
            int b = value[p] & 0xFF;
            p += ((b & 0x1F) == 0x1F) ? 2 : 1;
            if (p >= value.length) {
                return false; // tag without a length byte
            }
            int len = value[p++] & 0xFF;
            if ((len & 0x80) != 0) {
                int n = len & 0x7F;
                if (n == 0 || p + n > value.length) {
                    return false;
                }
                p += n;
            }
        }
        return true;
    }

    /**
     * Finds every value of tag in a BER-TLV buffer, in document order.  Used
     * for repeated Directory Entries (tag 61) of a PPSE FCI (EMV Contactless
     * Book B v2.12 Table 3-2).
     */
    public static java.util.List<byte[]> findAll(byte[] buf, int tag) {
        java.util.List<byte[]> out = new java.util.ArrayList<byte[]>();
        collect(buf, 0, buf.length, tag, out);
        return out;
    }

    /**
     * Finds every value of tag among the immediate (top-level) entries of a
     * BER-TLV buffer, without recursing into constructed templates.  Used to
     * collect the Directory Entries that are direct children of the PPSE
     * 'BF0C' (EMV Contactless Book B v2.12 Table 3-2): a '61' nested inside a
     * proprietary template must be ignored by Entry Point.
     */
    public static java.util.List<byte[]> findAllDirect(byte[] buf, int tag) {
        java.util.List<byte[]> out = new java.util.ArrayList<byte[]>();
        int p = 0;
        int end = buf.length;
        while (p < end) {
            int b = buf[p] & 0xFF;
            int t;
            int tagLen;
            if ((b & 0x1F) == 0x1F) {
                if (p + 2 > end) {
                    return out; // truncated two-byte tag
                }
                t = (b << 8) | (buf[p + 1] & 0xFF);
                tagLen = 2;
            } else {
                t = b;
                tagLen = 1;
            }
            int lOff = p + tagLen;
            if (lOff >= end) {
                return out; // tag without a length field
            }
            int lb = buf[lOff] & 0xFF;
            int lLen;
            int vLen;
            if ((lb & 0x80) == 0) {
                lLen = 1;
                vLen = lb;
            } else {
                int n = lb & 0x7F;
                if (n == 0 || lOff + 1 + n > end) {
                    return out; // unsupported or truncated length field
                }
                lLen = 1 + n;
                vLen = 0;
                for (int i = 0; i < n; i++) {
                    vLen = (vLen << 8) | (buf[lOff + 1 + i] & 0xFF);
                }
            }
            int vOff = lOff + lLen;
            if (vOff + vLen > end) {
                return out; // value runs past the buffer
            }
            if (t == tag) {
                out.add(Arrays.copyOfRange(buf, vOff, vOff + vLen));
            }
            p = vOff + vLen;
        }
        return out;
    }

    private static void collect(byte[] buf, int off, int len, int tag,
                                java.util.List<byte[]> out) {
        int p = off;
        int end = off + len;
        while (p < end) {
            int b = buf[p] & 0xFF;
            int t;
            int tagLen;
            if ((b & 0x1F) == 0x1F) {
                if (p + 2 > end) {
                    return; // truncated two-byte tag
                }
                t = (b << 8) | (buf[p + 1] & 0xFF);
                tagLen = 2;
            } else {
                t = b;
                tagLen = 1;
            }
            int lOff = p + tagLen;
            if (lOff >= end) {
                return; // tag without a length field
            }
            int lb = buf[lOff] & 0xFF;
            int lLen;
            int vLen;
            if ((lb & 0x80) == 0) {
                lLen = 1;
                vLen = lb;
            } else {
                int n = lb & 0x7F;
                if (n == 0 || lOff + 1 + n > end) {
                    return; // unsupported or truncated length field
                }
                lLen = 1 + n;
                vLen = 0;
                for (int i = 0; i < n; i++) {
                    vLen = (vLen << 8) | (buf[lOff + 1 + i] & 0xFF);
                }
            }
            int vOff = lOff + lLen;
            if (vOff + vLen > end) {
                return; // value runs past the buffer
            }
            if (t == tag) {
                out.add(Arrays.copyOfRange(buf, vOff, vOff + vLen));
            }
            if ((b & 0x20) != 0) { // constructed
                collect(buf, vOff, vLen, tag, out);
            }
            p = vOff + vLen;
        }
    }

    private static byte[] findValue(byte[] buf, int off, int len, int tag) {
        int p = off;
        int end = off + len;
        while (p < end) {
            int b = buf[p] & 0xFF;
            int t;
            int tagLen;
            if ((b & 0x1F) == 0x1F) {
                if (p + 2 > end) {
                    return null; // truncated two-byte tag
                }
                t = (b << 8) | (buf[p + 1] & 0xFF);
                tagLen = 2;
            } else {
                t = b;
                tagLen = 1;
            }
            int lOff = p + tagLen;
            if (lOff >= end) {
                return null; // tag without a length field
            }
            int lb = buf[lOff] & 0xFF;
            int lLen;
            int vLen;
            if ((lb & 0x80) == 0) {
                lLen = 1;
                vLen = lb;
            } else {
                int n = lb & 0x7F;
                if (n == 0 || lOff + 1 + n > end) {
                    return null; // unsupported or truncated length field
                }
                lLen = 1 + n;
                vLen = 0;
                for (int i = 0; i < n; i++) {
                    vLen = (vLen << 8) | (buf[lOff + 1 + i] & 0xFF);
                }
            }
            int vOff = lOff + lLen;
            if (vOff + vLen > end) {
                return null; // value runs past the buffer
            }
            if (t == tag) {
                return Arrays.copyOfRange(buf, vOff, vOff + vLen);
            }
            if ((b & 0x20) != 0) { // constructed
                byte[] inner = find(buf, vOff, vLen, tag);
                if (inner != null) {
                    return inner;
                }
            }
            p = vOff + vLen;
        }
        return null;
    }
}
