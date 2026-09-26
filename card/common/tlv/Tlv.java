package card42.common;

import javacard.framework.Util;

/* Minimal BER-TLV reader/writer for the subset used by card42.
 *
 * Supported encoding:
 *   - tags of 1 or 2 bytes (a first byte whose low 5 bits are 0x1F is 2 bytes),
 *   - definite lengths with 1, 2 or 3 length bytes (0x81 / 0x82 long form).
 *
 * Indefinite lengths and tags longer than 2 bytes are not supported; card42
 * personalization data never uses them.
 *
 * A tag is represented as a short; one-byte tags have a zero high byte, e.g.
 * 5A is 0x005A and 9F38 is 0x9F38.  All methods operate on caller-supplied
 * arrays and never allocate, so they are safe to use from personalization code
 * running while the applet is not selected.
 *
 * @author card42
 */

public final class Tlv {

    private Tlv() {
    }

    /** True if the tag starting at off is a two-byte tag. */
    public static boolean isTwoByteTag(byte[] buf, short off) {
        return (buf[off] & 0x1F) == 0x1F;
    }

    /** Length in bytes of the tag at off (1 or 2). */
    public static short tagLength(byte[] buf, short off) {
        return isTwoByteTag(buf, off) ? (short) 2 : (short) 1;
    }

    /** Reads the tag at off; one-byte tags have a zero high byte. */
    public static short getTag(byte[] buf, short off) {
        if (isTwoByteTag(buf, off)) {
            return (short) (((buf[off] & 0xFF) << 8) | (buf[(short) (off + 1)] & 0xFF));
        }
        return (short) (buf[off] & 0xFF);
    }

    /**
     * True when the tag is a constructed data object, i.e. bit 6 of its first
     * tag byte is set (EMV v4.4 Book 3 Annex B).  DOLs may only list primitive
     * data objects (EMV v4.4 Book 3 §5.4), so this is the check {@link DolReader} uses.
     */
    public static boolean isConstructed(short tag) {
        short first = (tag & (short) 0xFF00) != 0
                ? (short) ((tag >> 8) & 0xFF) : (short) (tag & 0xFF);
        return (first & 0x20) != 0;
    }

    /**
     * Number of bytes of the length field at off (1, 2 or 3), or 0 for an
     * unsupported (indefinite, 0x7F) length.
     */
    public static short lengthFieldLength(byte[] buf, short off) {
        byte b = buf[off];
        if ((b & 0x80) == 0) {
            return 1;
        }
        short n = (short) (b & 0x7F);
        if (n == 0x7F) {
            return 0; // indefinite length: not supported
        }
        return (short) (1 + n);
    }

    /** Value length of the TLV at off (off points at the length field). */
    public static short getLength(byte[] buf, short off) {
        byte b = buf[off];
        if ((b & 0x80) == 0) {
            return (short) (b & 0xFF);
        }
        short n = (short) (b & 0x7F);
        short len = 0;
        for (short i = 0; i < n; i++) {
            len = (short) ((len << 8) | (buf[(short) (off + 1 + i)] & 0xFF));
        }
        return len;
    }

    /** Offset of the length field of the TLV whose tag starts at off. */
    public static short lengthOffset(byte[] buf, short off) {
        return (short) (off + tagLength(buf, off));
    }

    /** Offset of the value of the TLV at off. */
    public static short valueOffset(byte[] buf, short off) {
        return (short) (off + tagLength(buf, off) + lengthFieldLength(buf, lengthOffset(buf, off)));
    }

    /** Total encoded length (tag + length field + value) of the TLV at off. */
    public static short totalLength(byte[] buf, short off) {
        short lenOff = lengthOffset(buf, off);
        return (short) (tagLength(buf, off) + lengthFieldLength(buf, lenOff) + getLength(buf, lenOff));
    }

    /**
     * Writes 6F { 84 aid || content } at out/outOff and returns the offset just
     * past it.  This is the FCI wrapper shared by the payment and directory
     * applets (docs/specs/common/architecture.md §2).
     */
    public static short appendFci(byte[] aid, short aidOff, short aidLen,
                                  byte[] content, short contentOff, short contentLen,
                                  byte[] out, short outOff) {
        short p = appendTag((short) 0x6F, out, outOff);
        p = appendLength((short) (2 + aidLen + contentLen), out, p);
        p = append((short) 0x84, aid, aidOff, aidLen, out, p);
        if (contentLen > 0) {
            Util.arrayCopyNonAtomic(content, contentOff, out, p, contentLen);
            p += contentLen;
        }
        return p;
    }

    /** Number of bytes of the BER length field for value length len (1-3). */
    public static short lengthSize(short len) {
        if (len <= 0x7F) {
            return 1;
        }
        if (len <= 0xFF) {
            return 2;
        }
        return 3;
    }

    /** Writes the BER length field for len at out/outOff; returns the new offset. */
    public static short appendLength(short len, byte[] out, short outOff) {
        if (len <= 0x7F) {
            out[outOff] = (byte) len;
            return (short) (outOff + 1);
        } else if (len <= 0xFF) {
            out[outOff] = (byte) 0x81;
            out[(short) (outOff + 1)] = (byte) len;
            return (short) (outOff + 2);
        } else {
            out[outOff] = (byte) 0x82;
            out[(short) (outOff + 1)] = (byte) (len >> 8);
            out[(short) (outOff + 2)] = (byte) len;
            return (short) (outOff + 3);
        }
    }

    /** Writes the tag at out/outOff; returns the new offset. */
    public static short appendTag(short tag, byte[] out, short outOff) {
        if ((tag & (short) 0xFF00) != 0) {
            out[outOff] = (byte) (tag >> 8);
            out[(short) (outOff + 1)] = (byte) tag;
            return (short) (outOff + 2);
        }
        out[outOff] = (byte) tag;
        return (short) (outOff + 1);
    }

    /**
     * Appends tag || length || value to out; returns the offset just past the
     * appended Tlv.
     */
    public static short append(short tag, byte[] value, short vOff, short vLen,
                               byte[] out, short outOff) {
        short p = appendTag(tag, out, outOff);
        p = appendLength(vLen, out, p);
        if (vLen > 0) {
            Util.arrayCopyNonAtomic(value, vOff, out, p, vLen);
            p += vLen;
        }
        return p;
    }
}
