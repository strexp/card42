package card42.host.emrtd.lds.common;

/**
 * Bounds-checked big-endian readers for the fixed-length ISO/IEC 19794 and
 * CBEFF headers.  They return -1 when the requested bytes are outside the
 * buffer, so a parser can validate a declared length before using it.
 */
public final class LdsBytes {

    private LdsBytes() {
    }

    public static int u8(byte[] buf, int off) {
        return off >= 0 && off < buf.length ? buf[off] & 0xFF : -1;
    }

    public static int u16(byte[] buf, int off) {
        if (off < 0 || off + 2 > buf.length) {
            return -1;
        }
        return ((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF);
    }

    public static int u24(byte[] buf, int off) {
        if (off < 0 || off + 3 > buf.length) {
            return -1;
        }
        return ((buf[off] & 0xFF) << 16) | ((buf[off + 1] & 0xFF) << 8)
                | (buf[off + 2] & 0xFF);
    }

    /** An unsigned 32-bit value as a long, or -1. */
    public static long u32(byte[] buf, int off) {
        if (off < 0 || off + 4 > buf.length) {
            return -1;
        }
        return ((long) (buf[off] & 0xFF) << 24)
                | ((long) (buf[off + 1] & 0xFF) << 16)
                | ((long) (buf[off + 2] & 0xFF) << 8)
                | (buf[off + 3] & 0xFFL);
    }

    /** An unsigned 48-bit value as a long, or -1. */
    public static long u48(byte[] buf, int off) {
        if (off < 0 || off + 6 > buf.length) {
            return -1;
        }
        long value = 0;
        for (int i = 0; i < 6; i++) {
            value = (value << 8) | (buf[off + i] & 0xFF);
        }
        return value;
    }

    /** A defensive copy of {@code buf[off..off+length)}, clamped to the buffer. */
    public static byte[] copy(byte[] buf, int off, int length) {
        if (buf == null || off < 0 || off > buf.length || length <= 0) {
            return new byte[0];
        }
        int end = Math.min(buf.length, off + length);
        return java.util.Arrays.copyOfRange(buf, off, end);
    }

    /** A defensive copy of the whole array (null becomes empty). */
    public static byte[] copy(byte[] buf) {
        return buf == null ? new byte[0] : buf.clone();
    }
}
