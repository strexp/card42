package card42.host.common.codec;

import java.io.ByteArrayOutputStream;

/**
 * Minimal DER (X.690) writer for the eMRTD Passive Authentication objects.
 * Every method returns a complete tag-length-value so callers compose
 * bottom-up.
 */
public final class DerWriter {

    private DerWriter() {
    }

    /** A single-byte-tag DER TLV. */
    public static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (value.length < 0x80) {
            out.write(value.length);
        } else if (value.length < 0x100) {
            out.write(0x81);
            out.write(value.length);
        } else {
            out.write(0x82);
            out.write((value.length >> 8) & 0xFF);
            out.write(value.length & 0xFF);
        }
        out.write(value, 0, value.length);
        return out.toByteArray();
    }

    public static byte[] sequence(byte[]... parts) {
        return tlv(0x30, concat(parts));
    }

    public static byte[] set(byte[]... parts) {
        return tlv(0x31, concat(parts));
    }

    public static byte[] integer(int value) {
        if (value == 0) {
            return tlv(0x02, new byte[] { 0 });
        }
        int length = 1;
        while ((value >>> (8 * length)) != 0) {
            length++;
        }
        byte[] v = new byte[length];
        for (int i = 0; i < length; i++) {
            v[length - 1 - i] = (byte) (value >> (8 * i));
        }
        return tlv(0x02, v);
    }

    /** A non-negative INTEGER from a BigInteger (minimal two's-complement). */
    public static byte[] integer(java.math.BigInteger value) {
        byte[] raw = value.toByteArray();
        return tlv(0x02, raw);
    }

    public static byte[] octetString(byte[] value) {
        return tlv(0x04, value);
    }

    public static byte[] nullValue() {
        return new byte[] { 0x05, 0x00 };
    }

    /** A context-specific constructed tag [n] (0xA0 | n). */
    public static byte[] context(int n, byte[] value) {
        return tlv(0xA0 | n, value);
    }

    /** An OID from its dotted-decimal form. */
    public static byte[] oid(String dotted) {
        String[] parts = dotted.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int first = Integer.parseInt(parts[0]) * 40 + Integer.parseInt(parts[1]);
        out.write(first);
        for (int i = 2; i < parts.length; i++) {
            long value = Long.parseLong(parts[i]);
            int shift = 0;
            while ((value >>> (7 * (shift + 1))) != 0) {
                shift++;
            }
            for (int s = shift; s >= 0; s--) {
                int b = (int) ((value >>> (7 * s)) & 0x7F);
                out.write(s == 0 ? b : (b | 0x80));
            }
        }
        return tlv(0x06, out.toByteArray());
    }

    public static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] p : parts) {
            length += p.length;
        }
        byte[] out = new byte[length];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
