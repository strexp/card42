package card42.host.common.codec;

import java.io.ByteArrayOutputStream;

/**
 * BER-TLV and EMV CPS v2.0 DGI encoders for the host tooling.
 *
 * It is the write-side counterpart of the card's {@code card42.Tlv}/{@code Dgi}
 * readers and of the host-side {@link Tags} finder.  All methods append to a
 * {@link ByteArrayOutputStream} over the exact byte range given.
 */
public final class TlvWriter {

    private TlvWriter() {
    }

    /** Wraps a value in a BER-TLV: tag (1 or 2 bytes) || BER length || value. */
    public static void writeTlv(ByteArrayOutputStream out, int tag, byte[] value) {
        if (tag > 0xFF) {
            out.write((tag >> 8) & 0xFF);
        }
        out.write(tag & 0xFF);
        writeLength(out, value.length);
        out.write(value, 0, value.length);
    }

    /**
     * Wraps a value in a DGI container: DGI || length || value.  The length
     * uses the EMV CPS v2.0 §3.2 encoding: one byte for 0-254 bytes, otherwise
     * 'FF' followed by a 2-byte length.
     */
    public static void writeDgi(ByteArrayOutputStream out, int dgi, byte[] value) {
        out.write((dgi >> 8) & 0xFF);
        out.write(dgi & 0xFF);
        writeCpsLength(out, value.length);
        out.write(value, 0, value.length);
    }

    /** Convenience: the DGI container for a raw value as a new array. */
    public static byte[] dgi(int dgi, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeDgi(out, dgi, value);
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 0x80) {
            out.write(length);
        } else if (length < 0x100) {
            out.write(0x81);
            out.write(length);
        } else {
            out.write(0x82);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        }
    }

    /** Writes the EMV CPS v2.0 DGI length field (1 byte, or FF + 2 bytes). */
    private static void writeCpsLength(ByteArrayOutputStream out, int length) {
        if (length < 0xFF) {
            out.write(length);
        } else {
            out.write(0xFF);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        }
    }
}
