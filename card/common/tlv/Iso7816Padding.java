package card42.common;

/* ISO/IEC 7816-4 §5.6.3 padding method 2 (a mandatory 0x80 then 0x00 to the
 * next block boundary).
 *
 * The EMV Format-1 secure-messaging MAC input and the eMRTD ISO/IEC 7816-4
 * secure-messaging envelopes both use this padding.  Keeping it here avoids
 * two independently written copies of a security-relevant framing rule.
 *
 * All methods are pure static helpers: no objects, arrays or fields, so this
 * class is heap-neutral for the card.
 *
 * @author card42
 */

public final class Iso7816Padding {

    private Iso7816Padding() {
    }

    /** Length after padding method 2: always at least one block larger. */
    public static short paddedLength(short len, short blockSize) {
        return (short) ((len + blockSize) - (len % blockSize));
    }

    /**
     * Pads {@code buf[0..len)} in place and returns the padded length.  The
     * buffer must have room for {@link #paddedLength(short, short)} bytes.
     */
    public static short pad(byte[] buf, short len, short blockSize) {
        return padFrom(buf, (short) 0, len, blockSize);
    }

    /**
     * Pads {@code buf[base..end)} in place (relative to {@code base}) and
     * returns the first byte past the padded region.  This is the form the EMV
     * Format-1 MAC input needs, where the block boundary is measured from the
     * start of the MAC input, not from the start of the buffer.
     */
    public static short padFrom(byte[] buf, short base, short end, short blockSize) {
        buf[end] = (byte) 0x80;
        short p = (short) (end + 1);
        while ((short) (p - base) % blockSize != 0) {
            buf[p] = (byte) 0x00;
            p++;
        }
        return p;
    }

    /**
     * Strips method-2 padding from {@code buf[off..off+len)} in place and
     * returns the unpadded length (relative to {@code off}).
     */
    public static short unpadInPlace(byte[] buf, short off, short len) {
        short i = (short) (off + len);
        while (i > off && buf[(short) (i - 1)] == 0) {
            i--;
        }
        if (i <= off || buf[(short) (i - 1)] != (byte) 0x80) {
            javacard.framework.ISOException.throwIt(
                    javacard.framework.ISO7816.SW_WRONG_DATA);
        }
        return (short) (i - 1 - off);
    }
}
