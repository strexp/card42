package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* Incremental DGI (EMV CPS v2.0 §3.2) framing parser for the eMRTD
 * personalization path.
 *
 * The Security Domain forwards each STORE DATA block (a short APDU payload of
 * at most 231 B, docs/specs/emv/personalization.md §1) separately and a DGI
 * value, in particular a DG2 face image, can span many blocks.  The previous
 * design reassembled the whole DGI sequence in one fixed 4096-byte array, which
 * capped the face image and burned persistent memory on every instance.  This
 * parser keeps only the DGI header (at most 5 bytes) plus a few fields and
 * hands the value bytes to a {@link Sink} as they arrive, so peak memory is
 * bounded by one STORE DATA block and never grows with the file size.
 *
 * <p>The DGI header is {@code dgi(2) || length(1 | 0xFF length(2))} (CPS §3.2);
 * a value length above 32767 is refused because READ BINARY addresses an EF by
 * a 15-bit offset (Doc 9303-10 §3.6.3.1) and the card stores the length in a
 * signed short.  {@link #finish()} refuses a sequence that ends in the middle
 * of a DGI, so a truncated personalization cannot look complete.
 *
 * @author card42
 */

public final class DgiStream {

    /**
     * The value consumer: one DGI is delivered as begin / chunk... / end.  It is
     * an abstract class, not an interface, because Java Card 3.0.5 has no
     * default methods: {@link #onReset} and {@link #onFinish} are no-ops that a
     * sink overrides only when it has per-sequence state or final checks.
     */
    public abstract static class Sink {

        /** Clears the sink's per-sequence state (a new P2=0 sequence starts). */
        public void onReset() {
        }

        /** A DGI header was parsed; its value is {@code valueLength} bytes. */
        public abstract void onBeginDgi(short dgi, short valueLength);

        /** The next run of the current value. */
        public abstract void onData(byte[] buf, short off, short len);

        /** The current value is complete. */
        public abstract void onEndDgi();

        /** The last STORE DATA block was received; apply final checks. */
        public void onFinish() {
        }
    }

    /** Largest accepted DGI value (15-bit READ BINARY offset / signed short). */
    public static final short MAX_VALUE = EmrtdTags.MAX_EF_BYTES;

    private static final byte STATE_HEADER = 0;
    private static final byte STATE_VALUE = 1;

    private final Sink sink;
    private final byte[] header = new byte[5];
    private short headerLen;
    private byte state;
    private short dgi;
    private short remaining;

    public DgiStream(Sink sink) {
        this.sink = sink;
        reset();
    }

    /** Clears the stream and the sink (start of a new DGI sequence). */
    public void reset() {
        headerLen = 0;
        state = STATE_HEADER;
        dgi = 0;
        remaining = 0;
        sink.onReset();
    }

    /** Feeds one STORE DATA payload; may be called repeatedly for one value. */
    public void feed(byte[] buf, short off, short len) {
        short p = off;
        short end = (short) (off + len);
        while (p < end) {
            if (state == STATE_VALUE) {
                short n = (short) (end - p);
                if (n > remaining) {
                    n = remaining;
                }
                sink.onData(buf, p, n);
                p = (short) (p + n);
                remaining = (short) (remaining - n);
                if (remaining == 0) {
                    sink.onEndDgi();
                    state = STATE_HEADER;
                    headerLen = 0;
                }
                continue;
            }
            // Header: collect exactly dgi(2) + length(1 or 3) bytes.  headerLen
            // tells us which byte is next (2 = the first length byte, 5 = done).
            header[headerLen++] = buf[p++];
            if (headerLen == (short) 2) {
                dgi = Util.getShort(header, (short) 0);
            } else if (headerLen == (short) 3) {
                short first = (short) (header[2] & 0xFF);
                if (first != (short) 0xFF) {
                    startValue(first);
                }
            } else if (headerLen == (short) 5) {
                short valueLength = Util.getShort(header, (short) 3);
                if (valueLength < 0) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                startValue(valueLength);
            }
        }
    }

    /**
     * Completes the sequence (the block with {@code P1.b8=1} was fed) and
     * refuses a DGI value that stops short.
     */
    public void finish() {
        if (state != STATE_HEADER) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        sink.onFinish();
    }

    private void startValue(short valueLength) {
        if (valueLength < 0 || valueLength > MAX_VALUE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        headerLen = 0;
        if (valueLength == 0) {
            sink.onBeginDgi(dgi, (short) 0);
            sink.onEndDgi();
            state = STATE_HEADER;
            return;
        }
        remaining = valueLength;
        state = STATE_VALUE;
        sink.onBeginDgi(dgi, valueLength);
    }
}
