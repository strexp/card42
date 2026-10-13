package card42.host.common.codec;

import java.util.Arrays;

/**
 * A forward BER-TLV cursor over a byte buffer (EMV v4.4 Book 3 Annex B and
 * X.690 definite-length encoding).
 *
 * <p>It handles one- and two-byte tags and short/long-form definite lengths.
 * Malformed input is reported through {@link Status} rather than an exception,
 * so both the strict searches in {@link Tags} and the tolerant pretty-printer
 * in the EMV CLI share one parser instead of each re-implementing the
 * tag/length walk.
 */
public final class TlvCursor {

    /** The outcome of {@link #next()}. */
    public enum Status {
        /** A complete tag-length-value was parsed. */
        OK,
        /** The buffer is exhausted. */
        END,
        /** A two-byte tag is truncated. */
        TRUNCATED_TAG,
        /** The length field is missing, indefinite (0x80) or truncated. */
        TRUNCATED_LENGTH,
        /** The value runs past the buffer. */
        TRUNCATED_VALUE
    }

    private final byte[] buf;
    private final int end;
    private int pos;
    private int start;
    private int tag;
    private int tagLength;
    private int valueOffset;
    private int valueLength;
    private Status status = Status.END;

    public TlvCursor(byte[] buf) {
        this(buf, 0, buf == null ? 0 : buf.length);
    }

    public TlvCursor(byte[] buf, int off, int len) {
        this.buf = buf;
        this.pos = off;
        this.end = off + len;
    }

    /** Parses the next data object; every {@link Status} except OK consumes the cursor. */
    public Status next() {
        if (pos >= end) {
            status = Status.END;
            return status;
        }
        start = pos;
        int b = buf[pos] & 0xFF;
        if ((b & 0x1F) == 0x1F) {
            if (pos + 2 > end) {
                status = Status.TRUNCATED_TAG;
                return status;
            }
            tag = (b << 8) | (buf[pos + 1] & 0xFF);
            tagLength = 2;
        } else {
            tag = b;
            tagLength = 1;
        }
        int lOff = pos + tagLength;
        if (lOff >= end) {
            status = Status.TRUNCATED_LENGTH;
            return status;
        }
        int lb = buf[lOff] & 0xFF;
        int lLen;
        if ((lb & 0x80) == 0) {
            lLen = 1;
            valueLength = lb;
        } else {
            int n = lb & 0x7F;
            if (n == 0 || lOff + 1 + n > end) {
                status = Status.TRUNCATED_LENGTH;
                return status;
            }
            lLen = 1 + n;
            valueLength = 0;
            for (int i = 0; i < n; i++) {
                valueLength = (valueLength << 8) | (buf[lOff + 1 + i] & 0xFF);
            }
        }
        valueOffset = lOff + lLen;
        if (valueOffset + valueLength > end) {
            status = Status.TRUNCATED_VALUE;
            return status;
        }
        pos = valueOffset + valueLength;
        status = Status.OK;
        return status;
    }

    /** The status of the most recent {@link #next()} call. */
    public Status status() {
        return status;
    }

    /** The parsed tag (valid after OK, and after TRUNCATED_LENGTH/TRUNCATED_VALUE). */
    public int tag() {
        return tag;
    }

    public int tagLength() {
        return tagLength;
    }

    /** True when bit 6 of the first tag byte is set (constructed template). */
    public boolean constructed() {
        return (buf[start] & 0x20) != 0;
    }

    public int start() {
        return start;
    }

    public int valueOffset() {
        return valueOffset;
    }

    public int valueLength() {
        return valueLength;
    }

    public int end() {
        return valueOffset + valueLength;
    }

    /** Total encoded length (tag + length + value) of the current object. */
    public int totalLength() {
        return end() - start;
    }

    /** A copy of the current value. */
    public byte[] value() {
        return Arrays.copyOfRange(buf, valueOffset, end());
    }

    /** A copy of the full tag || length || value encoding of the current object. */
    public byte[] encoded() {
        return Arrays.copyOfRange(buf, start, end());
    }

    /** A cursor over the current object's value (its children). */
    public TlvCursor child() {
        return new TlvCursor(buf, valueOffset, valueLength);
    }
}
