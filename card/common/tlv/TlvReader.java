package card42.common;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* Zero-allocation cursor over a BER-TLV byte range (docs/specs/common/architecture.md §2).
 *
 * It replaces the hand-written "walk the tags until the end" loops that were
 * repeated in the payment configuration, the directory entry and the
 * personalization handler.  Typical use:
 *
 *   TlvReader r = new TlvReader(buf, off, len);
 *   while (r.hasNext()) {
 *       r.next();
 *       switch (r.tag()) { ... r.valueOffset() ... r.valueLength() ... }
 *   }
 *
 * A malformed or truncated TLV aborts the walk with 6A80, so callers never
 * have to bounds-check themselves.  The cursor keeps no reference to the
 * current TLV beyond the fields read by next(), so it stays allocation-free
 * and is safe to use while the applet is not selected.
 *
 * @author card42
 */

public final class TlvReader implements ISO7816 {

    private final byte[] buf;
    private final short end;
    private short pos;

    private short tag;
    private short valueOffset;
    private short valueLength;

    public TlvReader(byte[] buf, short off, short len) {
        this.buf = buf;
        this.pos = off;
        this.end = (short) (off + len);
    }

    /** True while another TLV starts before the end of the range. */
    public boolean hasNext() {
        return pos < end;
    }

    /**
     * Advances to the next TLV and exposes it through tag()/valueOffset()/
     * valueLength().  Throws 6A80 if the TLV is malformed or runs past the end.
     */
    public void next() {
        short lenOffset = Tlv.lengthOffset(buf, pos);
        if (Tlv.lengthFieldLength(buf, lenOffset) == 0) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short total = Tlv.totalLength(buf, pos);
        if (total <= 0 || (short) (pos + total) > end) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        tag = Tlv.getTag(buf, pos);
        valueOffset = Tlv.valueOffset(buf, pos);
        valueLength = Tlv.getLength(buf, lenOffset);
        pos = (short) (pos + total);
    }

    /** Tag of the current TLV (zero high byte for one-byte tags). */
    public short tag() {
        return tag;
    }

    /** Offset of the current TLV's value in the backing array. */
    public short valueOffset() {
        return valueOffset;
    }

    /** Length of the current TLV's value. */
    public short valueLength() {
        return valueLength;
    }
}
