package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* Zero-allocation cursor over an EMV Data Object List (DOL) definition
 * (EMV v4.4 Book 3 §5.4).
 *
 * A DOL is a list of (tag, length) entries with no values; the terminal fills
 * the values, in order, into the command data field.  The reader walks the
 * definition and, in parallel, tracks the offset of each entry's value inside
 * that data field:
 *
 *   DolReader r = reader.reset(dol, off, len);
 *   while (r.hasNext()) {
 *       r.next();
 *       // r.tag(), r.valueLength(), r.dataOffset()
 *   }
 *
 * It replaces the hand-written "walk tag+length" loops of EMVStaticData
 * (CDOL length / 9F37 offset, docs/specs/emv/personalization.md §3) and provides the PDOL
 * length check of GET PROCESSING OPTIONS and the TVR lookup of Card Action
 * Analysis with a single tool.
 *
 * A malformed or truncated DOL aborts the walk with 6A80, so callers never
 * have to bounds-check themselves.  reset() returns the same instance so a
 * long-lived reader can be reused without allocating on the transaction path.
 *
 * @author card42
 */

public final class DolReader implements ISO7816 {

    private byte[] dol;
    private short end;
    private short pos;

    /** Offset of the current entry's value inside the (virtual) data field. */
    private short dataOffset;
    /** Offset of the next entry's value; equals the total data length so far. */
    private short nextDataOffset;

    private short tag;
    private short valueLength;

    public DolReader() {
        reset(null, (short) 0, (short) 0);
    }

    public DolReader(byte[] dol, short off, short len) {
        reset(dol, off, len);
    }

    /** Restarts the cursor over a new definition; returns this reader. */
    public DolReader reset(byte[] dol, short off, short len) {
        this.dol = dol;
        this.pos = off;
        this.end = (short) (off + len);
        this.dataOffset = 0;
        this.nextDataOffset = 0;
        this.tag = 0;
        this.valueLength = 0;
        return this;
    }

    /** True while another (tag, length) entry starts before the end. */
    public boolean hasNext() {
        return pos < end;
    }

    /**
     * Advances to the next entry.  Throws 6A80 when the tag or length field is
     * malformed or runs past the end of the definition.
     */
    public void next() {
        dataOffset = nextDataOffset;
        short tagLength = Tlv.tagLength(dol, pos);
        if ((short) (pos + tagLength) > end) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        tag = Tlv.getTag(dol, pos);
        pos += tagLength;
        if (pos >= end) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short lengthField = Tlv.lengthFieldLength(dol, pos);
        if (lengthField == 0 || (short) (pos + lengthField) > end) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        valueLength = Tlv.getLength(dol, pos);
        pos += lengthField;
        nextDataOffset += valueLength;
    }

    /** Tag of the current entry (zero high byte for one-byte tags). */
    public short tag() {
        return tag;
    }

    /** Value length of the current entry. */
    public short valueLength() {
        return valueLength;
    }

    /** Offset of the current entry's value inside the data field. */
    public short dataOffset() {
        return dataOffset;
    }

    /**
     * Sum of the value lengths of every entry, i.e. the total length of the
     * data field the terminal has to send.  Consumes the cursor.
     */
    public short totalDataLength() {
        while (hasNext()) {
            next();
        }
        return nextDataOffset;
    }

    /**
     * Validates the current definition as a Data Object List (EMV v4.4 Book 3
     * §5.4): every entry must be a well-formed (tag, length) pair whose tag is a
     * primitive data object.  Constructed tags (e.g. '70', 'A5', 'BF0C') and a
     * primitive inside a terminal-sourced constructed object cannot be requested
     * by a DOL; such a definition is rejected with 6A80.  Returns the total data
     * length.  Consumes the cursor.
     */
    public short validate() {
        while (hasNext()) {
            next();
            if (Tlv.isConstructed(tag)) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
        }
        return nextDataOffset;
    }

    /**
     * Offset of tag's value inside the data field, or -1 when the tag is not
     * listed.  Consumes the cursor.
     */
    public short findValueOffset(short tag) {
        while (hasNext()) {
            next();
            if (this.tag == tag) {
                return dataOffset;
            }
        }
        return -1;
    }
}
