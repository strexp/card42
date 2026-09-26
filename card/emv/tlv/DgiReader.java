package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* Zero-allocation cursor over a sequence of DGI containers (docs/specs/common/architecture.md §2).
 *
 * This is the DGI counterpart of TlvReader and replaces the hand-written loop
 * in PersoHandler.  A DGI container is DGI(2 bytes) || EMV CPS v2.0 length || value,
 * where the length field is the EMV CPS v2.0 §3.2 encoding (1 byte, or 'FF' +
 * 2 bytes) and only the value itself uses BER-TLV.  The cursor is a thin
 * wrapper over DGI/Tlv.
 *
 * @author card42
 */

public final class DgiReader implements ISO7816 {

    private final byte[] buf;
    private final short end;
    private short pos;

    private short dgi;
    private short valueOffset;
    private short valueLength;

    public DgiReader(byte[] buf, short off, short len) {
        this.buf = buf;
        this.pos = off;
        this.end = (short) (off + len);
    }

    /** True while another DGI container starts before the end of the range. */
    public boolean hasNext() {
        return pos < end;
    }

    /**
     * Advances to the next container and exposes it through dgi()/valueOffset()/
     * valueLength().  Throws 6A80 if the container is malformed or runs past the
     * end of the range.
     */
    public void next() {
        // Minimum container is DGI(2) + length(1); the 3-byte EMV CPS v2.0 length needs
        // two more bytes (EMV CPS v2.0 §3.2).
        if ((short) (pos + 3) > end) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short lengthField = Dgi.lengthFieldLength(buf, pos);
        if (lengthField == 3 && (short) (pos + 5) > end) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short total = Dgi.totalLength(buf, pos);
        if (total <= 0 || (short) (pos + total) > end) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        dgi = Dgi.getDgi(buf, pos);
        valueOffset = Dgi.valueOffset(buf, pos);
        valueLength = Dgi.getValueLength(buf, pos);
        pos = (short) (pos + total);
    }

    /** Identifier of the current container. */
    public short dgi() {
        return dgi;
    }

    /** Offset of the current container's value in the backing array. */
    public short valueOffset() {
        return valueOffset;
    }

    /** Length of the current container's value. */
    public short valueLength() {
        return valueLength;
    }
}
