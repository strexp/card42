package card42.emv;

import card42.common.*;

/* DGI container reader.
 *
 * A DGI container is: DGI(2 bytes) || length || value.  The value is itself
 * usually a BER-TLV structure (see TLV).
 *
 * The length field is the EMV CPS v2.0 §3.2 encoding, not
 * the BER encoding used inside the value:
 *
 *   - one byte for a data length of '00' to 'FE' (0-254 bytes);
 *   - three bytes 'FF' || 2-byte big-endian length for 0-65534 bytes.
 *
 * DGI containers are how personalization data is delivered over STORE DATA
 * (docs/specs/emv/personalization.md §1, EMV CPS v2.0 Annex A).  The card only
 * reads them; the host-side encoder lives in host/PersoScript
 * (docs/specs/emv/personalization.md §6).
 *
 * @author card42
 */

public final class Dgi {

    private Dgi() {
    }

    /** Reads the 2-byte DGI identifier at off. */
    public static short getDgi(byte[] buf, short off) {
        return (short) (((buf[off] & 0xFF) << 8) | (buf[(short) (off + 1)] & 0xFF));
    }

    /** Number of bytes of the EMV CPS v2.0 length field at off (1 or 3). */
    public static short lengthFieldLength(byte[] buf, short off) {
        return buf[(short) (off + 2)] == (byte) 0xFF ? (short) 3 : (short) 1;
    }

    /** Value length of the DGI container at off. */
    public static short getValueLength(byte[] buf, short off) {
        byte b = buf[(short) (off + 2)];
        if (b == (byte) 0xFF) {
            return (short) (((buf[(short) (off + 3)] & 0xFF) << 8)
                    | (buf[(short) (off + 4)] & 0xFF));
        }
        return (short) (b & 0xFF);
    }

    /** Offset of the value of the DGI container at off. */
    public static short valueOffset(byte[] buf, short off) {
        return (short) (off + 2 + lengthFieldLength(buf, off));
    }

    /** Total encoded length (2 + length field + value) of the DGI at off. */
    public static short totalLength(byte[] buf, short off) {
        return (short) (2 + lengthFieldLength(buf, off) + getValueLength(buf, off));
    }
}
