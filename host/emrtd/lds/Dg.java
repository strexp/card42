package card42.host.emrtd.lds;

import card42.host.common.codec.Tags;
import card42.host.common.codec.TlvWriter;

/**
 * Generic data group parser/generator for DG3-DG16 (ICAO Doc 9303-10 §5,
 * H7.6).  It recognises the outer application tag, keeps the raw EF bytes and
 * exposes the nested TLV values by tag.  Dedicated parsers exist for the data
 * groups a report consumes (DG1/DG2/DG15); the remaining groups are handled
 * generically because their inner structures vary per issuing State.
 */
public final class Dg {

    public final int number;
    public final int outerTag;
    /** The complete EF bytes, including the outer tag. */
    public final byte[] raw;

    private Dg(int number, int outerTag, byte[] raw) {
        this.number = number;
        this.outerTag = outerTag;
        this.raw = raw;
    }

    /** Parses an EF whose first byte is the data-group outer tag. */
    public static Dg parse(byte[] bytes) {
        int outer = bytes.length > 0 ? (bytes[0] & 0xFF) : 0;
        int number = LdsFileUtil.dgForTag(outer);
        return new Dg(number, outer, bytes);
    }

    /** Parses data group {@code number}, checking its outer tag. */
    public static Dg parse(int number, byte[] bytes) {
        int expected = LdsFileUtil.dgTag(number);
        if (expected != 0 && bytes.length > 0 && (bytes[0] & 0xFF) != expected) {
            throw new IllegalArgumentException("DG" + number + " outer tag is not "
                    + Integer.toHexString(expected));
        }
        return new Dg(number, bytes.length > 0 ? (bytes[0] & 0xFF) : expected, bytes);
    }

    /** The first value of the given nested tag, or null. */
    public byte[] value(int tag) {
        return Tags.find(raw, tag);
    }

    /** Every value of the given nested tag, in document order. */
    public java.util.List<byte[]> values(int tag) {
        return Tags.findAll(raw, tag);
    }

    /** Wraps an inner TLV list in the data-group outer tag (generation). */
    public static byte[] wrap(int dg, byte[] inner) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        TlvWriter.writeTlv(out, LdsFileUtil.dgTag(dg), inner);
        return out.toByteArray();
    }
}
