package card42.host.emrtd.lds.lds1;

import java.util.Collections;
import java.util.List;

import card42.host.emrtd.lds.common.LdsBytes;
import card42.host.emrtd.lds.common.LdsDataGroup;
import card42.host.emrtd.lds.common.LdsFileUtil;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.ParseStatus;

import card42.host.common.codec.Tags;
import card42.host.common.codec.TlvWriter;

/**
 * Generic data group parser/generator (ICAO Doc 9303-10 §5, H7.6).  It
 * recognises the outer application tag, keeps the raw EF bytes and exposes
 * the nested TLV values by tag.  It is the fallback for data groups that have
 * no dedicated model (DG6 is reserved, DG14/DG15 are security objects parsed
 * elsewhere) and the raw access path for every group.
 */
public final class Dg implements LdsDataGroup {

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
        int outer = bytes != null && bytes.length > 0 ? (bytes[0] & 0xFF) : 0;
        int number = LdsFileUtil.dgForTag(outer);
        return new Dg(number, outer, LdsBytes.copy(bytes));
    }

    /** Parses data group {@code number}, checking its outer tag. */
    public static Dg parse(int number, byte[] bytes) {
        int expected = LdsFileUtil.dgTag(number);
        if (expected != 0 && bytes != null && bytes.length > 0
                && (bytes[0] & 0xFF) != expected) {
            throw new IllegalArgumentException("DG" + number + " outer tag is not "
                    + String.format("%02X", expected));
        }
        return new Dg(number, bytes != null && bytes.length > 0
                ? (bytes[0] & 0xFF) : expected, LdsBytes.copy(bytes));
    }

    /** The first value of the given nested tag, or null. */
    public byte[] value(int tag) {
        return Tags.find(raw, tag);
    }

    /** Every value of the given nested tag, in document order. */
    public List<byte[]> values(int tag) {
        return Tags.findAll(raw, tag);
    }

    /** Wraps an inner TLV list in the data-group outer tag (generation). */
    public static byte[] wrap(int dg, byte[] inner) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        TlvWriter.writeTlv(out, LdsFileUtil.dgTag(dg), inner);
        return out.toByteArray();
    }

    @Override
    public int dg() {
        return number;
    }

    @Override
    public byte[] raw() {
        return raw.clone();
    }

    @Override
    public ParseStatus status() {
        return number > 0 ? ParseStatus.OK : ParseStatus.PARTIAL;
    }

    @Override
    public List<LdsIssue> issues() {
        return Collections.emptyList();
    }
}
