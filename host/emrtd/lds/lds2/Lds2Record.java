package card42.host.emrtd.lds.lds2;

import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;

import card42.host.common.codec.Json;
import card42.host.common.codec.TlvWriter;
import card42.host.common.codec.TlvCursor;
import card42.host.common.util.Hex;

/**
 * A structured LDS2 record (ICAO Doc 9303-10 §5.1/§5.2): the Travel/Entry/Exit
 * records, Visa records and the EF.Certificates signer records.
 *
 * <p>The base class keeps the raw bytes and provides the top-level TLV walk
 * plus a raw fallback; {@link TravelRecord}, {@link VisaRecord} and
 * {@link CertificateRecord} expose the named fields and render text/JSON.
 * Parsing is deliberately tolerant: a card may predate the structured format
 * (an old demo record is only {@code 5F44 || 5F37}), so an incomplete record
 * still yields an object with {@code wellFormed == false} instead of an
 * exception.
 */
public class Lds2Record {

    /** Explicit record kind; the EF/FID determines it, not a display label. */
    public enum Kind {
        TRAVEL, VISA, BIOMETRICS, CERTIFICATE, UNKNOWN;

        /** Compatibility mapping for callers that still carry a display label. */
        public static Kind forLabel(String label) {
            String name = label == null ? "" : label.toLowerCase(java.util.Locale.ROOT);
            if (name.contains("cert")) {
                return CERTIFICATE;
            }
            if (name.contains("visa")) {
                return VISA;
            }
            if (name.contains("entry") || name.contains("exit")) {
                return TRAVEL;
            }
            if (name.contains("biometric")) {
                return BIOMETRICS;
            }
            return UNKNOWN;
        }
    }

    protected final byte[] raw;

    protected Lds2Record(byte[] raw) {
        this.raw = raw == null ? new byte[0] : raw;
    }

    /**
     * Parses the record with an explicit kind derived from the EF/FID.  This is
     * the production path; display labels are not authoritative.
     */
    public static Lds2Record parse(Kind kind, byte[] raw) {
        switch (kind) {
        case CERTIFICATE:
            return new CertificateRecord(raw);
        case VISA:
            return new VisaRecord(raw);
        case TRAVEL:
            return new TravelRecord(raw);
        case BIOMETRICS:
            return new BiometricsRecord(raw);
        default:
            return parseByTags(raw);
        }
    }

    /**
     * Compatibility overload for tests/legacy callers that only have a label.
     *
     * @deprecated production callers should pass an explicit {@link Kind}.
     */
    @Deprecated
    public static Lds2Record parse(String label, byte[] raw) {
        return parse(Kind.forLabel(label), raw);
    }

    private static Lds2Record parseByTags(byte[] raw) {
        Map<Integer, byte[]> top = direct(raw);
        if (top.containsKey(0x71)) {
            return new VisaRecord(raw);
        }
        if (top.containsKey(0x73)) {
            return new TravelRecord(raw);
        }
        if (top.containsKey(0x72)) {
            return new CertificateRecord(raw);
        }
        if (top.containsKey(0x7F2E)) {
            return new BiometricsRecord(raw);
        }
        return new Lds2Record(raw);
    }

    /** The explicit kind of this record. */
    public Kind kind() {
        return Kind.UNKNOWN;
    }

    /** The EF.Certificates reference (5F38), or null when this kind has none. */
    public Integer certificateReference() {
        return null;
    }

    /** Verifies the record's signature token against the signer key. */
    public boolean verify(java.security.PublicKey key) {
        return false;
    }

    public byte[] raw() {
        return raw;
    }

    public String type() {
        return "LDS2 record";
    }

    /** The immediate (top-level) DOs of the record, in document order. */
    protected static Map<Integer, byte[]> direct(byte[] buf) {
        Map<Integer, byte[]> out = new LinkedHashMap<>();
        if (buf == null) {
            return out;
        }
        TlvCursor cursor = new TlvCursor(buf);
        while (cursor.next() == TlvCursor.Status.OK) {
            out.put(cursor.tag(), cursor.value());
        }
        return out;
    }

    protected static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, value);
        return out.toByteArray();
    }

    protected static String ascii(byte[] value) {
        return value == null ? null : new String(value, java.nio.charset.StandardCharsets.US_ASCII);
    }

    protected static String hex(byte[] value) {
        return value == null ? null : Hex.format(value);
    }

    protected static Integer number(byte[] value) {
        if (value == null || value.length == 0) {
            return null;
        }
        int v = 0;
        for (int i = 0; i < value.length; i++) {
            v = (v << 8) | (value[i] & 0xFF);
        }
        return v;
    }

    protected static String tags(byte[] buf) {
        StringBuilder b = new StringBuilder();
        TlvCursor cursor = new TlvCursor(buf);
        while (cursor.next() == TlvCursor.Status.OK) {
            if (b.length() > 0) {
                b.append(' ');
            }
            b.append(String.format("%02X", cursor.tag()));
        }
        return b.toString();
    }

    protected static void putField(Json.Obj out, String name, byte[] value) {
        out.put(name, ascii(value));
    }

    /** A human-readable record view (the base fallback lists the raw tags). */
    public String toText() {
        return type() + " (" + raw.length + " B) tags: " + tags(raw) + "\n";
    }

    /** A JSON object for the record (the base fallback lists type/length/tags). */
    public String toJson() {
        return new Json.Obj()
                .put("type", type())
                .put("length", raw.length)
                .put("tags", tags(raw))
                .build();
    }
}
