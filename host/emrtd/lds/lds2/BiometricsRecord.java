package card42.host.emrtd.lds.lds2;

import java.util.Map;

import card42.host.common.codec.Json;
import card42.host.common.codec.TlvCursor;

/**
 * An Additional Biometrics EF (ICAO Doc 9303-10 §5.3, Table 93):
 * {@code 7F2E { 5F2E <biometric data>, 5F37 <signature>, 5F38 <cert ref> }}.
 * The authenticity token covers the complete {@code 5F2E} DO, including its tag
 * and length.
 *
 * <p>A legacy/demo transparent file may contain bare biometric data without the
 * signature wrapper; it is parsed with {@code wellFormed == false} instead of
 * throwing so the report still shows the file length.
 */
public final class BiometricsRecord extends Lds2Record {

    public final byte[] biometrics;
    public final byte[] signedInfo;
    private final byte[] signedInfoEncoded;
    public final byte[] signature;
    public final Integer certificateReference;
    public final boolean wellFormed;

    public BiometricsRecord(byte[] raw) {
        super(raw);
        Map<Integer, byte[]> top = direct(raw);
        byte[] wrapper = top.get(0x7F2E);
        Map<Integer, byte[]> inner = wrapper == null ? top : direct(wrapper);
        biometrics = inner.get(0x5F2E);
        signature = inner.get(0x5F37);
        certificateReference = number(inner.get(0x5F38));
        TlvCursor cursor = new TlvCursor(wrapper == null ? raw : wrapper);
        byte[] encoded = null;
        byte[] value = null;
        while (cursor.next() == TlvCursor.Status.OK) {
            if (cursor.tag() == 0x5F2E) {
                encoded = cursor.encoded();
                value = cursor.value();
                break;
            }
        }
        signedInfo = value != null ? value : biometrics;
        signedInfoEncoded = encoded;
        wellFormed = wrapper != null && biometrics != null
                && signature != null && certificateReference != null;
    }

    @Override
    public Kind kind() {
        return Kind.BIOMETRICS;
    }

    @Override
    public Integer certificateReference() {
        return certificateReference;
    }

    @Override
    public String type() {
        return "Biometrics record";
    }

    /** The complete {@code 5F2E || Len || value} exactly as read from the card. */
    public byte[] signedInfoTlv() {
        if (signedInfoEncoded != null) {
            return signedInfoEncoded.clone();
        }
        return signedInfo == null ? null : tlv(0x5F2E, signedInfo);
    }

    /** Verifies the 5F37 token with the referenced EF.Certificates public key. */
    @Override
    public boolean verify(java.security.PublicKey key) {
        return Lds2Signature.verify(key, signedInfoTlv(), signature);
    }

    @Override
    public String toText() {
        StringBuilder b = new StringBuilder();
        b.append(type()).append(" (").append(raw.length).append(" B)");
        if (!wellFormed) {
            b.append(" [incomplete: no 7F2E/5F37/5F38 wrapper]");
        }
        b.append('\n');
        b.append("  biometrics        : ")
                .append(biometrics == null ? "-" : biometrics.length + " B").append('\n');
        b.append("  signature         : ")
                .append(signature == null ? "-" : signature.length + " B").append('\n');
        b.append("  certificateRef    : ").append(certificateReference).append('\n');
        return b.toString();
    }

    @Override
    public String toJson() {
        return new Json.Obj()
                .put("type", type())
                .put("length", raw.length)
                .put("wellFormed", wellFormed)
                .put("biometricsBytes", biometrics == null ? -1 : biometrics.length)
                .put("signatureHex", hex(signature))
                .put("certificateReference", certificateReference)
                .build();
    }
}
