package card42.host.emrtd.lds;

import java.util.Map;
import java.util.Set;

import card42.host.common.codec.Json;

/**
 * An Entry/Exit Travel Record (ICAO Doc 9303-10 §5.1.3/§5.1.4, Table 86):
 * {@code 5F44 || 73{ 5F44, [5F4C], 5F45, 5F4B, 5F46, 5F4A, [5F4D], [5F49],
 * [5F48], [5F4E] } || 5F37 || 5F38}.
 *
 * <p>Legacy/incomplete records may be only {@code 5F44 || 5F37}, so the parser
 * falls back to the top-level DOs for field lookup and marks the record
 * {@code wellFormed == false}.  The checked-in sample personalization now
 * writes the complete Table 86 structure.
 */
public final class TravelRecord extends Lds2Record {

    private static final Set<Integer> MANDATORY_FIELDS = Set.of(
            0x5F45, 0x5F4B, 0x5F46, 0x5F4A);

    public final String state;
    public final byte[] signedInfo;
    public final Map<Integer, byte[]> fields;
    public final byte[] signature;
    public final Integer certificateReference;
    public final boolean wellFormed;

    public TravelRecord(byte[] raw) {
        super(raw);
        Map<Integer, byte[]> top = direct(raw);
        state = ascii(top.get(0x5F44));
        signedInfo = top.get(0x73);
        fields = signedInfo != null ? direct(signedInfo) : top;
        signature = top.get(0x5F37);
        certificateReference = number(top.get(0x5F38));
        boolean complete = signedInfo != null && signature != null && certificateReference != null;
        for (Integer tag : MANDATORY_FIELDS) {
            complete = complete && fields.containsKey(tag);
        }
        wellFormed = complete;
    }

    @Override
    public String type() {
        return "Travel record";
    }

    /** The complete {@code 73 || Len || value} signed by the LDS2-TS key. */
    public byte[] signedInfoTlv() {
        return signedInfo == null ? null : tlv(0x73, signedInfo);
    }

    /** Verifies the 5F37 token with the referenced EF.Certificates public key. */
    public boolean verify(java.security.PublicKey key) {
        return Lds2Signature.verify(key, signedInfoTlv(), signature);
    }

    public String field(int tag) {
        return ascii(fields.get(tag));
    }

    public String travelDate() {
        return field(0x5F45);
    }

    public String inspectionAuthority() {
        return field(0x5F4B);
    }

    public String inspectionLocation() {
        return field(0x5F46);
    }

    public String inspectorReference() {
        return field(0x5F4A);
    }

    public String visaApprovals() {
        return field(0x5F4C);
    }

    public String inspectionResult() {
        return field(0x5F4D);
    }

    public String modeOfTravel() {
        return field(0x5F49);
    }

    public String durationOfStay() {
        return hex(fields.get(0x5F48));
    }

    public String conditions() {
        return field(0x5F4E);
    }

    @Override
    public String toText() {
        StringBuilder b = new StringBuilder();
        b.append(type()).append(" (").append(raw.length).append(" B)");
        if (!wellFormed) {
            b.append(" [incomplete]");
        }
        b.append('\n');
        b.append("  embarkationState  : ").append(state).append('\n');
        b.append("  travelDate        : ").append(travelDate()).append('\n');
        b.append("  inspectionAuthority: ").append(inspectionAuthority()).append('\n');
        b.append("  inspectionLocation : ").append(inspectionLocation()).append('\n');
        b.append("  inspectorReference : ").append(inspectorReference()).append('\n');
        b.append("  visaApprovals      : ").append(visaApprovals()).append('\n');
        b.append("  inspectionResult   : ").append(inspectionResult()).append('\n');
        b.append("  modeOfTravel       : ").append(modeOfTravel()).append('\n');
        b.append("  durationOfStay     : ").append(durationOfStay()).append('\n');
        b.append("  conditions         : ").append(conditions()).append('\n');
        b.append("  signature          : ")
                .append(signature == null ? "-" : signature.length + " B").append('\n');
        b.append("  certificateRef     : ").append(certificateReference).append('\n');
        return b.toString();
    }

    @Override
    public String toJson() {
        Json.Obj out = new Json.Obj()
                .put("type", type())
                .put("length", raw.length)
                .put("wellFormed", wellFormed)
                .put("embarkationState", state)
                .put("travelDate", travelDate())
                .put("inspectionAuthority", inspectionAuthority())
                .put("inspectionLocation", inspectionLocation())
                .put("inspectorReference", inspectorReference())
                .put("visaApprovals", visaApprovals())
                .put("inspectionResult", inspectionResult())
                .put("modeOfTravel", modeOfTravel())
                .put("durationOfStay", durationOfStay())
                .put("conditions", conditions())
                .put("signatureHex", hex(signature));
        if (certificateReference != null) {
            out.put("certificateReference", certificateReference);
        }
        return out.build();
    }
}
