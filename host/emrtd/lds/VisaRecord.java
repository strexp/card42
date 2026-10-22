package card42.host.emrtd.lds;

import java.util.Map;
import java.util.Set;

import card42.host.common.codec.Json;

/**
 * A Visa Record (ICAO Doc 9303-10 §5.2.3, Table 90):
 * {@code 5F28 || 71{ 5F28, 43, [5F71], [5F72], [5F73], [5F74], [5F75], [5F76],
 * [5F77], 49, 5F25, 5F24, 5A, [5F32], 5B, 5F33, 5F34, 5F35, 5F2B, 5F2C, 5F1F,
 * [5F40] } || 5F37 || 5F38}.
 *
 * <p>As with {@link TravelRecord}, an incomplete record is tolerated: the
 * fields are looked up in the top-level DOs when there is no {@code 71}
 * container, and {@code wellFormed} is false.
 */
public final class VisaRecord extends Lds2Record {

    private static final Set<Integer> MANDATORY_FIELDS = Set.of(
            0x43, 0x49, 0x5F25, 0x5F24, 0x5A, 0x5B, 0x5F33, 0x5F34, 0x5F35,
            0x5F2B, 0x5F2C, 0x5F1F);

    public final String issuingState;
    public final byte[] signedInfo;
    public final Map<Integer, byte[]> fields;
    public final byte[] signature;
    public final Integer certificateReference;
    public final boolean wellFormed;

    public VisaRecord(byte[] raw) {
        super(raw);
        Map<Integer, byte[]> top = direct(raw);
        issuingState = ascii(top.get(0x5F28));
        signedInfo = top.get(0x71);
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
        return "Visa record";
    }

    /** The complete {@code 71 || Len || value} signed by the LDS2-TS key. */
    public byte[] signedInfoTlv() {
        return signedInfo == null ? null : tlv(0x71, signedInfo);
    }

    /** Verifies the 5F37 token with the referenced EF.Certificates public key. */
    public boolean verify(java.security.PublicKey key) {
        return Lds2Signature.verify(key, signedInfoTlv(), signature);
    }

    public String field(int tag) {
        return ascii(fields.get(tag));
    }

    public String documentType() {
        return field(0x43);
    }

    public String machineReadableVisaA() {
        return field(0x5F71);
    }

    public String machineReadableVisaB() {
        return field(0x5F72);
    }

    public String numberOfEntries() {
        return hex(fields.get(0x5F73));
    }

    public String durationOfStay() {
        return hex(fields.get(0x5F74));
    }

    public String passportNumber() {
        return field(0x5F75);
    }

    public String visaType() {
        return hex(fields.get(0x5F76));
    }

    public String territory() {
        return hex(fields.get(0x5F77));
    }

    public String placeOfIssue() {
        return field(0x49);
    }

    public String effectiveDate() {
        return field(0x5F25);
    }

    public String expirationDate() {
        return field(0x5F24);
    }

    public String documentNumber() {
        return field(0x5A);
    }

    public String additionalInfo() {
        return field(0x5F32);
    }

    public String name() {
        return field(0x5B);
    }

    public String surname() {
        return field(0x5F33);
    }

    public String givenNames() {
        return field(0x5F34);
    }

    public String sex() {
        return field(0x5F35);
    }

    public String dateOfBirth() {
        return field(0x5F2B);
    }

    public String nationality() {
        return field(0x5F2C);
    }

    public String mrz() {
        return field(0x5F1F);
    }

    public String biometricsReference() {
        return hex(fields.get(0x5F40));
    }

    @Override
    public String toText() {
        StringBuilder b = new StringBuilder();
        b.append(type()).append(" (").append(raw.length).append(" B)");
        if (!wellFormed) {
            b.append(" [incomplete]");
        }
        b.append('\n');
        b.append("  issuingState      : ").append(issuingState).append('\n');
        b.append("  documentType      : ").append(documentType()).append('\n');
        b.append("  placeOfIssue      : ").append(placeOfIssue()).append('\n');
        b.append("  effectiveDate     : ").append(effectiveDate()).append('\n');
        b.append("  expirationDate    : ").append(expirationDate()).append('\n');
        b.append("  documentNumber    : ").append(documentNumber()).append('\n');
        b.append("  name              : ").append(name()).append('\n');
        b.append("  surname           : ").append(surname()).append('\n');
        b.append("  givenNames        : ").append(givenNames()).append('\n');
        b.append("  sex               : ").append(sex()).append('\n');
        b.append("  dateOfBirth       : ").append(dateOfBirth()).append('\n');
        b.append("  nationality       : ").append(nationality()).append('\n');
        b.append("  mrz               : ").append(mrz()).append('\n');
        b.append("  machineReadableA  : ").append(machineReadableVisaA()).append('\n');
        b.append("  machineReadableB  : ").append(machineReadableVisaB()).append('\n');
        b.append("  numberOfEntries   : ").append(numberOfEntries()).append('\n');
        b.append("  durationOfStay    : ").append(durationOfStay()).append('\n');
        b.append("  passportNumber    : ").append(passportNumber()).append('\n');
        b.append("  visaType          : ").append(visaType()).append('\n');
        b.append("  territory         : ").append(territory()).append('\n');
        b.append("  additionalInfo    : ").append(additionalInfo()).append('\n');
        b.append("  biometricsRef     : ").append(biometricsReference()).append('\n');
        b.append("  signature         : ")
                .append(signature == null ? "-" : signature.length + " B").append('\n');
        b.append("  certificateRef    : ").append(certificateReference).append('\n');
        return b.toString();
    }

    @Override
    public String toJson() {
        Json.Obj out = new Json.Obj()
                .put("type", type())
                .put("length", raw.length)
                .put("wellFormed", wellFormed)
                .put("issuingState", issuingState)
                .put("documentType", documentType())
                .put("placeOfIssue", placeOfIssue())
                .put("effectiveDate", effectiveDate())
                .put("expirationDate", expirationDate())
                .put("documentNumber", documentNumber())
                .put("name", name())
                .put("surname", surname())
                .put("givenNames", givenNames())
                .put("sex", sex())
                .put("dateOfBirth", dateOfBirth())
                .put("nationality", nationality())
                .put("mrz", mrz())
                .put("machineReadableVisaA", machineReadableVisaA())
                .put("machineReadableVisaB", machineReadableVisaB())
                .put("numberOfEntries", numberOfEntries())
                .put("durationOfStay", durationOfStay())
                .put("passportNumber", passportNumber())
                .put("visaType", visaType())
                .put("territory", territory())
                .put("additionalInfo", additionalInfo())
                .put("biometricsReference", biometricsReference())
                .put("signatureHex", hex(signature));
        if (certificateReference != null) {
            out.put("certificateReference", certificateReference);
        }
        return out.build();
    }
}
