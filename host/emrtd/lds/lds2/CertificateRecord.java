package card42.host.emrtd.lds.lds2;

import java.util.Map;

import card42.host.common.codec.Json;

/**
 * An EF.Certificates signer record (ICAO Doc 9303-10 §5.1.2 Table 83/§5.2.2):
 * {@code 5F3A{ country || serial } || 72{ X.509 certificate }}.
 *
 * <p>A legacy/incomplete record may be a bare X.509 DER record (no 5F3A/72
 * wrapper); the parser accepts that as a fallback so the CLI still reports the
 * certificate length, while {@code wellFormed} stays false.  The checked-in
 * sample personalization now writes the wrapped Table 83 structure.
 */
public final class CertificateRecord extends Lds2Record {

    public final byte[] serial;
    public final String country;
    public final String serialNumber;
    public final byte[] certificate;
    public final boolean wellFormed;

    public CertificateRecord(byte[] raw) {
        super(raw);
        Map<Integer, byte[]> top = direct(raw);
        serial = top.get(0x5F3A);
        byte[] wrapped = top.get(0x72);
        if (wrapped != null) {
            certificate = wrapped;
        } else if (raw != null && raw.length > 0 && (raw[0] & 0xFF) == 0x30) {
            // Demo/legacy bare certificate record.
            certificate = raw;
        } else {
            certificate = null;
        }
        if (serial != null && serial.length >= 2) {
            country = ascii(new byte[] { serial[0], serial[1] });
            serialNumber = hex(java.util.Arrays.copyOfRange(serial, 2, serial.length));
        } else {
            country = null;
            serialNumber = hex(serial);
        }
        wellFormed = serial != null && wrapped != null;
    }

    @Override
    public Kind kind() {
        return Kind.CERTIFICATE;
    }

    @Override
    public String type() {
        return "Certificate record";
    }

    @Override
    public String toText() {
        StringBuilder b = new StringBuilder();
        b.append(type()).append(" (").append(raw.length).append(" B)");
        if (!wellFormed) {
            b.append(" [incomplete: no 5F3A/72 wrapper]");
        }
        b.append('\n');
        b.append("  country           : ").append(country).append('\n');
        b.append("  serialNumber      : ").append(serialNumber).append('\n');
        b.append("  certificate       : ")
                .append(certificate == null ? "-" : certificate.length + " B X.509")
                .append('\n');
        return b.toString();
    }

    @Override
    public String toJson() {
        return new Json.Obj()
                .put("type", type())
                .put("length", raw.length)
                .put("wellFormed", wellFormed)
                .put("country", country)
                .put("serialNumber", serialNumber)
                .put("certificateBytes", certificate == null ? -1 : certificate.length)
                .build();
    }
}
