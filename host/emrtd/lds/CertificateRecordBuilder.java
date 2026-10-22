package card42.host.emrtd.lds;

/**
 * Builds an EF.Certificates record (ICAO Doc 9303-10 §5.1.2 Table 83):
 * {@code 5F3A { country(2) || serial } || 72 { X.509 certificate }}.
 * The signer certificate is written once and then referenced by the travel/
 * visa records through {@code 5F38}.
 */
public final class CertificateRecordBuilder extends Lds2RecordBuilder {

    private String country;
    private byte[] serialNumber;
    private byte[] certificate;

    public CertificateRecordBuilder country(String value) {
        country = value;
        return this;
    }

    public CertificateRecordBuilder serialNumber(byte[] value) {
        serialNumber = value;
        return this;
    }

    public CertificateRecordBuilder certificate(byte[] value) {
        certificate = value;
        return this;
    }

    public byte[] build() {
        require("country", country);
        if (country.length() != 2) {
            throw new IllegalArgumentException("certificate country must be two ASCII letters");
        }
        if (serialNumber == null || serialNumber.length == 0) {
            throw new IllegalStateException("certificate serial number is required");
        }
        if (certificate == null || certificate.length == 0) {
            throw new IllegalStateException("X.509 certificate is required");
        }
        return concat(tlv(0x5F3A, concat(ascii(country), serialNumber)),
                tlv(0x72, certificate));
    }
}
