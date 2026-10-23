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
        if (country.length() != 2
                || country.charAt(0) < 'A' || country.charAt(0) > 'Z'
                || country.charAt(1) < 'A' || country.charAt(1) > 'Z') {
            throw new IllegalArgumentException(
                    "certificate country must be two upper-case ASCII letters");
        }
        if (serialNumber == null || serialNumber.length == 0) {
            throw new IllegalStateException("certificate serial number is required");
        }
        if (serialNumber.length > 20) {
            throw new IllegalStateException(
                    "certificate serial number must be at most 20 octets");
        }
        if (new java.math.BigInteger(1, serialNumber).signum() == 0) {
            throw new IllegalStateException("certificate serial number must be positive");
        }
        if (certificate == null || certificate.length == 0) {
            throw new IllegalStateException("X.509 certificate is required");
        }
        if (certificate.length > 900) {
            throw new IllegalStateException(
                    "X.509 certificate is " + certificate.length
                            + " bytes; EF.Certificates allows at most 900");
        }
        byte[] serialDo = tlv(0x5F3A, concat(ascii(country), serialNumber));
        if (serialDo.length > 25) {
            // 5F3A tag (2) + one-byte length + at most 22 content octets.
            throw new IllegalStateException("5F3A exceeds the 22-octet content limit");
        }
        byte[] record = concat(serialDo, tlv(0x72, certificate));
        if (record.length > 900) {
            throw new IllegalStateException(
                    "EF.Certificates record is " + record.length
                            + " bytes; the LDS2 limit is 900");
        }
        return record;
    }
}
