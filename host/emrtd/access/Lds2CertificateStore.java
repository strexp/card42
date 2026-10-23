package card42.host.emrtd.access;

import java.security.cert.X509Certificate;
import java.util.List;

import card42.host.emrtd.lds.CertificateRecord;
import card42.host.emrtd.lds.CertificateRecordBuilder;
import card42.host.emrtd.lds.Lds2Record;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.pa.CscaKeyStore;
import card42.host.emrtd.pa.Lds2Verifier;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * EF.Certificates reference management for LDS2 writing (Doc 9303-10 §5.1.2):
 * a Travel/Visa/Biometrics record refers to its LDS2 Signer certificate by the
 * one-byte {@code 5F38} record number, so the writer must either reuse an
 * existing certificate record or append a new one and use its number.
 *
 * <p>The signer certificate is validated against the LDS2 Signer profile
 * (Doc 9303-12 §7.1.2) and, when a CSCA store is supplied, against the trusted
 * CSCA chain before it is written.  The {@code 5F3A} country and serial are
 * derived from the certificate, never from a caller-supplied string, so a
 * record cannot claim a different country/serial than its certificate.
 */
public final class Lds2CertificateStore {

    private Lds2CertificateStore() {
    }

    /**
     * Validates {@code certificate} as the LDS2 Signer for {@code application}
     * and appends it unless the same X.509 bytes are already in EF.Certificates.
     *
     * @param application {@code travel}, {@code visa}, {@code biometrics}, or
     *                    null to accept any LDS2 Signer EKU
     * @param trust       trusted CSCA store; a null store only checks the
     *                    certificate profile (callers that write to a card
     *                    should always pass it)
     */
    public static int findOrAppend(EmrtdTerminal terminal, X509Certificate certificate,
                                   String application, CscaKeyStore trust) throws Exception {
        Lds2Verifier.CertificateCheck check =
                Lds2Verifier.checkCertificate(certificate, null, application, trust);
        requireConformant(check, trust != null);
        return appendOrReuse(terminal, certificate, check.country);
    }

    /**
     * Legacy entry point without an application/trust context.  It still
     * enforces the LDS2 Signer profile and that the caller's country matches
     * the certificate subject; new callers should use
     * {@link #findOrAppend(EmrtdTerminal, X509Certificate, String, CscaKeyStore)}.
     */
    @Deprecated
    public static int findOrAppend(EmrtdTerminal terminal, X509Certificate certificate,
                                   String country) throws Exception {
        Lds2Verifier.CertificateCheck check =
                Lds2Verifier.checkCertificate(certificate, null, null, null);
        if (!check.profileValid) {
            throw new IllegalArgumentException("LDS2 signer certificate rejected: "
                    + String.join("; ", check.problems));
        }
        if (country != null && check.country != null
                && !country.equalsIgnoreCase(check.country)) {
            throw new IllegalArgumentException(
                    "5F3A country does not match the certificate subject C: "
                            + country + " vs " + check.country);
        }
        return appendOrReuse(terminal, certificate, check.country);
    }

    private static void requireConformant(Lds2Verifier.CertificateCheck check,
                                          boolean trustRequired) {
        if (!check.profileValid || (trustRequired && !check.trusted)) {
            throw new IllegalArgumentException("LDS2 signer certificate rejected: "
                    + String.join("; ", check.problems));
        }
    }

    private static int appendOrReuse(EmrtdTerminal terminal, X509Certificate certificate,
                                     String country) throws Exception {
        if (country == null || country.length() != 2) {
            throw new IllegalArgumentException(
                    "LDS2 signer certificate has no two-letter subject countryName");
        }
        byte[] encoded = certificate.getEncoded();
        List<byte[]> records = LdsReader.readAllRecords(terminal,
                LdsFileUtil.sfi(LdsFileUtil.FID_CERTIFICATES), 1);
        for (int i = 0; i < records.size(); i++) {
            CertificateRecord record = (CertificateRecord) Lds2Record.parse(
                    "EF.Certificates (011A)", records.get(i));
            if (record.certificate != null
                    && java.util.Arrays.equals(record.certificate, encoded)) {
                return i + 1;
            }
        }
        int reference = records.size() + 1;
        if (reference > 254) {
            throw new IllegalStateException("EF.Certificates record limit reached");
        }
        byte[] record = new CertificateRecordBuilder()
                .country(country)
                .serialNumber(certificate.getSerialNumber().toByteArray())
                .certificate(encoded)
                .build();
        Lds2RecordWriter.append(terminal, LdsFileUtil.FID_CERTIFICATES, record);
        return reference;
    }
}
