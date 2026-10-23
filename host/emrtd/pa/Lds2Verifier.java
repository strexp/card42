package card42.host.emrtd.pa;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.util.Hex;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.lds.lds2.CertificateRecord;
import card42.host.emrtd.lds.lds2.Lds2VerificationView;
import card42.host.emrtd.lds.lds2.Lds2Record;
import card42.host.emrtd.lds.common.LdsFileUtil;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * LDS2 Authenticity verification (ICAO Doc 9303-10 §5.1.2/§5.2.2/§5.3,
 * Doc 9303-12 §7.1.2).
 *
 * <p>An LDS2 record is signed by an LDS2 Signer whose X.509 certificate is
 * stored in the application's EF.Certificates; the record references it by the
 * one-byte {@code 5F38}.  Verification therefore has two independent halves:
 *
 * <ol>
 *   <li>resolve the signer certificate and validate its LDS2 Signer profile
 *       (subject C/CN only, CN &lt;= 9, only AKI + critical EKU, the EKU for the
 *       record type, size &lt;= 900 bytes, validity, CSCA signature);</li>
 *   <li>verify the record's {@code 5F37} authenticity token over the complete
 *       signed-information DO ({@code 73}/{@code 71}/{@code 5F2E}).</li>
 * </ol>
 *
 * <p>This is separate from the LDS2 Authorization PKI (CVCA/DV/terminal CVCs)
 * used by Terminal Authentication: the certificate here is an X.509 signature
 * certificate, not a card-verifiable certificate.
 */
public final class Lds2Verifier {

    public static final String APP_TRAVEL = "travel";
    public static final String APP_VISA = "visa";
    public static final String APP_BIOMETRICS = "biometrics";

    /** LDS2 Signer EKU OIDs (Doc 9303-12 §7.1.2, id-icao-lds2Signer). */
    public static final String EKU_TRAVEL = "2.23.136.1.1.9.8.1";
    public static final String EKU_VISA = "2.23.136.1.1.9.8.2";
    public static final String EKU_BIOMETRICS = "2.23.136.1.1.9.8.3";


    private Lds2Verifier() {
    }

    /** The expected LDS2 Signer EKU for an application, or null for "any LDS2". */
    public static String expectedEku(String application) {
        if (application == null) {
            return null;
        }
        switch (application) {
        case APP_TRAVEL:
            return EKU_TRAVEL;
        case APP_VISA:
            return EKU_VISA;
        case APP_BIOMETRICS:
            return EKU_BIOMETRICS;
        default:
            throw new IllegalArgumentException("unknown LDS2 application: " + application);
        }
    }

    /** A validated signer certificate plus the profile/trust problems found. */
    public static final class CertificateCheck {
        public final X509Certificate certificate;
        public final CertificateRecord record;
        public final String subject;
        public final String country;
        public final boolean profileValid;
        public final boolean trusted;
        public final List<String> problems;

        CertificateCheck(X509Certificate certificate, CertificateRecord record,
                         String subject, String country, boolean profileValid,
                         boolean trusted, List<String> problems) {
            this.certificate = certificate;
            this.record = record;
            this.subject = subject;
            this.country = country;
            this.profileValid = profileValid;
            this.trusted = trusted;
            this.problems = Collections.unmodifiableList(new ArrayList<String>(problems));
        }

        /** Profile and trust are both required for a conformant signer certificate. */
        public boolean valid() {
            return certificate != null && profileValid && trusted;
        }

        Lds2VerificationView.CertificateView view() {
            return new Lds2VerificationView.CertificateView(subject, country,
                    profileValid, trusted);
        }
    }

    /** One record's signature and signer-certificate verification result. */
    public static final class Verification {
        public final String label;
        public final boolean signatureValid;
        public final CertificateCheck certificate;
        public final List<String> problems;

        Verification(String label, boolean signatureValid, CertificateCheck certificate,
                     List<String> problems) {
            this.label = label;
            this.signatureValid = signatureValid;
            this.certificate = certificate;
            this.problems = Collections.unmodifiableList(new ArrayList<String>(problems));
        }

        public boolean valid() {
            return signatureValid && certificate != null && certificate.valid();
        }

        /** Signature + profile valid; used when the caller has no CSCA store. */
        public boolean validWithoutTrust() {
            return signatureValid && certificate != null && certificate.profileValid;
        }

        public Lds2VerificationView view() {
            return new Lds2VerificationView(label, signatureValid,
                    certificate == null ? null : certificate.view(), problems);
        }
    }

    /**
     * Validates an LDS2 Signer certificate against the profile and (when
     * provided) a trusted CSCA store.  {@code record} may be null when the
     * certificate is being checked before it is written.
     */
    public static CertificateCheck checkCertificate(X509Certificate certificate,
                                                    CertificateRecord record,
                                                    String application,
                                                    CscaKeyStore trust) {
        return checkCertificate(certificate, record, application, trust, new Date());
    }

    public static CertificateCheck checkCertificate(X509Certificate certificate,
                                                    CertificateRecord record,
                                                    String application,
                                                    CscaKeyStore trust,
                                                    Date at) {
        return Lds2CertificateProfile.check(certificate, record, application, trust, at);
    }

    /** The two-letter subject countryName, or null when absent/unparseable. */
    public static String subjectCountry(X509Certificate certificate) {
        if (certificate == null) {
            return null;
        }
        try {
            return Lds2CertificateProfile.subjectValue(certificate, "C");
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Loads EF.Certificates record {@code reference} (1-based), or null at 6A83. */
    public static CertificateRecord loadCertificateRecord(EmrtdTerminal terminal, int reference)
            throws Exception {
        if (reference < 1 || reference > 254) {
            return null;
        }
        ResponseAPDU response = terminal.readRecord(
                LdsFileUtil.sfi(LdsFileUtil.FID_CERTIFICATES), reference, false,
                LdsReader.RECORD_LE);
        if (response.getSW() == 0x6A83) {
            return null;
        }
        if (response.getSW() != 0x9000) {
            throw new IllegalStateException("EF.Certificates record " + reference
                    + " -> " + String.format("%04X", response.getSW()));
        }
        return (CertificateRecord) Lds2Record.parse(
                Lds2Record.Kind.CERTIFICATE, response.getData());
    }

    /** Loads and parses EF.Certificates record {@code reference}, or null. */
    public static X509Certificate loadCertificate(EmrtdTerminal terminal, int reference)
            throws Exception {
        CertificateRecord record = loadCertificateRecord(terminal, reference);
        return record == null ? null : x509(record.certificate);
    }

    public static X509Certificate x509(byte[] der) throws Exception {
        if (der == null || der.length == 0) {
            return null;
        }
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }

    public static Map<String, List<Verification>> verifyGroups(EmrtdTerminal terminal,
            Map<String, List<byte[]>> groups, String application, CscaKeyStore trust)
            throws Exception {
        return Lds2RecordVerifier.verifyGroups(terminal, groups, application, trust);
    }

    public static Verification verifyRecord(byte[] raw, String label, X509Certificate signer,
            CertificateRecord signerRecord, String application, CscaKeyStore trust) {
        return Lds2RecordVerifier.verifyRecord(raw, label, signer, signerRecord,
                application, trust);
    }

    public static Integer certificateReference(Lds2Record record) {
        return record.certificateReference();
    }

}
