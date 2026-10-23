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

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.util.Hex;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.lds.lds2.CertificateRecord;
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

    private static final String OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
    private static final String OID_EXTENDED_KEY_USAGE = "2.5.29.37";
    private static final int MAX_CERTIFICATE_BYTES = 900;
    private static final int MAX_SUBJECT_COMMON_NAME = 9;

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
        List<String> problems = new ArrayList<String>();
        if (certificate == null) {
            problems.add("no LDS2 signer certificate");
            return new CertificateCheck(null, record, null, null, false, false, problems);
        }
        String subject = certificate.getSubjectX500Principal().getName();
        String country = null;
        try {
            country = subjectValue(certificate, "C");
        } catch (RuntimeException e) {
            problems.add("subject cannot be parsed: " + e.getMessage());
        }

        // --- certificate profile (Doc 9303-12 §7.1.2 / Table 7) -------------
        try {
            if (certificate.getVersion() != 3) {
                problems.add("certificate version is not v3");
            }
        } catch (RuntimeException e) {
            problems.add("cannot read certificate version");
        }
        try {
            int encodedLength = certificate.getEncoded().length;
            if (encodedLength > MAX_CERTIFICATE_BYTES) {
                problems.add("certificate is " + encodedLength + " B (EF.Certificates limit 900)");
            }
        } catch (Exception e) {
            problems.add("certificate cannot be encoded");
        }
        try {
            BigInteger serial = certificate.getSerialNumber();
            if (serial == null || serial.signum() <= 0) {
                problems.add("serial number is not positive");
            } else if (serial.toByteArray().length > 20) {
                problems.add("serial number is longer than 20 octets");
            }
        } catch (RuntimeException e) {
            problems.add("cannot read serial number");
        }
        try {
            certificate.checkValidity(at);
        } catch (CertificateExpiredException e) {
            problems.add("certificate has expired");
        } catch (CertificateNotYetValidException e) {
            problems.add("certificate is not yet valid");
        } catch (RuntimeException e) {
            problems.add("certificate validity cannot be checked");
        }

        // subject: countryName + commonName only, CN <= 9 characters.
        try {
            List<Rdn> rdns = new LdapName(
                    certificate.getSubjectX500Principal().getName()).getRdns();
            String commonName = null;
            for (Rdn rdn : rdns) {
                String type = rdn.getType();
                if ("C".equalsIgnoreCase(type)) {
                    String value = String.valueOf(rdn.getValue());
                    if (value.length() != 2 || !value.equals(value.toUpperCase(Locale.ROOT))) {
                        problems.add("subject countryName must be two upper-case letters");
                    }
                } else if ("CN".equalsIgnoreCase(type)) {
                    commonName = String.valueOf(rdn.getValue());
                } else {
                    problems.add("subject contains prohibited attribute " + type);
                }
            }
            if (commonName == null || commonName.isEmpty()) {
                problems.add("subject commonName is missing");
            } else if (commonName.length() > MAX_SUBJECT_COMMON_NAME) {
                problems.add("subject commonName is longer than 9 characters");
            }
        } catch (Exception e) {
            problems.add("subject cannot be parsed: " + e.getMessage());
        }

        Set<String> critical = new LinkedHashSet<String>();
        Set<String> nonCritical = new LinkedHashSet<String>();
        if (certificate.getCriticalExtensionOIDs() != null) {
            critical.addAll(certificate.getCriticalExtensionOIDs());
        }
        if (certificate.getNonCriticalExtensionOIDs() != null) {
            nonCritical.addAll(certificate.getNonCriticalExtensionOIDs());
        }
        Set<String> allExtensions = new LinkedHashSet<String>(critical);
        allExtensions.addAll(nonCritical);
        for (String oid : allExtensions) {
            if (!OID_AUTHORITY_KEY_IDENTIFIER.equals(oid)
                    && !OID_EXTENDED_KEY_USAGE.equals(oid)) {
                problems.add("prohibited certificate extension " + oid);
            }
        }
        if (!allExtensions.contains(OID_AUTHORITY_KEY_IDENTIFIER)) {
            problems.add("AuthorityKeyIdentifier is missing");
        } else if (critical.contains(OID_AUTHORITY_KEY_IDENTIFIER)) {
            problems.add("AuthorityKeyIdentifier must be non-critical");
        }
        if (!allExtensions.contains(OID_EXTENDED_KEY_USAGE)) {
            problems.add("ExtendedKeyUsage is missing");
        } else if (!critical.contains(OID_EXTENDED_KEY_USAGE)) {
            problems.add("ExtendedKeyUsage must be critical");
        }
        List<String> eku = null;
        try {
            eku = certificate.getExtendedKeyUsage();
        } catch (Exception e) {
            problems.add("ExtendedKeyUsage cannot be parsed");
        }
        String expected = expectedEku(application);
        if (eku == null || eku.isEmpty()) {
            problems.add("ExtendedKeyUsage is empty");
        } else if (expected != null && !eku.contains(expected)) {
            problems.add("ExtendedKeyUsage does not contain " + expected + " for " + application);
        } else if (expected == null
                && !eku.contains(EKU_TRAVEL)
                && !eku.contains(EKU_VISA)
                && !eku.contains(EKU_BIOMETRICS)) {
            problems.add("ExtendedKeyUsage contains no LDS2 Signer OID");
        }

        // --- 5F3A consistency (country + serial must identify this cert) -----
        if (record != null) {
            if (record.serial == null || record.serial.length == 0) {
                problems.add("5F3A is missing");
            } else if (record.serial.length > 22) {
                problems.add("5F3A is longer than 22 octets");
            } else {
                if (country != null && record.country != null
                        && !country.equalsIgnoreCase(record.country)) {
                    problems.add("5F3A country does not match the certificate subject C");
                }
                try {
                    BigInteger serial = new BigInteger(Hex.parse(record.serialNumber));
                    if (!serial.equals(certificate.getSerialNumber())) {
                        problems.add("5F3A serial does not match the certificate serial");
                    }
                } catch (RuntimeException e) {
                    problems.add("5F3A serial cannot be parsed");
                }
            }
            if (record.certificate != null) {
                try {
                    if (!java.util.Arrays.equals(record.certificate, certificate.getEncoded())) {
                        problems.add("72 certificate bytes differ from the parsed certificate");
                    }
                } catch (Exception e) {
                    // getEncoded failure already reported above.
                }
            }
        }

        boolean profileValid = problems.isEmpty();
        boolean trusted = false;
        String trustError = null;
        if (trust == null) {
            problems.add("no CSCA trust store (trust not verified)");
        } else {
            try {
                CertificateTrust.verify(certificate, trust, at);
                trusted = true;
            } catch (Exception e) {
                trustError = e.getMessage();
            }
            if (!trusted) {
                problems.add("not signed by a trusted CSCA"
                        + (trustError == null ? "" : ": " + trustError));
            }
        }
        return new CertificateCheck(certificate, record, subject, country,
                profileValid, trusted, problems);
    }

    /** The two-letter subject countryName, or null when absent/unparseable. */
    public static String subjectCountry(X509Certificate certificate) {
        if (certificate == null) {
            return null;
        }
        try {
            return subjectValue(certificate, "C");
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

    /**
     * Verifies every record in {@code groups} (label -> records) and returns the
     * same shape of results.  EF.Certificates is read once and cached by record
     * number.
     */
    public static Map<String, List<Verification>> verifyGroups(EmrtdTerminal terminal,
                                                               Map<String, List<byte[]>> groups,
                                                               String application,
                                                               CscaKeyStore trust)
            throws Exception {
        Map<String, List<Verification>> out =
                new LinkedHashMap<String, List<Verification>>();
        if (groups == null) {
            return out;
        }
        Map<Integer, CertificateRecord> records = new LinkedHashMap<Integer, CertificateRecord>();
        Map<Integer, X509Certificate> certificates = new LinkedHashMap<Integer, X509Certificate>();
        List<byte[]> certificateBytes = LdsReader.readAllRecords(terminal,
                LdsFileUtil.sfi(LdsFileUtil.FID_CERTIFICATES), 1);
        for (int i = 0; i < certificateBytes.size(); i++) {
            CertificateRecord record = (CertificateRecord) Lds2Record.parse(
                    Lds2Record.Kind.CERTIFICATE, certificateBytes.get(i));
            records.put(i + 1, record);
            try {
                certificates.put(i + 1, x509(record.certificate));
            } catch (Exception e) {
                certificates.put(i + 1, null);
            }
        }
        for (Map.Entry<String, List<byte[]>> group : groups.entrySet()) {
            List<Verification> results = new ArrayList<Verification>();
            for (byte[] raw : group.getValue()) {
                Lds2Record record = Lds2Record.parse(
                        Lds2Record.Kind.forLabel(group.getKey()), raw);
                if (record.kind() == Lds2Record.Kind.CERTIFICATE) {
                    CertificateRecord certificateRecord = (CertificateRecord) record;
                    CertificateCheck check = checkCertificate(
                            x509(certificateRecord.certificate),
                            certificateRecord, application, trust);
                    results.add(new Verification(group.getKey(), check.profileValid, check,
                            check.problems));
                } else {
                    results.add(verifyRecord(record, group.getKey(), records, certificates,
                            application, trust));
                }
            }
            out.put(group.getKey(), results);
        }
        return out;
    }

    /** Verifies one record against the certificate cache built by {@link #verifyGroups}. */
    private static Verification verifyRecord(Lds2Record record, String label,
                                             Map<Integer, CertificateRecord> records,
                                             Map<Integer, X509Certificate> certificates,
                                             String application, CscaKeyStore trust) {
        List<String> problems = new ArrayList<String>();
        Integer reference = certificateReference(record);
        CertificateCheck check = null;
        if (reference == null) {
            problems.add("record has no 5F38 certificate reference");
        } else {
            CertificateRecord certificateRecord = records.get(reference);
            X509Certificate certificate = certificates.get(reference);
            if (certificateRecord == null) {
                problems.add("5F38 references missing EF.Certificates record " + reference);
            } else if (certificate == null) {
                problems.add("EF.Certificates record " + reference + " has no X.509 certificate");
            } else {
                check = checkCertificate(certificate, certificateRecord, application, trust);
            }
        }
        boolean signatureValid = false;
        if (check != null && check.certificate != null) {
            signatureValid = signature(record, check.certificate.getPublicKey());
            if (!signatureValid) {
                problems.add("5F37 signature does not verify");
            }
        }
        return new Verification(label, signatureValid, check, problems);
    }

    /** Verifies a record against an explicitly supplied signer certificate. */
    public static Verification verifyRecord(byte[] raw, String label, X509Certificate signer,
                                            CertificateRecord signerRecord, String application,
                                            CscaKeyStore trust) {
        Lds2Record record = Lds2Record.parse(Lds2Record.Kind.forLabel(label), raw);
        CertificateCheck check = checkCertificate(signer, signerRecord, application, trust);
        boolean signatureValid = signer != null && record.verify(signer.getPublicKey());
        List<String> problems = new ArrayList<String>(check.problems);
        if (!signatureValid) {
            problems.add("5F37 signature does not verify");
        }
        return new Verification(label, signatureValid, check, problems);
    }

    public static Integer certificateReference(Lds2Record record) {
        return record.certificateReference();
    }

    private static boolean signature(Lds2Record record, PublicKey key) {
        return record.verify(key);
    }

    private static String subjectValue(X509Certificate certificate, String type) {
        try {
            for (Rdn rdn : new LdapName(
                    certificate.getSubjectX500Principal().getName()).getRdns()) {
                if (type.equalsIgnoreCase(rdn.getType())) {
                    return String.valueOf(rdn.getValue());
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return null;
    }
}
