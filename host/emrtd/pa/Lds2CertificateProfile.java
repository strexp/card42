package card42.host.emrtd.pa;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.List;
import java.util.Set;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import card42.host.common.codec.Der;
import card42.host.common.util.Hex;
import card42.host.emrtd.lds.lds2.CertificateRecord;

/** LDS2 signer certificate profile and CSCA trust checks (Doc 9303-12 §7.1.2). */
final class Lds2CertificateProfile {

    private static final String OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
    private static final String OID_EXTENDED_KEY_USAGE = "2.5.29.37";
    private static final int MAX_CERTIFICATE_BYTES = 900;
    private static final int MAX_SUBJECT_COMMON_NAME = 9;

    private Lds2CertificateProfile() {
    }

    static Lds2Verifier.CertificateCheck check(X509Certificate certificate,
            CertificateRecord record, String application, CscaKeyStore trust, Date at) {

        List<String> problems = new ArrayList<String>();
        if (certificate == null) {
            problems.add("no LDS2 signer certificate");
            return new Lds2Verifier.CertificateCheck(null, record, null, null, false, false, problems);
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
        String expected = Lds2Verifier.expectedEku(application);
        if (eku == null || eku.isEmpty()) {
            problems.add("ExtendedKeyUsage is empty");
        } else if (expected != null && !eku.contains(expected)) {
            problems.add("ExtendedKeyUsage does not contain " + expected + " for " + application);
        } else if (expected == null
                && !eku.contains(Lds2Verifier.EKU_TRAVEL)
                && !eku.contains(Lds2Verifier.EKU_VISA)
                && !eku.contains(Lds2Verifier.EKU_BIOMETRICS)) {
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
        return new Lds2Verifier.CertificateCheck(certificate, record, subject, country,
                profileValid, trusted, problems);
    
    }

    static String subjectValue(X509Certificate certificate, String type) {
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
