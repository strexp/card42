package card42.host.emrtd.pa;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Files;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * The trusted CSCA key store (ICAO Doc 9303-12, §6.1): X.509 CSCA certificates
 * plus optional CRLs.  Loads PEM/DER certificates and CRLs from files or a
 * directory; the reference implementation trusts exactly what it is given.
 *
 * <p>CRL checking is opt-in: when no CRL for a certificate's issuer is present
 * the caller can still verify its signature, but revocation has not been
 * checked.  This is deliberate because the demo PKI has no publication point;
 * production deployments should supply the CSCA CRLs.
 */
public final class CscaKeyStore {

    private final List<X509Certificate> certificates;
    private final List<X509CRL> crls;

    public CscaKeyStore(List<X509Certificate> certificates) {
        this(certificates, new ArrayList<X509CRL>());
    }

    public CscaKeyStore(List<X509Certificate> certificates, List<X509CRL> crls) {
        this.certificates = certificates;
        this.crls = crls;
    }

    public List<X509Certificate> certificates() {
        return certificates;
    }

    public List<X509CRL> crls() {
        return crls;
    }

    /** Loads every certificate from a PEM or DER blob (no CRLs). */
    public static CscaKeyStore fromPem(byte[] pem) throws Exception {
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> parsed =
                factory.generateCertificates(new ByteArrayInputStream(pem));
        for (Certificate c : parsed) {
            if (c instanceof X509Certificate) {
                certs.add((X509Certificate) c);
            }
        }
        return new CscaKeyStore(certs);
    }

    /** Loads every certificate and CRL from the given PEM/DER files. */
    public static CscaKeyStore fromFiles(File... files) throws Exception {
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        List<X509CRL> crls = new ArrayList<X509CRL>();
        for (File file : files) {
            load(file, certs, crls);
        }
        return new CscaKeyStore(certs, crls);
    }

    /**
     * Loads every certificate/CRL from a file, or every file in a directory
     * (sorted by name).  The CLI's {@code -csca=<path>} accepts either form.
     */
    public static CscaKeyStore fromPath(File path) throws Exception {
        if (!path.isDirectory()) {
            return fromFiles(path);
        }
        File[] files = path.listFiles();
        if (files == null) {
            throw new IllegalArgumentException("cannot list CSCA directory " + path);
        }
        java.util.Arrays.sort(files);
        List<File> usable = new ArrayList<File>();
        for (File file : files) {
            if (!file.isFile()) {
                continue;
            }
            String name = file.getName().toLowerCase(java.util.Locale.ROOT);
            if (name.endsWith(".crt") || name.endsWith(".cer")
                    || name.endsWith(".pem") || name.endsWith(".der")
                    || name.endsWith(".crl")) {
                usable.add(file);
            }
        }
        return fromFiles(usable.toArray(new File[0]));
    }

    private static void load(File file, List<X509Certificate> certs, List<X509CRL> crls)
            throws Exception {
        byte[] bytes = Files.readAllBytes(file.toPath());
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try {
            Collection<? extends Certificate> parsed =
                    factory.generateCertificates(new ByteArrayInputStream(bytes));
            boolean found = false;
            for (Certificate c : parsed) {
                if (c instanceof X509Certificate) {
                    certs.add((X509Certificate) c);
                    found = true;
                }
            }
            if (found) {
                return;
            }
        } catch (java.security.cert.CertificateException e) {
            // Not a certificate bundle; try CRLs below.
        }
        Collection<? extends CRL> parsed = factory.generateCRLs(
                new ByteArrayInputStream(bytes));
        for (CRL crl : parsed) {
            if (crl instanceof X509CRL) {
                crls.add((X509CRL) crl);
            }
        }
    }

    /**
     * Checks every matching CRL for a revoked certificate.  No matching CRL
     * means "revocation not checked", not "valid"; callers that require CRL
     * coverage should reject a store with no CRL for the issuer.
     */
    public void checkRevocation(X509Certificate certificate, Date at) throws Exception {
        for (X509CRL crl : crls) {
            if (!crl.getIssuerX500Principal().equals(certificate.getIssuerX500Principal())) {
                continue;
            }
            X509Certificate issuer = issuer(crl.getIssuerX500Principal());
            if (issuer == null) {
                throw new IllegalStateException("no CSCA for CRL issuer "
                        + crl.getIssuerX500Principal());
            }
            crl.verify(issuer.getPublicKey());
            issuer.checkValidity(at);
            if (crl.getThisUpdate() != null && crl.getThisUpdate().after(at)) {
                throw new IllegalStateException("CRL is not yet valid");
            }
            if (crl.getNextUpdate() != null && crl.getNextUpdate().before(at)) {
                throw new IllegalStateException("CRL has expired");
            }
            if (crl.isRevoked(certificate)) {
                throw new IllegalStateException("certificate is revoked");
            }
        }
        // No CRL for this issuer: revocation is simply not checked.
    }

    private X509Certificate issuer(javax.security.auth.x500.X500Principal name) {
        for (X509Certificate certificate : certificates) {
            if (certificate.getSubjectX500Principal().equals(name)) {
                return certificate;
            }
        }
        return null;
    }
}
