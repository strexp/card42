package card42.host.emrtd.pa;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Files;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * The trusted CSCA key store (ICAO Doc 9303-12, H3.4).  Loads X.509 CSCA
 * certificates from PEM/DER files or a PEM blob; the reference implementation
 * trusts exactly the certificates it is given.
 */
public final class CscaKeyStore {

    private final List<X509Certificate> certificates;

    public CscaKeyStore(List<X509Certificate> certificates) {
        this.certificates = certificates;
    }

    public List<X509Certificate> certificates() {
        return certificates;
    }

    /** Loads every certificate in a PEM or DER blob. */
    public static CscaKeyStore fromPem(byte[] pem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certs =
                factory.generateCertificates(new ByteArrayInputStream(pem));
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        for (Certificate c : certs) {
            out.add((X509Certificate) c);
        }
        return new CscaKeyStore(out);
    }

    /** Loads every certificate from the given PEM/DER files. */
    public static CscaKeyStore fromFiles(File... files) throws Exception {
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        for (File file : files) {
            out.addAll(fromPem(Files.readAllBytes(file.toPath())).certificates());
        }
        return new CscaKeyStore(out);
    }
}
