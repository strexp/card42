package card42.host.emrtd.pa;

import java.io.ByteArrayInputStream;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Verifies the Document Signer Certificate against the trusted CSCA store
 * (ICAO Doc 9303-12, H3.5).  It checks the DSC's issuer signature; a production
 * implementation would also check the certificate policy, validity dates and
 * revocation.
 */
public final class DscVerifier {

    private DscVerifier() {
    }

    /** Returns the DSC when it is signed by a trusted CSCA, else throws. */
    public static X509Certificate verify(byte[] dscDer, CscaKeyStore trust) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate dsc = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(dscDer));
        for (X509Certificate csca : trust.certificates()) {
            try {
                dsc.verify(csca.getPublicKey());
                return dsc;
            } catch (SignatureException e) {
                // Not this CSCA; try the next one.
            }
        }
        throw new IllegalStateException("DSC is not signed by any trusted CSCA");
    }
}
