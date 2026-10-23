package card42.host.emrtd.pa;

import java.io.ByteArrayInputStream;
import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Verifies the Document Signer Certificate against the trusted CSCA store
 * (ICAO Doc 9303-12 §6.1.2/§7.1.1): the certificate must be v3, currently
 * valid, issued by a trusted CSCA, and its signature must verify with that
 * CSCA's public key.
 *
 * <p>Revocation checking (CRL/OCSP) remains outside this class because the
 * project has no CRL store yet; the caller should treat an absent CRL as
 * "revocation not checked" (see docs/specs/common/risks.md).
 */
public final class DscVerifier {

    private DscVerifier() {
    }

    /** Returns the DSC when it is signed by a trusted CSCA, else throws. */
    public static X509Certificate verify(byte[] dscDer, CscaKeyStore trust) throws Exception {
        return verify(dscDer, trust, new Date());
    }

    /** Validity-date variant for deterministic tests and historical validation. */
    public static X509Certificate verify(byte[] dscDer, CscaKeyStore trust, Date at)
            throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate dsc = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(dscDer));
        if (dsc.getVersion() != 3) {
            throw new IllegalStateException("DSC is not an X.509 v3 certificate");
        }
        try {
            dsc.checkValidity(at);
        } catch (CertificateExpiredException e) {
            throw new IllegalStateException("DSC has expired", e);
        } catch (CertificateNotYetValidException e) {
            throw new IllegalStateException("DSC is not yet valid", e);
        }
        for (X509Certificate csca : trust.certificates()) {
            if (!dsc.getIssuerX500Principal().equals(csca.getSubjectX500Principal())) {
                continue;
            }
            try {
                csca.checkValidity(at);
                dsc.verify(csca.getPublicKey());
                trust.checkRevocation(dsc, at);
                return dsc;
            } catch (SignatureException e) {
                // Not this CSCA; try the next one.
            } catch (CertificateExpiredException e) {
                // Expired trust anchor; try the next one.
            } catch (CertificateNotYetValidException e) {
                // Future trust anchor; try the next one.
            }
        }
        throw new IllegalStateException("DSC is not signed by any trusted CSCA");
    }
}
