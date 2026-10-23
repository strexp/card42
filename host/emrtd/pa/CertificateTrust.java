package card42.host.emrtd.pa;

import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * The CSCA trust-loop shared by {@link DscVerifier} and
 * {@link Lds2Verifier}: a certificate is trusted when a trusted CSCA has the
 * same subject as its issuer, is valid at {@code at}, verifies the signature,
 * and the store's revocation policy accepts it.
 *
 * <p>Revocation checking (CRL/OCSP) remains delegated to
 * {@link CscaKeyStore#checkRevocation}; an absent CRL means "revocation not
 * checked" (see docs/specs/common/risks.md).
 */
final class CertificateTrust {

    private CertificateTrust() {
    }

    /** Returns the matching CSCA, or throws when the certificate is not trusted. */
    static X509Certificate verify(X509Certificate certificate, CscaKeyStore trust, Date at)
            throws Exception {
        if (trust == null) {
            throw new IllegalStateException("no CSCA trust store");
        }
        String lastError = null;
        for (X509Certificate csca : trust.certificates()) {
            if (!certificate.getIssuerX500Principal().equals(
                    csca.getSubjectX500Principal())) {
                continue;
            }
            try {
                csca.checkValidity(at);
                certificate.verify(csca.getPublicKey());
                trust.checkRevocation(certificate, at);
                return csca;
            } catch (SignatureException e) {
                lastError = e.getMessage();
            } catch (CertificateExpiredException e) {
                lastError = "trust anchor has expired";
            } catch (CertificateNotYetValidException e) {
                lastError = "trust anchor is not yet valid";
            } catch (Exception e) {
                lastError = e.getMessage();
            }
        }
        throw new IllegalStateException("certificate is not signed by any trusted CSCA"
                + (lastError == null ? "" : ": " + lastError));
    }
}
