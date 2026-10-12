package card42.host.emrtd.ta;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import card42.host.common.crypto.Ecdsa;

/**
 * Verifies a CV certificate chain against a CVCA trust anchor and computes the
 * effective authorization (BSI TR-03110-3 A.7.2/C.1, ICAO Doc 9303-10 §5.4.2).
 *
 * <p>The chain is ordered issuer-first: {@code chain[0]} is signed by the trust
 * anchor, {@code chain[i]} by {@code chain[i-1]}, and the last certificate
 * holds the terminal key.  The effective authorization for an application is
 * the bitwise AND of the authorization extensions the chain members carry for
 * that application (missing extensions are not referenced).
 */
public final class CvChainVerifier {

    private CvChainVerifier() {
    }

    /** Verifies the signatures and the CAR/CHR linkage; returns the terminal certificate. */
    public static CvCertificate verify(List<CvCertificate> chain, byte[] trustAnchorPublicPointW) {
        if (chain == null || chain.isEmpty()) {
            throw new IllegalArgumentException("empty CV certificate chain");
        }
        byte[] key = trustAnchorPublicPointW;
        CvCertificate previous = null;
        for (CvCertificate cert : chain) {
            if (!cert.isEc() || !CvCertificate.OID_TA_ECDSA_SHA_256.equals(cert.publicKeyOid())) {
                throw new IllegalArgumentException("unsupported CV certificate public key: "
                        + cert.publicKeyOid());
            }
            if (previous != null && !cert.certificationAuthorityReference()
                    .equals(previous.certificateHolderReference())) {
                throw new IllegalStateException("CV chain is broken: "
                        + cert.certificationAuthorityReference() + " does not match "
                        + previous.certificateHolderReference());
            }
            if (!Ecdsa.verify(cert.body(), key, cert.signature())) {
                throw new IllegalStateException("CV certificate signature verification failed for "
                        + cert.certificateHolderReference());
            }
            key = cert.ecPublicKey();
            previous = cert;
        }
        return previous;
    }

    /** The bitwise-AND effective authorization per application OID. */
    public static Map<String, byte[]> effectiveAuthorization(List<CvCertificate> chain) {
        Map<String, byte[]> out = new LinkedHashMap<String, byte[]>();
        for (CvCertificate cert : chain) {
            for (Map.Entry<String, byte[]> entry : cert.authorizationExtensions().entrySet()) {
                byte[] existing = out.get(entry.getKey());
                out.put(entry.getKey(), existing == null ? entry.getValue()
                        : and(existing, entry.getValue()));
            }
        }
        return out;
    }

    private static byte[] and(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (a[i] & b[i]);
        }
        return out;
    }

    /** True when the given authorization bits grant the requested bit. */
    public static boolean granted(byte[] authorization, int bitIndex) {
        int byteIndex = bitIndex / 8;
        if (authorization == null || authorization.length <= byteIndex) {
            return false;
        }
        return (authorization[byteIndex] & (1 << (bitIndex % 8))) != 0;
    }
}
