package card42.host.emrtd.lds.lds2;

import java.security.PublicKey;
import java.security.Signature;

/**
 * Verifies an LDS2 record authenticity token ({@code 5F37}) against an
 * EF.Certificates X.509 public key.  The signature covers the complete signed
 * information DO ({@code 73} for Travel, {@code 71} for Visa), including its
 * tag and length (ICAO Doc 9303-10 Table 86/90).
 */
public final class Lds2Signature {

    private Lds2Signature() {
    }

    /**
     * The LDS2 record does not carry a signature AlgorithmIdentifier, so the
     * verifier tries the Doc 9303-12 signature algorithms compatible with the
     * signer key.  SHA-256 is preferred; SHA-384/512 and RSA SHA-1 are fallbacks
     * for cards written by other implementations.
     */
    private static final String[] EC_ALGORITHMS = {
            "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "SHA1withECDSA" };
    private static final String[] RSA_ALGORITHMS = {
            "SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA1withRSA" };

    public static boolean verify(PublicKey key, byte[] signedInfoTlv, byte[] signature) {
        if (key == null || signedInfoTlv == null || signature == null) {
            return false;
        }
        String[] candidates = "EC".equalsIgnoreCase(key.getAlgorithm())
                ? EC_ALGORITHMS : RSA_ALGORITHMS;
        for (String algorithm : candidates) {
            try {
                Signature verifier = Signature.getInstance(algorithm);
                verifier.initVerify(key);
                verifier.update(signedInfoTlv);
                if (verifier.verify(signature)) {
                    return true;
                }
            } catch (Exception e) {
                // Try the next compatible algorithm.
            }
        }
        return false;
    }
}
