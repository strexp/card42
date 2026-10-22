package card42.host.emrtd.lds;

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

    public static boolean verify(PublicKey key, byte[] signedInfoTlv, byte[] signature) {
        if (key == null || signedInfoTlv == null || signature == null) {
            return false;
        }
        try {
            String algorithm = "EC".equalsIgnoreCase(key.getAlgorithm())
                    ? "SHA256withECDSA" : "SHA256withRSA";
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(key);
            verifier.update(signedInfoTlv);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
