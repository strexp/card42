package card42.host.common.crypto;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * RSA-PSS with SHA-256 for the Terminal Authentication RSA profile
 * ({@code id-TA-RSA-PSS-SHA-256}, BSI TR-03110-3 A.7.4 / ICAO Doc 9303-11
 * §7.1.4.1): MGF1 with SHA-256 and a 32-byte salt, the parameters the Java Card
 * {@code Signature.ALG_RSA_SHA_256_PKCS1_PSS} the card uses expects.
 *
 * <p>Like {@link P256}, it keeps the host eMRTD stack free of an explicit
 * provider choice; RSA is provided by the JDK itself.
 */
public final class RsaPss {

    /** The salt length the Java Card PSS algorithm uses: the hash output length. */
    public static final int SALT_LENGTH = 32;

    private RsaPss() {
    }

    /** Signs a message (SHA-256, PSS) and returns the raw signature. */
    public static byte[] sign(byte[] message, PrivateKey key) {
        try {
            java.security.Signature signer =
                    java.security.Signature.getInstance("RSASSA-PSS");
            signer.setParameter(pss());
            signer.initSign(key);
            signer.update(message);
            return signer.sign();
        } catch (Exception e) {
            throw new IllegalStateException("RSA-PSS signing failed", e);
        }
    }

    /** Verifies a raw RSA-PSS signature over a message. */
    public static boolean verify(byte[] message, PublicKey key, byte[] signature) {
        try {
            java.security.Signature verifier =
                    java.security.Signature.getInstance("RSASSA-PSS");
            verifier.setParameter(pss());
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /** Builds an RSA public key from the raw modulus and exponent. */
    public static PublicKey publicKey(byte[] modulus, byte[] exponent) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                    new BigInteger(1, modulus), new BigInteger(1, exponent)));
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid RSA public key", e);
        }
    }

    /** The minimal two's-complement encoding of a non-negative BigInteger. */
    public static byte[] unsigned(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            return java.util.Arrays.copyOfRange(raw, 1, raw.length);
        }
        return raw;
    }

    private static PSSParameterSpec pss() {
        return new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, SALT_LENGTH, 1);
    }
}
