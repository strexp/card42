package card42.host.common.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Self-contained ECDSA over P-256 for Terminal Authentication (BSI TR-03110-3
 * A.7.4, BSI TR-03111 §5.2): the signature is the TR-03111 <em>plain</em>
 * format {@code r || s} (32 + 32 bytes), which is what is carried in a CV
 * certificate's {@code 5F37} and in the {@code EXTERNAL AUTHENTICATE} data.
 *
 * <p>Like {@link P256}, it needs no external EC provider, so the host eMRTD
 * stack keeps working under the integration suites' module graph (which omits
 * {@code jdk.crypto.ec}).  The hash is SHA-256.
 */
public final class Ecdsa {

    /** Plain-signature length for P-256: r (32) || s (32). */
    public static final int PLAIN_SIGNATURE_LENGTH = 64;

    private Ecdsa() {
    }

    /** Signs a message (SHA-256 internally) and returns the plain {@code r||s}. */
    public static byte[] sign(byte[] message, BigInteger privateScalar, SecureRandom random) {
        return signHash(sha256(message), privateScalar, random);
    }

    /** Signs a precomputed 32-byte SHA-256 hash and returns the plain {@code r||s}. */
    public static byte[] signHash(byte[] hash, BigInteger privateScalar, SecureRandom random) {
        BigInteger z = new BigInteger(1, hash);
        BigInteger n = P256.N;
        while (true) {
            BigInteger k = P256.randomScalar(random);
            P256.Point point = P256.scalarMult(k, P256.generator());
            BigInteger r = point.x.mod(n);
            if (r.signum() == 0) {
                continue;
            }
            BigInteger s = k.modInverse(n)
                    .multiply(z.add(r.multiply(privateScalar))).mod(n);
            if (s.signum() == 0) {
                continue;
            }
            return encode(r, s);
        }
    }

    /** Verifies a plain {@code r||s} signature over a message (SHA-256 internally). */
    public static boolean verify(byte[] message, byte[] publicPointW, byte[] plainSignature) {
        return verifyHash(sha256(message), publicPointW, plainSignature);
    }

    /** Verifies a plain {@code r||s} signature over a precomputed SHA-256 hash. */
    public static boolean verifyHash(byte[] hash, byte[] publicPointW, byte[] plainSignature) {
        if (plainSignature == null || plainSignature.length != PLAIN_SIGNATURE_LENGTH) {
            return false;
        }
        BigInteger n = P256.N;
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(plainSignature, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(plainSignature, 32, 64));
        if (r.signum() == 0 || r.compareTo(n) >= 0 || s.signum() == 0 || s.compareTo(n) >= 0) {
            return false;
        }
        P256.Point publicPoint;
        try {
            publicPoint = P256.decode(publicPointW);
        } catch (RuntimeException e) {
            return false;
        }
        BigInteger z = new BigInteger(1, hash);
        BigInteger w = s.modInverse(n);
        BigInteger u1 = z.multiply(w).mod(n);
        BigInteger u2 = r.multiply(w).mod(n);
        P256.Point result = P256.add(
                P256.scalarMult(u1, P256.generator()), P256.scalarMult(u2, publicPoint));
        return !result.infinity && result.x.mod(n).equals(r);
    }

    private static byte[] sha256(byte[] message) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(message);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static byte[] encode(BigInteger r, BigInteger s) {
        byte[] out = new byte[PLAIN_SIGNATURE_LENGTH];
        copyFixed(r, out, 0);
        copyFixed(s, out, 32);
        return out;
    }

    private static void copyFixed(BigInteger value, byte[] out, int off) {
        byte[] raw = value.toByteArray();
        int start = raw.length > 32 ? raw.length - 32 : 0;
        int len = raw.length - start;
        System.arraycopy(raw, start, out, off + 32 - len, len);
    }
}
