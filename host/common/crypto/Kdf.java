package card42.host.common.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * SHA-1 counter-mode key derivation shared by BAC, PACE and Chip
 * Authentication (ICAO Doc 9303-11 §9.7.2, BSI TR-03110-3 A.2.3.1):
 *
 * <pre>
 *   KDF(x, counter) = SHA-1(x || 00 00 00 counter)[0..16)
 * </pre>
 *
 * <p>The 3DES profiles set odd DES parity on the result; the AES profile does
 * not.  Keeping the primitive here removes three independently written copies
 * while leaving the per-protocol key usage in the callers.
 */
public final class Kdf {

    private Kdf() {
    }

    /** Derives a 16-byte key from {@code x} with the given counter. */
    public static byte[] sha1Counter(byte[] x, int counter, boolean desParity) {
        return sha1Counter(x, 0, x.length, counter, desParity);
    }

    /** Derives a 16-byte key from {@code x[off..off+len)} with the given counter. */
    public static byte[] sha1Counter(byte[] x, int off, int len, int counter,
                                     boolean desParity) {
        byte[] input = new byte[len + 4];
        System.arraycopy(x, off, input, 0, len);
        input[input.length - 1] = (byte) counter;
        byte[] key = Arrays.copyOf(sha1(input), 16);
        if (desParity) {
            adjustParity(key);
        }
        return key;
    }

    /** Sets odd parity on each byte, as required for a 3DES key. */
    public static void adjustParity(byte[] key) {
        for (int i = 0; i < key.length; i++) {
            if ((Integer.bitCount(key[i] & 0xFF) & 1) == 0) {
                key[i] ^= 0x01;
            }
        }
    }

    private static byte[] sha1(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-1").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 is not available", e);
        }
    }
}
