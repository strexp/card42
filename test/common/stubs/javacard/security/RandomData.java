package javacard.security;

import java.security.SecureRandom;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code RandomData}, backed by
 * {@link SecureRandom} (docs/specs/common/toolchain.md §6).  The card-side eMRTD
 * {@code GET CHALLENGE} path uses it.
 */
public class RandomData {

    public static final byte ALG_SECURE_RANDOM = (byte) 1;

    private final SecureRandom random = new SecureRandom();
    private byte[] seed;

    private RandomData() {
    }

    public static RandomData getInstance(byte algorithm) {
        if (algorithm != ALG_SECURE_RANDOM) {
            throw new CryptoException((short) 1);
        }
        return new RandomData();
    }

    public void generateData(byte[] buffer, short offset, short length) {
        byte[] out = new byte[length];
        random.nextBytes(out);
        System.arraycopy(out, 0, buffer, offset, length);
    }

    public void setSeed(byte[] buffer, short offset, short length) {
        seed = new byte[length];
        System.arraycopy(buffer, offset, seed, 0, length);
        random.setSeed(seed);
    }
}
