package javacard.security;

import java.security.NoSuchAlgorithmException;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code MessageDigest}, backed by
 * JCE (docs/specs/common/toolchain.md §6).  It supports the algorithms the card-side
 * eMRTD code under test uses (SHA-1 for BAC, SHA-1/256 for Active
 * Authentication and Passive Authentication hashes).
 */
public class MessageDigest {

    public static final byte ALG_SHA = (byte) 1;
    public static final byte ALG_SHA_256 = (byte) 4;
    public static final byte ALG_SHA_384 = (byte) 5;
    public static final byte ALG_SHA_512 = (byte) 6;

    private final byte algorithm;
    private java.security.MessageDigest digest;

    private MessageDigest(byte algorithm) {
        this.algorithm = algorithm;
        reset();
    }

    public static MessageDigest getInstance(byte algorithm, boolean externalAccess) {
        if (algorithm != ALG_SHA && algorithm != ALG_SHA_256
                && algorithm != ALG_SHA_384 && algorithm != ALG_SHA_512) {
            throw new CryptoException((short) 1);
        }
        return new MessageDigest(algorithm);
    }

    public static MessageDigest getInstance(byte algorithm) {
        return getInstance(algorithm, false);
    }

    public void reset() {
        try {
            digest = java.security.MessageDigest.getInstance(name(algorithm));
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException((short) 1);
        }
    }

    public void update(byte[] inBuf, short inOff, short inLen) {
        digest.update(inBuf, inOff, inLen);
    }

    public short doFinal(byte[] inBuf, short inOff, short inLen,
                         byte[] outBuf, short outOff) {
        digest.update(inBuf, inOff, inLen);
        byte[] out = digest.digest();
        System.arraycopy(out, 0, outBuf, outOff, out.length);
        reset();
        return (short) out.length;
    }

    public short getLength() {
        return (short) digest.getDigestLength();
    }

    private static String name(byte algorithm) {
        switch (algorithm) {
        case ALG_SHA:
            return "SHA-1";
        case ALG_SHA_256:
            return "SHA-256";
        case ALG_SHA_384:
            return "SHA-384";
        default:
            return "SHA-512";
        }
    }
}
