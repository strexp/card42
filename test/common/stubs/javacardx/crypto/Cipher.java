package javacardx.crypto;

import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code Cipher}, backed by JCE
 * (docs/specs/common/toolchain.md §6).  It supports exactly the algorithms and call
 * shapes the card-side crypto classes under test use, so those classes can be
 * checked against independent JCE vectors on a plain JVM instead of only
 * end-to-end.
 *
 * <p>The Java Card {@code init(Key, mode)} resets the CBC IV to zero, which is
 * what the card classes rely on, so each {@code init} builds a fresh JCE cipher.
 * ECB/CBC with no padding supports in-place operation (same array and offset),
 * matching the Java Card contract.
 */
public class Cipher {

    public static final byte MODE_ENCRYPT = (byte) 1;
    public static final byte MODE_DECRYPT = (byte) 2;

    public static final byte ALG_DES_CBC_NOPAD = (byte) 1;
    public static final byte ALG_DES_ECB_NOPAD = (byte) 2;
    public static final byte ALG_AES_BLOCK_128_CBC_NOPAD = (byte) 3;
    public static final byte ALG_AES_BLOCK_128_ECB_NOPAD = (byte) 4;
    public static final byte ALG_RSA_NOPAD = (byte) 5;

    private final byte algorithm;
    private javax.crypto.Cipher cipher;

    private Cipher(byte algorithm) {
        this.algorithm = algorithm;
    }

    public static Cipher getInstance(byte algorithm, boolean externalAccess) {
        if (algorithm != ALG_DES_CBC_NOPAD && algorithm != ALG_DES_ECB_NOPAD
                && algorithm != ALG_AES_BLOCK_128_CBC_NOPAD
                && algorithm != ALG_AES_BLOCK_128_ECB_NOPAD
                && algorithm != ALG_RSA_NOPAD) {
            throw new CryptoException((short) 1);
        }
        return new Cipher(algorithm);
    }

    public void init(Key key, byte mode) {
        init(key, mode, new byte[16], (short) 0, (short) 16);
    }

    public void init(Key key, byte mode, byte[] iv, short ivOff, short ivLen) {
        try {
            if (algorithm == ALG_RSA_NOPAD) {
                cipher = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding");
                cipher.init(mode == MODE_ENCRYPT
                                ? javax.crypto.Cipher.ENCRYPT_MODE
                                : javax.crypto.Cipher.DECRYPT_MODE,
                        rsaKey(key));
                return;
            }
            boolean aes = algorithm == ALG_AES_BLOCK_128_CBC_NOPAD
                    || algorithm == ALG_AES_BLOCK_128_ECB_NOPAD;
            boolean cbc = algorithm == ALG_DES_CBC_NOPAD
                    || algorithm == ALG_AES_BLOCK_128_CBC_NOPAD;
            byte[] keyBytes = keyBytes(key);
            String algorithmName = aes ? "AES"
                    : (keyBytes.length == 8 ? "DES" : "DESede");
            String transformation = transformation(algorithmName, cbc);
            SecretKeySpec spec = new SecretKeySpec(keyBytes, algorithmName);
            cipher = javax.crypto.Cipher.getInstance(transformation);
            if (cbc) {
                cipher.init(mode == MODE_ENCRYPT
                                ? javax.crypto.Cipher.ENCRYPT_MODE
                                : javax.crypto.Cipher.DECRYPT_MODE,
                        spec, new IvParameterSpec(Arrays.copyOfRange(iv, ivOff,
                                ivOff + ivLen)));
            } else {
                cipher.init(mode == MODE_ENCRYPT
                                ? javax.crypto.Cipher.ENCRYPT_MODE
                                : javax.crypto.Cipher.DECRYPT_MODE,
                        spec);
            }
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException((short) 1);
        }
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    public byte getCipherAlgorithm() {
        return 0;
    }

    public byte getPaddingAlgorithm() {
        return 0;
    }

    public short doFinal(byte[] in, short inOff, short inLen, byte[] out, short outOff) {
        try {
            return (short) cipher.doFinal(in, inOff, inLen, out, outOff);
        } catch (Exception e) {
            throw new CryptoException((short) 1);
        }
    }

    public short update(byte[] in, short inOff, short inLen, byte[] out, short outOff) {
        try {
            return (short) cipher.update(in, inOff, inLen, out, outOff);
        } catch (Exception e) {
            throw new CryptoException((short) 1);
        }
    }

    private static String transformation(String algorithmName, boolean cbc) {
        return algorithmName + (cbc ? "/CBC/NoPadding" : "/ECB/NoPadding");
    }

    /** Rebuilds a JCE RSA key from the stub's stored modulus/exponent bytes. */
    private static java.security.Key rsaKey(Key key) throws Exception {
        if (key instanceof RSAPrivateKey) {
            RSAPrivateKey rsa = (RSAPrivateKey) key;
            return java.security.KeyFactory.getInstance("RSA").generatePrivate(
                    new java.security.spec.RSAPrivateKeySpec(
                            new java.math.BigInteger(1, rsa.modulusBytes()),
                            new java.math.BigInteger(1, rsa.exponentBytes())));
        }
        RSAPublicKey rsa = (RSAPublicKey) key;
        return java.security.KeyFactory.getInstance("RSA").generatePublic(
                new java.security.spec.RSAPublicKeySpec(
                        new java.math.BigInteger(1, rsa.modulusBytes()),
                        new java.math.BigInteger(1, rsa.exponentBytes())));
    }

    /**
     * The raw key bytes as a JCE key.  A single DES key (8 bytes) is padded to
     * the 24-byte 3DES form K1||K2||K1 that SunJCE requires; a 16-byte two-key
     * 3DES key is expanded the same way (EMV uses two-key 3DES).
     */
    private static byte[] keyBytes(Key key) {
        short size = key.getSize();
        byte[] raw = new byte[(short) (size / 8)];
        if (key instanceof DESKey) {
            ((DESKey) key).getKey(raw, (short) 0);
        } else if (key instanceof AESKey) {
            ((AESKey) key).getKey(raw, (short) 0);
        } else {
            throw new CryptoException((short) 1);
        }
        if (key instanceof AESKey) {
            return raw;
        }
        if (raw.length == 8) {
            return raw;
        }
        if (raw.length == 16) {
            byte[] expanded = new byte[24];
            System.arraycopy(raw, 0, expanded, 0, 16);
            System.arraycopy(raw, 0, expanded, 16, 8);
            return expanded;
        }
        return raw;
    }
}
