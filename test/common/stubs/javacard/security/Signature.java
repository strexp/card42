package javacard.security;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code Signature}, backed by JCE
 * (docs/specs/common/toolchain.md §6).  It supports the RSA PKCS#1 v1.5 algorithms the
 * card-side eMRTD Active Authentication uses (SHA-1 and SHA-256) and the single
 * DES MAC algorithms the card {@code RetailMac} prefers
 * ({@code ALG_DES_MAC8_ISO9797_M2} and {@code ALG_DES_MAC8_NOPAD}).  Setting the
 * system property {@code card42.desmac.software} makes the DES MAC algorithms
 * report {@code NO_SUCH_ALGORITHM} so the unit tests can also drive the manual
 * fallback path with the same card source.
 */
public class Signature {

    public static final byte MODE_SIGN = (byte) 1;
    public static final byte MODE_VERIFY = (byte) 2;

    public static final byte ALG_RSA_SHA_PKCS1 = (byte) 1;
    public static final byte ALG_RSA_SHA_256_PKCS1 = (byte) 4;
    public static final byte ALG_DES_MAC8_NOPAD = (byte) 10;
    public static final byte ALG_DES_MAC8_ISO9797_M2 = (byte) 11;

    /** Forces the DES MAC algorithms to be reported as unavailable. */
    public static final String SOFTWARE_DES_MAC_PROPERTY = "card42.desmac.software";

    private final byte algorithm;
    private java.security.Signature signature;
    private Key key;
    private byte mode;

    private byte[] desKey;
    private ByteArrayOutputStream desData;
    private boolean desM2;

    private Signature(byte algorithm) {
        this.algorithm = algorithm;
    }

    public static Signature getInstance(byte algorithm, boolean externalAccess) {
        if (algorithm == ALG_DES_MAC8_ISO9797_M2 || algorithm == ALG_DES_MAC8_NOPAD) {
            if (System.getProperty(SOFTWARE_DES_MAC_PROPERTY) != null) {
                throw new CryptoException((short) 1); // NO_SUCH_ALGORITHM
            }
            return new Signature(algorithm);
        }
        if (algorithm != ALG_RSA_SHA_PKCS1 && algorithm != ALG_RSA_SHA_256_PKCS1) {
            throw new CryptoException((short) 1);
        }
        return new Signature(algorithm);
    }

    public static Signature getInstance(byte algorithm) {
        return getInstance(algorithm, false);
    }

    public void init(Key theKey, byte theMode) {
        this.key = theKey;
        this.mode = theMode;
        if (algorithm == ALG_DES_MAC8_ISO9797_M2 || algorithm == ALG_DES_MAC8_NOPAD) {
            desKey = new byte[8];
            ((DESKey) theKey).getKey(desKey, (short) 0);
            desData = new ByteArrayOutputStream();
            desM2 = algorithm == ALG_DES_MAC8_ISO9797_M2;
            return;
        }
        try {
            signature = java.security.Signature.getInstance(name(algorithm));
            signature.initSign(jcePrivate(theKey));
        } catch (Exception e) {
            throw new CryptoException((short) 1);
        }
    }

    public void update(byte[] inBuff, short inOffset, short inLength) {
        if (desData != null) {
            desData.write(inBuff, inOffset, inLength);
            return;
        }
        try {
            signature.update(inBuff, inOffset, inLength);
        } catch (Exception e) {
            throw new CryptoException((short) 1);
        }
    }

    public short sign(byte[] inBuff, short inOffset, short inLength,
                      byte[] sigBuff, short sigOffset) {
        if (desData != null) {
            if (inLength > 0) {
                desData.write(inBuff, inOffset, inLength);
            }
            byte[] mac = desMac();
            System.arraycopy(mac, 0, sigBuff, sigOffset, mac.length);
            desData = null;
            desKey = null;
            return (short) mac.length;
        }
        try {
            if (inLength > 0) {
                signature.update(inBuff, inOffset, inLength);
            }
            byte[] sig = signature.sign();
            System.arraycopy(sig, 0, sigBuff, sigOffset, sig.length);
            return (short) sig.length;
        } catch (Exception e) {
            throw new CryptoException((short) 1);
        }
    }

    /** Single-DES CBC-MAC, with method-2 padding unless the input is aligned. */
    private byte[] desMac() {
        byte[] msg = desData.toByteArray();
        byte[] padded;
        if (desM2) {
            int pad = 8 - (msg.length % 8);
            padded = new byte[msg.length + pad];
            System.arraycopy(msg, 0, padded, 0, msg.length);
            padded[msg.length] = (byte) 0x80;
        } else {
            if ((msg.length & 7) != 0) {
                throw new CryptoException((short) 1);
            }
            padded = msg.length == 0 ? new byte[8] : msg;
        }
        try {
            javax.crypto.Cipher des = javax.crypto.Cipher.getInstance("DES/CBC/NoPadding");
            des.init(javax.crypto.Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(desKey, "DES"), new IvParameterSpec(new byte[8]));
            byte[] ciphertext = des.doFinal(padded);
            byte[] mac = new byte[8];
            System.arraycopy(ciphertext, ciphertext.length - 8, mac, 0, 8);
            return mac;
        } catch (Exception e) {
            throw new CryptoException((short) 1);
        }
    }

    public boolean verify(byte[] inBuff, short inOffset, short inLength,
                          byte[] sigBuff, short sigOffset, short sigLength) {
        try {
            java.security.Signature verifier =
                    java.security.Signature.getInstance(name(algorithm));
            verifier.initVerify(jcePublic(key));
            if (inLength > 0) {
                verifier.update(inBuff, inOffset, inLength);
            }
            byte[] sig = new byte[sigLength];
            System.arraycopy(sigBuff, sigOffset, sig, 0, sigLength);
            return verifier.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    public short getLength() {
        if (algorithm == ALG_DES_MAC8_ISO9797_M2 || algorithm == ALG_DES_MAC8_NOPAD) {
            return 8;
        }
        return (short) (((key != null ? key.getSize() : (short) 0) + 7) / 8);
    }

    public void setInitialDigest(byte[] initialDigestBuf, short initialDigestOffset,
                                 short initialDigestLength, byte[] digestedMsgLenBuf,
                                 short digestedMsgLenOffset, short digestedMsgLenLength) {
        update(initialDigestBuf, initialDigestOffset, initialDigestLength);
    }

    private static java.security.PrivateKey jcePrivate(Key key) throws Exception {
        RSAPrivateKey rsa = (RSAPrivateKey) key;
        RSAPrivateKeySpec spec = new RSAPrivateKeySpec(
                new BigInteger(1, rsa.modulusBytes()),
                new BigInteger(1, rsa.exponentBytes()));
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private static java.security.PublicKey jcePublic(Key key) throws Exception {
        RSAPublicKey rsa = (RSAPublicKey) key;
        RSAPublicKeySpec spec = new RSAPublicKeySpec(
                new BigInteger(1, rsa.modulusBytes()),
                new BigInteger(1, rsa.exponentBytes()));
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static String name(byte algorithm) {
        return algorithm == ALG_RSA_SHA_PKCS1 ? "SHA1withRSA" : "SHA256withRSA";
    }
}
