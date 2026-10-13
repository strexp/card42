package javacard.security;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code Signature}, backed by JCE
 * (docs/specs/common/toolchain.md §6).  It supports the RSA PKCS#1 v1.5 algorithms the
 * card-side eMRTD Active Authentication uses (SHA-1 and SHA-256), the single
 * DES MAC algorithms the card {@code RetailMac} prefers
 * ({@code ALG_DES_MAC8_ISO9797_M2} and {@code ALG_DES_MAC8_NOPAD}) and the
 * P-256 ECDSA plain-format verification the card-side Terminal Authentication
 * uses.  Setting the system property {@code card42.desmac.software} makes the
 * DES MAC algorithms report {@code NO_SUCH_ALGORITHM} so the unit tests can also
 * drive the manual fallback path with the same card source.
 */
public class Signature {

    public static final byte MODE_SIGN = (byte) 1;
    public static final byte MODE_VERIFY = (byte) 2;

    public static final byte ALG_RSA_SHA_PKCS1 = (byte) 1;
    public static final byte ALG_RSA_SHA_256_PKCS1 = (byte) 4;
    public static final byte ALG_DES_MAC8_NOPAD = (byte) 10;
    public static final byte ALG_DES_MAC8_ISO9797_M2 = (byte) 11;
    public static final byte ALG_ECDSA_SHA_256 = (byte) 33;
    /** Card-side RSA-PSS with SHA-256 (Terminal Authentication RSA profile). */
    public static final byte ALG_RSA_SHA_256_PKCS1_PSS = (byte) 21;

    /** Cipher selector for the plain (r||s) ECDSA signature format. */
    public static final byte SIG_CIPHER_ECDSA_PLAIN = (byte) 9;

    /** Forces the DES MAC algorithms to be reported as unavailable. */
    public static final String SOFTWARE_DES_MAC_PROPERTY = "card42.desmac.software";

    private final byte algorithm;
    private java.security.Signature signature;
    private Key key;
    private byte mode;

    private byte[] desKey;
    private ByteArrayOutputStream desData;
    private boolean desM2;

    private boolean ecdsaPlain;

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
        if (algorithm != ALG_RSA_SHA_PKCS1 && algorithm != ALG_RSA_SHA_256_PKCS1
                && algorithm != ALG_RSA_SHA_256_PKCS1_PSS) {
            throw new CryptoException((short) 1);
        }
        return new Signature(algorithm);
    }

    public static Signature getInstance(byte algorithm) {
        return getInstance(algorithm, false);
    }

    /**
     * The three-parameter factory used by Terminal Authentication with the
     * plain-format ECDSA cipher (Java Card {@code Signature.SIG_CIPHER_ECDSA_PLAIN}).
     */
    public static Signature getInstance(byte messageDigestAlgorithm, byte cipherAlgorithm,
                                        byte paddingAlgorithm, boolean externalAccess) {
        if (cipherAlgorithm == SIG_CIPHER_ECDSA_PLAIN
                && messageDigestAlgorithm == MessageDigest.ALG_SHA_256
                && paddingAlgorithm == 0) {
            Signature s = new Signature(ALG_ECDSA_SHA_256);
            s.ecdsaPlain = true;
            return s;
        }
        throw new CryptoException((short) 1);
    }

    public void init(Key theKey, byte theMode) {
        this.key = theKey;
        this.mode = theMode;
        if (ecdsaPlain) {
            return;
        }
        if (algorithm == ALG_DES_MAC8_ISO9797_M2 || algorithm == ALG_DES_MAC8_NOPAD) {
            desKey = new byte[8];
            ((DESKey) theKey).getKey(desKey, (short) 0);
            desData = new ByteArrayOutputStream();
            desM2 = algorithm == ALG_DES_MAC8_ISO9797_M2;
            return;
        }
        try {
            if (theMode == MODE_VERIFY) {
                // verify() builds its own verifier from the public key.
                return;
            }
            signature = algorithm == ALG_RSA_SHA_256_PKCS1_PSS
                    ? pssSigner() : java.security.Signature.getInstance(name(algorithm));
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
        if (ecdsaPlain) {
            return signEcdsaPlain(inBuff, inOffset, inLength, sigBuff, sigOffset);
        }
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
        if (ecdsaPlain) {
            return verifyEcdsaPlain(inBuff, inOffset, inLength, sigBuff, sigOffset, sigLength);
        }
        try {
            java.security.Signature verifier = algorithm == ALG_RSA_SHA_256_PKCS1_PSS
                    ? pssSigner() : java.security.Signature.getInstance(name(algorithm));
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

    /** P-256 ECDSA plain (r||s) verification, delegating to the JDK's SunEC. */
    private boolean verifyEcdsaPlain(byte[] inBuff, short inOffset, short inLength,
                                     byte[] sigBuff, short sigOffset, short sigLength) {
        try {
            byte[] w = ((ECPublicKey) key).wBytes();
            java.security.Signature verifier =
                    java.security.Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(jceEcPublic(w));
            if (inLength > 0) {
                verifier.update(inBuff, inOffset, inLength);
            }
            byte[] plain = new byte[sigLength];
            System.arraycopy(sigBuff, sigOffset, plain, 0, sigLength);
            return verifier.verify(plainToDer(plain));
        } catch (Exception e) {
            return false;
        }
    }

    /** P-256 ECDSA plain (r||s) signing, delegating to the JDK's SunEC. */
    private short signEcdsaPlain(byte[] inBuff, short inOffset, short inLength,
                                 byte[] sigBuff, short sigOffset) {
        try {
            java.security.Signature signer =
                    java.security.Signature.getInstance("SHA256withECDSA");
            signer.initSign(jceEcPrivate((ECPrivateKey) key));
            if (inLength > 0) {
                signer.update(inBuff, inOffset, inLength);
            }
            byte[] plain = derToPlain(signer.sign());
            System.arraycopy(plain, 0, sigBuff, sigOffset, plain.length);
            return (short) plain.length;
        } catch (Exception e) {
            throw new CryptoException((short) 1);
        }
    }

    public short getLength() {
        if (algorithm == ALG_DES_MAC8_ISO9797_M2 || algorithm == ALG_DES_MAC8_NOPAD) {
            return 8;
        }
        if (ecdsaPlain) {
            return 64;
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

    private static java.security.PublicKey jceEcPublic(byte[] w) throws Exception {
        java.security.AlgorithmParameters params =
                java.security.AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        java.security.spec.ECParameterSpec spec =
                params.getParameterSpec(java.security.spec.ECParameterSpec.class);
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(w, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(w, 33, 65));
        return KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
    }

    private static java.security.PrivateKey jceEcPrivate(ECPrivateKey key) throws Exception {
        java.security.AlgorithmParameters params =
                java.security.AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        java.security.spec.ECParameterSpec spec =
                params.getParameterSpec(java.security.spec.ECParameterSpec.class);
        return KeyFactory.getInstance("EC").generatePrivate(
                new java.security.spec.ECPrivateKeySpec(
                        new BigInteger(1, key.scalarBytes()), spec));
    }

    /** X9.62 DER ECDSA signature to the TR-03111 plain (r||s) 64-byte form. */
    private static byte[] derToPlain(byte[] der) {
        if (der.length < 8 || (der[0] & 0xFF) != 0x30) {
            throw new CryptoException((short) 1);
        }
        int p = 1;
        int len = der[p++] & 0xFF;
        if ((len & 0x80) != 0) {
            int n = len & 0x7F;
            len = 0;
            for (int i = 0; i < n; i++) {
                len = (len << 8) | (der[p++] & 0xFF);
            }
        }
        if (p + len > der.length || (der[p] & 0xFF) != 0x02) {
            throw new CryptoException((short) 1);
        }
        p++;
        int rLen = der[p++] & 0xFF;
        int rOff = p;
        p += rLen;
        if ((der[p] & 0xFF) != 0x02) {
            throw new CryptoException((short) 1);
        }
        p++;
        int sLen = der[p++] & 0xFF;
        int sOff = p;
        byte[] out = new byte[64];
        copyInt(der, rOff, rLen, out, 0);
        copyInt(der, sOff, sLen, out, 32);
        return out;
    }

    private static void copyInt(byte[] src, int off, int len, byte[] out, int outOff) {
        while (len > 1 && src[off] == 0) {
            off++;
            len--;
        }
        if (len > 32) {
            throw new CryptoException((short) 1);
        }
        System.arraycopy(src, off, out, outOff + 32 - len, len);
    }

    /** TR-03111 plain (r||s) to X9.62 DER, for the JDK verifier. */
    private static byte[] plainToDer(byte[] plain) {
        if (plain.length != 64) {
            throw new CryptoException((short) 1);
        }
        byte[] r = derInteger(plain, 0);
        byte[] s = derInteger(plain, 32);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        writeLength(out, r.length + s.length);
        out.write(r, 0, r.length);
        out.write(s, 0, s.length);
        return out.toByteArray();
    }

    private static byte[] derInteger(byte[] value, int off) {
        int start = off;
        int len = 32;
        while (len > 1 && value[start] == 0) {
            start++;
            len--;
        }
        byte[] v = Arrays.copyOfRange(value, start, start + len);
        if ((v[0] & 0x80) != 0) {
            byte[] padded = new byte[v.length + 1];
            System.arraycopy(v, 0, padded, 1, v.length);
            v = padded;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x02);
        writeLength(out, v.length);
        out.write(v, 0, v.length);
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int len) {
        if (len < 0x80) {
            out.write(len);
        } else {
            out.write(0x81);
            out.write(len);
        }
    }

    private static String name(byte algorithm) {
        return algorithm == ALG_RSA_SHA_PKCS1 ? "SHA1withRSA" : "SHA256withRSA";
    }

    /** A JDK RSA-PSS signer/verifier with SHA-256 and a 32-byte salt (Java Card default). */
    private static java.security.Signature pssSigner() throws Exception {
        java.security.Signature s = java.security.Signature.getInstance("RSASSA-PSS");
        s.setParameter(new java.security.spec.PSSParameterSpec("SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256, 32, 1));
        return s;
    }
}
