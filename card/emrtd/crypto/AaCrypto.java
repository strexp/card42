package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/* Active Authentication signing (ICAO Doc 9303-11 §6.1.2.2).
 *
 * The document holds an AA private key whose public part is stored in DG15.
 * INTERNAL AUTHENTICATE sends an 8-byte RND.IFD; the card generates RND.IC and
 * signs M = RND.IC || RND.IFD with the ISO/IEC 9796-2 Digital Signature Scheme 1
 * (message recovery, partial message M2).  The response is the signature sigma
 * only; the verifier recovers RND.IC from sigma.
 *
 * The recoverable part M1 = RND.IC is one byte shorter than the space left
 * after the leading 0x6A separator, the hash H(M) and the trailer field
 * (Doc 9303-11 §6.1.2.2): c = k - Lh - 8t - 4 bits, M1 = c - 4 bits.  SHA-1
 * uses trailer field option 1 (t=1, 0xBC); SHA-256 option 2 (t=2, 0x34CC).
 *
 * @author card42
 */

public final class AaCrypto {

    /** 0x01 = RSA ISO/IEC 9796-2 Scheme 1 with SHA-1; 0x02 = with SHA-256. */
    public static final byte AA_SHA1 = (byte) 0x01;
    public static final byte AA_SHA256 = (byte) 0x02;

    private final byte algorithm;
    private final RSAPrivateKey privateKey;
    private final Cipher rsa;
    private final MessageDigest digest;
    private final RandomData random;
    private final short keyBytes;
    private final short digestLength;
    private final short trailerLength;
    /** M1 = RND.IC, the recoverable message part. */
    private final byte[] nonce;
    /** The ISO/IEC 9796-2 encoded message to be raised to the private exponent. */
    private final byte[] block;
    /** H(M), reused across calls. */
    private final byte[] hash;

    public AaCrypto(short keyBits, byte algorithm) {
        this.algorithm = algorithm;
        keyBytes = (short) (keyBits / 8);
        privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
                keyBits, false);
        // Raw RSA (modular exponentiation) so the card controls the ISO/IEC
        // 9796-2 encoding itself; the platform only performs the RSA primitive.
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        if (algorithm == AA_SHA256) {
            digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            digestLength = (short) 32;
            trailerLength = (short) 2;
        } else {
            digest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
            digestLength = (short) 20;
            trailerLength = (short) 1;
        }
        short nonceLength = (short) (keyBytes - digestLength);
        nonceLength = (short) (nonceLength - trailerLength);
        nonceLength = (short) (nonceLength - 1);
        nonce = new byte[nonceLength];
        block = new byte[keyBytes];
        hash = new byte[digestLength];
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    /** Sets the AA private key (modulus || exponent) from personalization data. */
    public void setPrivateKey(byte[] modulus, short modOff, short modLen,
                              byte[] exponent, short expOff, short expLen) {
        privateKey.setModulus(modulus, modOff, modLen);
        privateKey.setExponent(exponent, expOff, expLen);
    }

    public boolean isInitialized() {
        return privateKey.isInitialized();
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    /**
     * Signs the 8-byte RND.IFD.  RND.IC is generated here; returns the
     * signature length written to out.
     */
    public short sign(byte[] challenge, short off, short len, byte[] out, short outOff) {
        if (len != (short) 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        random.generateData(nonce, (short) 0, (short) nonce.length);
        return sign(nonce, (short) 0, challenge, off, len, out, outOff);
    }

    /**
     * Signs M = RND.IC || RND.IFD with an explicit RND.IC (used by the known
     * answer tests; the public {@link #sign} generates a fresh one).
     */
    public short sign(byte[] rndIc, short rndOff, byte[] challenge, short off, short len,
                      byte[] out, short outOff) {
        if (!privateKey.isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (len != (short) 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // H(M) = H(RND.IC || RND.IFD).
        digest.reset();
        digest.update(rndIc, rndOff, (short) nonce.length);
        digest.update(challenge, off, len);
        digest.doFinal(block, (short) 0, (short) 0, hash, (short) 0);

        // Encoded message: 0x6A || M1 || H(M) || trailer.
        short p = 0;
        block[p++] = (byte) 0x6A;
        Util.arrayCopyNonAtomic(rndIc, rndOff, block, p, (short) nonce.length);
        p += nonce.length;
        Util.arrayCopyNonAtomic(hash, (short) 0, block, p, digestLength);
        p += digestLength;
        if (trailerLength == (short) 1) {
            block[p++] = (byte) 0xBC; // option 1 (SHA-1)
        } else {
            block[p++] = (byte) 0x34; // SHA-256 hash-function identifier
            block[p++] = (byte) 0xCC; // option 2
        }

        rsa.init(privateKey, Cipher.MODE_DECRYPT);
        return rsa.doFinal(block, (short) 0, keyBytes, out, outOff);
    }
}
