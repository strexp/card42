package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/* Active Authentication signing (ICAO Doc 9303-11 §6.1.2).
 *
 * Two profiles are supported, selected at personalization (DGI FF0A):
 *
 *  - RSA: the document holds an RSA private key whose public part is stored in
 *    DG15.  INTERNAL AUTHENTICATE sends an 8-byte RND.IFD; the card generates
 *    RND.IC and signs M = RND.IC || RND.IFD with the ISO/IEC 9796-2 Digital
 *    Signature Scheme 1 (message recovery, §6.1.2.2).  The recoverable part
 *    M1 = RND.IC is one byte shorter than the space left after the leading 0x6A
 *    separator, H(M) and the trailer field; SHA-1 uses trailer option 1
 *    (t=1, 0xBC), SHA-256 option 2 (t=2, 0x34CC).
 *  - ECDSA: the card holds a P-256 key pair whose public part is stored in DG15
 *    as an RFC 5480 SubjectPublicKeyInfo.  The signed message is RND.IFD only
 *    and the signature is the TR-03111 plain form r||s (§6.1.2.3).
 *
 * @author card42
 */

public final class AaCrypto {

    /** 0x01 = RSA ISO/IEC 9796-2 Scheme 1 with SHA-1; 0x02 = with SHA-256. */
    public static final byte AA_SHA1 = (byte) 0x01;
    public static final byte AA_SHA256 = (byte) 0x02;
    /** 0x03 = ECDSA with SHA-256 (P-256, plain r||s). */
    public static final byte AA_ECDSA_SHA256 = (byte) 0x03;

    private byte algorithm;
    private final RSAPrivateKey privateKey;
    private final Cipher rsa;
    private final MessageDigest sha1;
    private final MessageDigest sha256;
    private MessageDigest digest;
    private final RandomData random;
    private final short keyBytes;
    private short digestLength;
    private short trailerLength;
    /** M1 = RND.IC length for the active algorithm (keyBytes - 1 - Lh - 4t bits). */
    private short nonceLength;
    /** M1 = RND.IC, the recoverable message part (sized for SHA-1, the longest). */
    private final byte[] nonce;
    /** The ISO/IEC 9796-2 encoded message to be raised to the private exponent. */
    private final byte[] block;
    /** H(M), reused across calls (sized for the longest digest, SHA-256). */
    private final byte[] hash;

    /* ECDSA profile: P-256 private scalar and the plain-format signer. */
    private final ECPrivateKey ecKey;
    private final Signature ecdsa;

    public AaCrypto(short keyBits, byte algorithm) {
        keyBytes = (short) (keyBits / 8);
        privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
                keyBits, false);
        // Raw RSA (modular exponentiation) so the card controls the ISO/IEC
        // 9796-2 encoding itself; the platform only performs the RSA primitive.
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        // Every crypto object is built at install: the personalization may switch
        // the algorithm (DGI FF0A) but must not allocate inside the Security
        // Domain's processData transaction (docs/specs/common/risks.md §4).
        sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        ecKey = (ECPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        P256.setCurve(ecKey);
        ecdsa = Signature.getInstance(MessageDigest.ALG_SHA_256,
                Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false);
        // SHA-1 leaves the longest recoverable part, so it sizes nonce; SHA-256
        // the longest digest, so it sizes hash.
        nonce = new byte[(short) (keyBytes - 22)];
        block = new byte[keyBytes];
        hash = new byte[32];
        random = KdfEngines.random();
        setAlgorithm(algorithm);
    }

    /**
     * Selects the AA signature algorithm (DGI FF0A): RSA ISO/IEC 9796-2 with
     * SHA-1 (trailer option 1) or SHA-256 (option 2), or ECDSA-SHA-256
     * (ICAO Doc 9303-11 §6.1.2.2/§6.1.2.3).  No crypto object is allocated
     * here, so it is safe during personalization.
     */
    public void setAlgorithm(byte algorithm) {
        this.algorithm = algorithm;
        if (algorithm == AA_ECDSA_SHA256) {
            return;
        }
        if (algorithm == AA_SHA256) {
            digest = sha256;
            digestLength = (short) 32;
            trailerLength = (short) 2;
        } else {
            digest = sha1;
            digestLength = (short) 20;
            trailerLength = (short) 1;
        }
        nonceLength = (short) (keyBytes - 1 - digestLength - trailerLength);
    }

    /** Sets the RSA AA private key (modulus || exponent) from personalization data. */
    public void setPrivateKey(byte[] modulus, short modOff, short modLen,
                              byte[] exponent, short expOff, short expLen) {
        privateKey.setModulus(modulus, modOff, modLen);
        privateKey.setExponent(exponent, expOff, expLen);
    }

    /** Sets the ECDSA AA private scalar (DGI FF0D) from personalization data. */
    public void setEcPrivateKey(byte[] scalar, short off, short len) {
        ecKey.setS(scalar, off, len);
    }

    public boolean isInitialized() {
        return algorithm == AA_ECDSA_SHA256 ? ecKey.isInitialized() : privateKey.isInitialized();
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    /**
     * Signs the 8-byte RND.IFD.  RSA generates RND.IC here; ECDSA signs the
     * challenge directly.  Returns the signature length written to out.
     */
    public short sign(byte[] challenge, short off, short len, byte[] out, short outOff) {
        if (len != (short) 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (algorithm == AA_ECDSA_SHA256) {
            if (!ecKey.isInitialized()) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            ecdsa.init(ecKey, Signature.MODE_SIGN);
            return ecdsa.sign(challenge, off, len, out, outOff);
        }
        random.generateData(nonce, (short) 0, nonceLength);
        return sign(nonce, (short) 0, challenge, off, len, out, outOff);
    }

    /**
     * Signs M = RND.IC || RND.IFD with an explicit RND.IC (RSA profile; used by
     * the known answer tests.  The public {@link #sign} generates a fresh one).
     */
    public short sign(byte[] rndIc, short rndOff, byte[] challenge, short off, short len,
                      byte[] out, short outOff) {
        if (algorithm == AA_ECDSA_SHA256) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (!privateKey.isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (len != (short) 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // H(M) = H(RND.IC || RND.IFD).
        digest.reset();
        digest.update(rndIc, rndOff, nonceLength);
        digest.update(challenge, off, len);
        digest.doFinal(block, (short) 0, (short) 0, hash, (short) 0);

        // Encoded message: 0x6A || M1 || H(M) || trailer.
        short p = 0;
        block[p++] = (byte) 0x6A;
        Util.arrayCopyNonAtomic(rndIc, rndOff, block, p, nonceLength);
        p += nonceLength;
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
