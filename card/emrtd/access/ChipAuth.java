package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;

/* Chip Authentication, ECDH variant (ICAO Doc 9303-11 §6.2, BSI TR-03110-3 A.4/B.2).
 *
 * The chip holds a static P-256 key pair; its public key is published in
 * EF.CardSecurity (ChipAuthenticationPublicKeyInfo).  The terminal generates an
 * ephemeral key pair, sends its public key with MSE:SET KAT (DO'91'), and both
 * sides derive the shared secret Z = ECDH(static_priv, ephemeral_pub).  The new
 * secure-messaging keys are KDF(Z, 1/2) (SHA-1 for the 3DES profile), reusing
 * the ISO/IEC 7816-4 SM framework; the session counter restarts at zero.
 *
 * The card switches keys only after the response to MSE:SET KAT has been wrapped
 * with the old keys, so the terminal can restart SM on the next command.
 *
 * @author card42
 */

public final class ChipAuth {

    /* P-256 (secp256r1) domain parameters, FIPS 186-4 / BSI TR-03110 Table 6. */
    private static final byte[] P = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
    private static final byte[] A = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC };
    private static final byte[] B = {
        0x5A, (byte) 0xC6, 0x35, (byte) 0xD8, (byte) 0xAA, 0x3A, (byte) 0x93, (byte) 0xE7,
        (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, 0x55, 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
        0x65, 0x1D, 0x06, (byte) 0xB0, (byte) 0xCC, 0x53, (byte) 0xB0, (byte) 0xF6,
        0x3B, (byte) 0xCE, 0x3C, 0x3E, 0x27, (byte) 0xD2, 0x60, 0x4B };
    private static final byte[] G = {
        0x04,
        0x6B, 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, 0x2C, 0x42, 0x47,
        (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, 0x63, (byte) 0xA4, 0x40, (byte) 0xF2,
        0x77, 0x03, 0x7D, (byte) 0x81, 0x2D, (byte) 0xEB, 0x33, (byte) 0xA0,
        (byte) 0xF4, (byte) 0xA1, 0x39, 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96,
        0x4F, (byte) 0xE3, 0x42, (byte) 0xE2, (byte) 0xFE, 0x1A, 0x7F, (byte) 0x9B,
        (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, 0x4A, 0x7C, 0x0F, (byte) 0x9E, 0x16,
        0x2B, (byte) 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, (byte) 0xCE,
        (byte) 0xCB, (byte) 0xB6, 0x40, 0x68, 0x37, (byte) 0xBF, 0x51, (byte) 0xF5 };
    private static final byte[] R = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00, 0x00, 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, 0x17, (byte) 0x9E, (byte) 0x84,
        (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, 0x63, 0x25, 0x51 };

    private static final short SCALAR_LENGTH = (short) 32;

    /*
     * The EC key and KeyAgreement are built lazily: an LDS1/LDS2 instance that
     * is never personalized with a CA scalar (DGI FF03) must install and serve
     * BAC/LDS2 on a platform without ECC support (risks.md §ECC).
     */
    private ECPrivateKey privateKey;
    private KeyAgreement agreement;
    private final MessageDigest sha1;
    private final byte[] derivation = new byte[4];
    private final byte[] digest = new byte[20];
    /** Reused ECDH output; a per-session array would leak persistent memory. */
    private final byte[] secret = new byte[64];

    public ChipAuth() {
        sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
    }

    /** Sets the static private scalar (personalization DGI FF03). */
    public void setPrivateKey(byte[] scalar, short off, short len) {
        if (privateKey == null) {
            privateKey = (ECPrivateKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
            setCurve(privateKey);
            agreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        }
        privateKey.setS(scalar, off, len);
    }

    public boolean isInitialized() {
        return privateKey != null && privateKey.isInitialized();
    }

    /**
     * Runs ECDH with the terminal's ephemeral public key and writes the new
     * session keys Ks_enc/Ks_mac to the caller's buffers (3DES CA profile).
     *
     * <p>The peer point is validated before the scalar multiplication
     * (BSI TR-03110-3 A.3.4.1): a wrong length/prefix, a coordinate outside
     * [0, p), or a point the platform rejects as off-curve yields {@code 6A80}
     * (ICAO Doc 9303-11 §6.2.4.1).
     */
    public void deriveSessionKeys(byte[] peerW, short off, short len,
                                  byte[] encOut, short encOff,
                                  byte[] macOut, short macOff) {
        if (!isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (!isValidPublicPoint(peerW, off, len)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        agreement.init(privateKey);
        short secretLength;
        try {
            secretLength = agreement.generateSecret(peerW, off, len, secret, (short) 0);
        } catch (CryptoException e) {
            // The ECDH primitive rejects a point that is not on the curve;
            // map it to 6A80 rather than leaking a platform error.
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        deriveKey(secret, (short) 0, secretLength, (byte) 1, encOut, encOff);
        deriveKey(secret, (short) 0, secretLength, (byte) 2, macOut, macOff);
    }

    /**
     * Structural validation of the terminal's uncompressed public point:
     * {@code 0x04 || x(32) || y(32)} with both coordinates in [0, p).  The
     * on-curve condition itself is enforced by the platform's ECDH primitive
     * (see {@link #deriveSessionKeys}).
     */
    private static boolean isValidPublicPoint(byte[] w, short off, short len) {
        if (len != 65 || w[off] != 0x04) {
            return false;
        }
        short xOff = (short) (off + 1);
        short yOff = (short) (off + 33);
        return lessThanP(w, xOff) && lessThanP(w, yOff);
    }

    /** True when the 32-byte big-endian value at off is strictly less than p. */
    private static boolean lessThanP(byte[] value, short off) {
        for (short i = 0; i < (short) 32; i++) {
            short a = (short) (value[(short) (off + i)] & 0xFF);
            short b = (short) (P[i] & 0xFF);
            if (a != b) {
                return a < b;
            }
        }
        return false; // equal to p is not a reduced coordinate
    }

    /** KDF(Z, counter) = SHA-1(Z || 00 00 00 counter) truncated to 16 bytes. */
    private void deriveKey(byte[] z, short zOff, short zLen, byte counter,
                           byte[] out, short outOff) {
        derivation[3] = counter;
        sha1.reset();
        sha1.update(z, zOff, zLen);
        sha1.update(derivation, (short) 0, (short) 4);
        sha1.doFinal(digest, (short) 0, (short) 0, digest, (short) 0);
        Util.arrayCopyNonAtomic(digest, (short) 0, out, outOff, (short) 16);
        BacCrypto.adjustParity(out, outOff, (short) 16);
    }

    private static void setCurve(ECKey key) {
        key.setFieldFP(P, (short) 0, (short) P.length);
        key.setA(A, (short) 0, (short) A.length);
        key.setB(B, (short) 0, (short) B.length);
        key.setG(G, (short) 0, (short) G.length);
        key.setR(R, (short) 0, (short) R.length);
        key.setK((short) 1);
    }
}
