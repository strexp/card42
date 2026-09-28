package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;

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

    private static final short SCALAR_LENGTH = (short) 32;

    /*
     * The EC key and KeyAgreement are built lazily: an LDS1/LDS2 instance that
     * is never personalized with a CA scalar (DGI FF03) must install and serve
     * BAC/LDS2 on a platform without ECC support (risks.md §ECC).
     */
    private ECPrivateKey privateKey;
    private KeyAgreement agreement;
    private final Sha1Kdf kdf;
    /** Reused ECDH output; a per-session array would leak persistent memory. */
    private final byte[] secret = new byte[64];

    public ChipAuth() {
        kdf = new Sha1Kdf();
    }

    /** Sets the static private scalar (personalization DGI FF03). */
    public void setPrivateKey(byte[] scalar, short off, short len) {
        if (privateKey == null) {
            privateKey = (ECPrivateKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
            P256.setCurve(privateKey);
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
        return P256.isLessThanP(w, xOff) && P256.isLessThanP(w, yOff);
    }

    /** KDF(Z, counter) = SHA-1(Z || 00 00 00 counter) truncated to 16 bytes. */
    private void deriveKey(byte[] z, short zOff, short zLen, byte counter,
                           byte[] out, short outOff) {
        kdf.derive(z, zOff, zLen, counter, out, outOff, true);
    }
}
