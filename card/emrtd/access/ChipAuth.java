package card42.emrtd;

import card42.common.Tlv;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;

/* Chip Authentication (ICAO Doc 9303-11 §6.2, BSI TR-03110-3 A.4/B.2).
 *
 * CA v1 with 3DES uses MSE:Set KAT (DO'91' = the terminal's ephemeral key);
 * CA v1 with AES uses MSE:Set AT (DO'80' = the CA OID) followed by GENERAL
 * AUTHENTICATE (DO'80' = the ephemeral key), with no protocol response data
 * (BSI TR-03110-3 B.2/B.14.3).  Both derive Z = ECDH(static_priv, ephemeral_pub)
 * and Ks_enc/Ks_mac = KDF(Z, 1/2); only the 3DES keys take DES parity.
 *
 * The chip holds a static P-256 key pair; its public key is published in
 * EF.CardSecurity (ChipAuthenticationPublicKeyInfo).
 *
 * The card switches keys only after the response to the authenticating command
 * has been wrapped with the old keys, so the terminal can restart SM on the
 * next command.
 *
 * @author card42
 */

public final class ChipAuth {

    private static final short SCALAR_LENGTH = (short) 32;
    /** id-CA-ECDH-<cipher> OID prefix (0.4.0.127.0.7.2.2.3.2); the last byte selects. */
    private static final byte[] CA_OID_PREFIX = {
        0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02 };
    /** Reusable TLV search result; a per-command array would leak persistent memory. */
    private static final short[] FIND = new short[2];

    /*
     * The EC key and KeyAgreement are built lazily: an LDS1/LDS2 instance that
     * is never personalized with a CA scalar (DGI FF03) must install and serve
     * BAC/LDS2 on a platform without ECC support (risks.md §ECC).
     */
    private ECPrivateKey privateKey;
    private KeyAgreement agreement;
    private final Sha1Kdf kdf;
    /**
     * Reused ECDH output, package-shared: only one instance runs a Chip
     * Authentication at a time, and the secret is consumed within one call, so
     * one array per package is enough (docs/specs/common/risks.md §2).
     */
    private static byte[] secret;
    /** True when the pending/negotiated CA profile uses AES-128 (no DES parity). */
    private boolean aes;
    /** True between MSE:Set AT (CA) and the GENERAL AUTHENTICATE that completes it. */
    private boolean gaPending;

    public ChipAuth() {
        kdf = KdfEngines.kdf();
        if (secret == null) {
            secret = new byte[64];
        }
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

    /** True when the pending/negotiated CA profile is AES-128 (else 3DES). */
    public boolean isAes() {
        return aes;
    }

    /** True between a CA MSE:Set AT and its GENERAL AUTHENTICATE. */
    public boolean isGaPending() {
        return gaPending;
    }

    /** Clears the pending CA state on application selection (ISO/IEC 7816-4). */
    public void reset() {
        gaPending = false;
    }

    /**
     * True when the MSE:Set AT DO'80' names a Chip Authentication ECDH profile
     * (as opposed to PACE), so {@link Mse} routes the command to
     * {@link #mseSetAt} rather than to PACE.
     */
    static boolean isChipAuthenticationData(byte[] data, short off, short len) {
        short[] r = FIND;
        if (!Tlv.find(data, off, len, EmrtdTags.DO_PACE_NONCE, r)
                || r[1] != (short) 10) {
            return false;
        }
        for (short i = 0; i < (short) 9; i++) {
            if (data[(short) (r[0] + i)] != CA_OID_PREFIX[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * MSE:Set AT for CA v1 with AES (BSI TR-03110-3 B.2/B.14.1): DO'80' = the CA
     * OID, DO'84' = the key reference.  The GENERAL AUTHENTICATE step follows.
     */
    public void mseSetAt(byte[] data, short off, short len) {
        short[] r = FIND;
        if (!isChipAuthenticationData(data, off, len)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        byte variant = data[(short) (r[0] + 9)];
        if (variant == (byte) 0x01) {
            aes = false;
        } else if (variant == (byte) 0x02) {
            aes = true;
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA); // only 3DES / AES-128
            // (id-CA-ECDH-3DES/AES-128, BSI TR-03110-3 Annex A)
        }
        gaPending = true;
    }

    /**
     * GENERAL AUTHENTICATE for CA v1 with AES: DO'80' = the terminal's ephemeral
     * public key.  No protocol response data is returned for version 1
     * (BSI TR-03110-3 B.2).
     */
    public void generalAuthenticate(byte[] data, short off, short len,
                                    byte[] encOut, short encOff,
                                    byte[] macOut, short macOff) {
        short[] r = FIND;
        if (!Tlv.find(data, off, len, EmrtdTags.DO_PACE_NONCE, r)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        gaPending = false;
        derive(data, r[0], r[1], encOut, encOff, macOut, macOff);
    }

    /**
     * Runs ECDH with the terminal's ephemeral public key for the 3DES profile
     * (MSE:Set KAT path) and writes Ks_enc/Ks_mac.
     *
     * <p>The peer point is validated before the scalar multiplication
     * (BSI TR-03110-3 A.3.4.1): a wrong length/prefix, a coordinate outside
     * [0, p), or a point the platform rejects as off-curve yields {@code 6A80}
     * (ICAO Doc 9303-11 §6.2.4.1).
     */
    public void deriveSessionKeys(byte[] peerW, short off, short len,
                                  byte[] encOut, short encOff,
                                  byte[] macOut, short macOff) {
        aes = false;
        derive(peerW, off, len, encOut, encOff, macOut, macOff);
    }

    private void derive(byte[] peerW, short off, short len,
                        byte[] encOut, short encOff, byte[] macOut, short macOff) {
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
        // DES parity applies to the 3DES profile only (BSI A.2.3.1/A.2.3.2).
        kdf.derive(z, zOff, zLen, counter, out, outOff, !aes);
    }
}
