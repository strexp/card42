package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import card42.common.Tlv;

/* Card-side Terminal Authentication state (ICAO Doc 9303-11 §7.1, BSI
 * TR-03110-3 A.7): the CVCA trust point, the certificate chain verification
 * (MSE:Set DST + PSO:Verify Certificate), and the terminal key import.  The
 * ECDSA-SHA-256 plain-format verification uses the platform
 * Signature.getInstance(ALG_SHA_256, SIG_CIPHER_ECDSA_PLAIN, PAD_NULL) (see
 * docs/specs/emrtd/terminal-authentication.md).
 *
 * Only the LDS1 instance creates a TaContext; LDS2 instances get null (their
 * Terminal Authentication is not wired yet).
 *
 * @author card42
 */

public final class TaContext {

    private static final short KEY_LENGTH = (short) 65;
    private static final short REFERENCE_LENGTH = (short) 16;

    /** Reused TLV search result; a per-command array would leak persistent memory. */
    private static final short[] FIND = new short[2];

    /** CVCA trust point (personalization DGI FF07); permanent. */
    final byte[] trustPointW = new byte[KEY_LENGTH];
    final byte[] trustPointRef = new byte[REFERENCE_LENGTH];
    short trustPointRefLength;
    boolean trustPointValid;

    /** The most recently verified certificate's public key (session). */
    final byte[] importedW = new byte[KEY_LENGTH];
    final byte[] importedRef = new byte[REFERENCE_LENGTH];
    short importedRefLength;
    boolean importedValid;

    /** The reference set by MSE:Set DST (session). */
    final byte[] dstRef = new byte[REFERENCE_LENGTH];
    short dstRefLength;
    boolean dstSet;

    /* Terminal Authentication challenge and the ID_IC / Comp(PKDH,IFD) inputs
     * captured from PACE/Chip Authentication (used by EXTERNAL AUTHENTICATE). */
    final byte[] challenge = new byte[8];
    boolean challengeValid;
    boolean taDone;
    /** True after MSE:Set AT selected the terminal key (awaiting EXTERNAL AUTHENTICATE). */
    boolean terminalSelected;
    final byte[] idIc = new byte[32];
    final byte[] caKeyHash = new byte[32];

    /** ID_IC || rIC || Comp(PKDH,IFD) (32 + 8 + 32). */
    private final byte[] signatureInput = new byte[72];

    private ECPublicKey ecKey;
    private Signature ecSig;

    public TaContext() {
    }

    /** Clears the per-session state (called on selection). */
    public void clearSession() {
        importedValid = false;
        importedRefLength = 0;
        dstSet = false;
        dstRefLength = 0;
        challengeValid = false;
        taDone = false;
        terminalSelected = false;
        Util.arrayFillNonAtomic(idIc, (short) 0, (short) idIc.length, (byte) 0);
        Util.arrayFillNonAtomic(caKeyHash, (short) 0, (short) caKeyHash.length, (byte) 0);
    }

    /** True once a CVCA trust point has been personalized. */
    public boolean hasTrustPoint() {
        return trustPointValid;
    }

    /**
     * Personalization (DGI FF07): {@code W(65) || refLen(1) || CAR(refLen)}.
     * The CVCA public key is the trust anchor for the certificate chain.
     */
    public void setTrustPoint(byte[] src, short off, short len) {
        if (len < (short) (KEY_LENGTH + 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short refLen = (short) (src[(short) (off + KEY_LENGTH)] & 0xFF);
        if (refLen < 1 || refLen > REFERENCE_LENGTH
                || (short) (KEY_LENGTH + 1 + refLen) > len) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        ensureEc();
        Util.arrayCopyNonAtomic(src, off, trustPointW, (short) 0, KEY_LENGTH);
        Util.arrayCopyNonAtomic(src, (short) (off + KEY_LENGTH + 1),
                trustPointRef, (short) 0, refLen);
        trustPointRefLength = refLen;
        trustPointValid = true;
    }

    /** MSE:Set DST (P1/P2 = 0x81B6): DO'83' names the key that verifies the next certificate. */
    public void mseSetDst(byte[] data, short off, short len) {
        if (!hasTrustPoint()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (taDone) {
            // Terminal Authentication MUST NOT run twice in a session
            // (ICAO Doc 9303-11 §7.1.3).
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (!Lds2Record.find(data, off, len, EmrtdTags.DO_KEY_REFERENCE, FIND)
                || FIND[1] < 1 || FIND[1] > REFERENCE_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Util.arrayCopyNonAtomic(data, FIND[0], dstRef, (short) 0, FIND[1]);
        dstRefLength = FIND[1];
        dstSet = true;
    }

    /**
     * PSO:Verify Certificate (P1/P2 = 0x00BE): data is {@code 7F4E <body> 5F37 <sig>}.
     * Verifies the body signature with the DST key and imports the certificate's
     * public key (its Certificate Holder Reference becomes the next DST target).
     */
    public void psoVerifyCertificate(byte[] data, short off, short len) {
        if (!dstSet) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        // The PSO data is the certificate body TLV (7F4E, whose tag and length
        // the signature covers, BSI TR-03110-3 C.1.8) followed by the signature
        // TLV (5F37).
        short end = (short) (off + len);
        short p = off;
        short bodyStart = -1;
        short bodyTotal = 0;
        short bodyValueOffset = 0;
        short bodyValueLength = 0;
        short signatureOffset = 0;
        short signatureLength = 0;
        while (p < end) {
            short total = Tlv.totalLength(data, p);
            if (total <= 0 || (short) (p + total) > end) {
                break;
            }
            short tag = Tlv.getTag(data, p);
            if (tag == EmrtdTags.DO_CERT_BODY) {
                bodyStart = p;
                bodyTotal = total;
                bodyValueOffset = Tlv.valueOffset(data, p);
                bodyValueLength = Tlv.getLength(data, Tlv.lengthOffset(data, p));
            } else if (tag == EmrtdTags.DO_CERT_SIGNATURE) {
                signatureOffset = Tlv.valueOffset(data, p);
                signatureLength = Tlv.getLength(data, Tlv.lengthOffset(data, p));
            }
            p = (short) (p + total);
        }
        if (bodyStart < 0 || signatureLength != 64) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        byte[] verifyingKey = resolveDstKey();
        if (!verifyEcdsa(verifyingKey, data, bodyStart, bodyTotal,
                data, signatureOffset, signatureLength)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        importCertificate(data, bodyValueOffset, bodyValueLength);
        dstSet = false;
    }

    /** Records ID_IC = Comp(PKDH,IC) from an uncompressed PICC ephemeral point. */
    public void notePiccEphemeral(byte[] uncompressedW, short off, short len) {
        if (len == KEY_LENGTH && uncompressedW[off] == (byte) 0x04) {
            Util.arrayCopyNonAtomic(uncompressedW, (short) (off + 1), idIc, (short) 0, (short) 32);
        }
    }

    /** Records Comp(PKDH,IFD) from an uncompressed terminal ephemeral point. */
    public void noteTerminalEphemeral(byte[] uncompressedW, short off, short len) {
        if (len == KEY_LENGTH && uncompressedW[off] == (byte) 0x04) {
            Util.arrayCopyNonAtomic(uncompressedW, (short) (off + 1), caKeyHash, (short) 0,
                    (short) 32);
        }
    }

    /** MSE:Set AT (P1/P2 = 0x81A4): selects the terminal public key by holder reference. */
    public void mseSetAt(byte[] data, short off, short len) {
        if (taDone) {
            // Terminal Authentication MUST NOT run twice in a session
            // (ICAO Doc 9303-11 §7.1.3).
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (!importedValid) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (!Lds2Record.find(data, off, len, EmrtdTags.DO_KEY_REFERENCE, FIND)
                || FIND[1] < 1 || FIND[1] != importedRefLength
                || Util.arrayCompare(data, FIND[0], importedRef, (short) 0, FIND[1]) != 0) {
            ISOException.throwIt((short) 0x6A88); // referenced data not found
        }
        terminalSelected = true;
        challengeValid = false;
    }

    public boolean isTerminalSelected() {
        return terminalSelected;
    }

    /**
     * EXTERNAL AUTHENTICATE for Terminal Authentication: verifies the terminal
     * signature over {@code ID_IC || rIC || Comp(PKDH,IFD)} with the imported key
     * (ICAO Doc 9303-11 §7.1.5.5).
     */
    public void externalAuthenticate(byte[] data, short off, short len) {
        if (!terminalSelected || !challengeValid) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (len != 64) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(idIc, (short) 0, signatureInput, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(challenge, (short) 0, signatureInput, (short) 32, (short) 8);
        Util.arrayCopyNonAtomic(caKeyHash, (short) 0, signatureInput, (short) 40, (short) 32);
        boolean ok = verifyEcdsa(importedW, signatureInput, (short) 0, (short) 72, data, off, len);
        challengeValid = false;
        terminalSelected = false;
        if (!ok) {
            ISOException.throwIt((short) 0x6300); // warning: signature verification failed
        }
        taDone = true;
    }

    /** The key referenced by the pending MSE:Set DST, or 6A88. */
    private byte[] resolveDstKey() {
        if (dstRefLength == trustPointRefLength
                && Util.arrayCompare(dstRef, (short) 0, trustPointRef, (short) 0, dstRefLength) == 0) {
            return trustPointW;
        }
        if (importedValid && dstRefLength == importedRefLength
                && Util.arrayCompare(dstRef, (short) 0, importedRef, (short) 0, dstRefLength) == 0) {
            return importedW;
        }
        ISOException.throwIt((short) 0x6A88); // referenced data not found
        return null; // unreachable
    }

    /** Extracts the certificate's EC public point (7F49 -> 86) and holder reference (5F20). */
    private void importCertificate(byte[] data, short off, short len) {
        short p = off;
        short end = (short) (off + len);
        boolean chrFound = false;
        short chrOff = 0;
        short chrLength = 0;
        short pointOff = 0;
        boolean pointFound = false;

        while (p < end) {
            short total = Tlv.totalLength(data, p);
            if (total <= 0 || (short) (p + total) > end) {
                break;
            }
            short tag = Tlv.getTag(data, p);
            short valueOff = Tlv.valueOffset(data, p);
            short valueLength = Tlv.getLength(data, Tlv.lengthOffset(data, p));
            if (tag == EmrtdTags.TAG_TA_PUBLIC_KEY) {
                pointOff = findEcPoint(data, valueOff, valueLength);
                pointFound = pointOff > 0;
            } else if (tag == EmrtdTags.TAG_TA_CHR) {
                if (valueLength > REFERENCE_LENGTH) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                chrOff = valueOff;
                chrLength = valueLength;
                chrFound = true;
            }
            p = (short) (p + total);
        }
        if (!pointFound || !chrFound) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Util.arrayCopyNonAtomic(data, pointOff, importedW, (short) 0, KEY_LENGTH);
        Util.arrayCopyNonAtomic(data, chrOff, importedRef, (short) 0, chrLength);
        importedRefLength = chrLength;
        importedValid = true;
    }

    /** The offset of the 65-byte EC public point (tag 86) inside a 7F49 value, or 0. */
    private static short findEcPoint(byte[] data, short off, short len) {
        short p = off;
        short end = (short) (off + len);
        while (p < end) {
            short total = Tlv.totalLength(data, p);
            if (total <= 0 || (short) (p + total) > end) {
                return 0;
            }
            short tag = Tlv.getTag(data, p);
            short valueOff = Tlv.valueOffset(data, p);
            short valueLength = Tlv.getLength(data, Tlv.lengthOffset(data, p));
            if (tag == EmrtdTags.TAG_TA_EC_POINT && valueLength == KEY_LENGTH) {
                return valueOff;
            }
            p = (short) (p + total);
        }
        return 0;
    }

    private void ensureEc() {
        if (ecKey == null) {
            ecKey = (ECPublicKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            P256.setCurve(ecKey);
            ecSig = Signature.getInstance(MessageDigest.ALG_SHA_256,
                    Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false);
        }
    }

    private boolean verifyEcdsa(byte[] keyW, byte[] message, short messageOff, short messageLength,
                                byte[] signature, short signatureOff, short signatureLength) {
        ensureEc();
        ecKey.setW(keyW, (short) 0, KEY_LENGTH);
        ecSig.init(ecKey, Signature.MODE_VERIFY);
        return ecSig.verify(message, messageOff, messageLength, signature, signatureOff,
                signatureLength);
    }
}
