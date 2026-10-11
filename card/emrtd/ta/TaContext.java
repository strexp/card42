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

    /**
     * Trust-point relative authorization per application (Doc 9303-10 §5.4.2):
     * [0] = ePassport CHAT byte, [1] = Travel, [2] = Visa, [3] = Biometrics.
     * Persistent (personalization DGI FF07).
     */
    final byte[] trustPointAuth = new byte[4];
    /** Session effective authorization: trust-point auth AND each verified certificate. */
    final byte[] effectiveAuth = new byte[4];

    /**
     * The ICC's approximated current date (BSI TR-03110-3 §2.5): 6 octets,
     * unpacked BCD YYMMDD.  Set to the personalization date (DGI FF08) and only
     * ever advanced to the most recent valid CVCA/DV/Accurate-Terminal Effective
     * Date; it is used to reject expired DV/terminal certificates.
     */
    final byte[] currentDate = new byte[6];
    boolean currentDateValid;
    /** Role of the certificate whose public key is the current DST target. */
    private byte dstIssuerRole;
    /** Role of the most recently imported certificate. */
    private byte importedRole;

    /* Certificate-holder roles (CHAT bits b8/b7, BSI TR-03110-4 §2.1.3.2). */
    private static final byte ROLE_IS = 0;
    private static final byte ROLE_DV_FOREIGN = 1;
    private static final byte ROLE_DV_DOMESTIC = 2;
    private static final byte ROLE_CVCA = 3;

    /** Application authorization extension OIDs (ICAO Doc 9303-10 §5.4.2). */
    private static final byte[] OID_TRAVEL = {
        0x67, (byte) 0x81, 0x08, 0x01, 0x01, 0x09, 0x01 };
    private static final byte[] OID_VISA = {
        0x67, (byte) 0x81, 0x08, 0x01, 0x01, 0x09, 0x02 };
    private static final byte[] OID_BIOMETRICS = {
        0x67, (byte) 0x81, 0x08, 0x01, 0x01, 0x09, 0x03 };

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
        importedRole = ROLE_IS;
        dstIssuerRole = ROLE_IS;
        Util.arrayCopyNonAtomic(trustPointAuth, (short) 0, effectiveAuth, (short) 0, (short) 4);
        Util.arrayFillNonAtomic(idIc, (short) 0, (short) idIc.length, (byte) 0);
        Util.arrayFillNonAtomic(caKeyHash, (short) 0, (short) caKeyHash.length, (byte) 0);
    }

    /** Effective authorization byte for an application index (0 epassport, 1..3). */
    public byte authorization(short application) {
        return effectiveAuth[application];
    }

    /** True when the terminal is authenticated and holds the requested bit (0..7). */
    public boolean granted(short application, byte bit) {
        short mask = (short) (1 << bit);
        short value = (short) (effectiveAuth[application] & mask);
        return taDone && value != 0;
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
        Util.arrayFillNonAtomic(trustPointAuth, (short) 0, (short) 4, (byte) 0);
        short authOff = (short) (off + KEY_LENGTH + 1 + refLen);
        if ((short) (authOff + 4) <= (short) (off + len)) {
            // Optional trailing relative authorization
            // [ePassport, Travel, Visa, Biometrics] (Doc 9303-10 §5.4.2).
            Util.arrayCopyNonAtomic(src, authOff, trustPointAuth, (short) 0, (short) 4);
        }
        Util.arrayCopyNonAtomic(trustPointAuth, (short) 0, effectiveAuth, (short) 0, (short) 4);
        trustPointValid = true;
    }

    /**
     * Personalization (DGI FF08): the ICC current date, 6 octets unpacked BCD
     * YYMMDD (BSI TR-03110-3 §2.6).  A card without it skips the expiration
     * check but still advances from the first certificate it verifies.
     */
    public void setCurrentDate(byte[] src, short off, short len) {
        if (len != (short) 6) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        for (short i = 0; i < 6; i++) {
            if (src[(short) (off + i)] > 9) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
        Util.arrayCopyNonAtomic(src, off, currentDate, (short) 0, (short) 6);
        currentDateValid = true;
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
        importCertificate(data, bodyValueOffset, bodyValueLength, dstIssuerRole);
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

    /** The key referenced by the pending MSE:Set DST, or 6A88.  Sets the issuer role. */
    private byte[] resolveDstKey() {
        if (dstRefLength == trustPointRefLength
                && Util.arrayCompare(dstRef, (short) 0, trustPointRef, (short) 0, dstRefLength) == 0) {
            dstIssuerRole = ROLE_CVCA;
            return trustPointW;
        }
        if (importedValid && dstRefLength == importedRefLength
                && Util.arrayCompare(dstRef, (short) 0, importedRef, (short) 0, dstRefLength) == 0) {
            dstIssuerRole = importedRole;
            return importedW;
        }
        ISOException.throwIt((short) 0x6A88); // referenced data not found
        return null; // unreachable
    }

    /**
     * Parses the certificate body, enforces the validity period and imports the
     * key (BSI TR-03110-3 §2.5.2): a non-CVCA-Link certificate whose expiration
     * date is before the current date fails; the current date is advanced to the
     * Effective Date for CVCA/DV and for accurate (domestic-DV-issued) terminal
     * certificates.
     */
    private void importCertificate(byte[] data, short off, short len, byte issuerRole) {
        short p = off;
        short end = (short) (off + len);
        boolean chrFound = false;
        short chrOff = 0;
        short chrLength = 0;
        short pointOff = 0;
        boolean pointFound = false;
        byte role = ROLE_IS;
        short effectiveOff = 0;
        boolean effectiveFound = false;
        short expirationOff = 0;
        boolean expirationFound = false;

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
            } else if (tag == EmrtdTags.TAG_TA_CHAT) {
                role = andChat(data, valueOff, valueLength);
            } else if (tag == EmrtdTags.TAG_TA_EXTENSIONS) {
                andExtensions(data, valueOff, valueLength);
            } else if (tag == EmrtdTags.TAG_TA_EFFECTIVE) {
                effectiveOff = valueOff;
                effectiveFound = valueLength == (short) 6;
            } else if (tag == EmrtdTags.TAG_TA_EXPIRATION) {
                expirationOff = valueOff;
                expirationFound = valueLength == (short) 6;
            }
            p = (short) (p + total);
        }
        if (!pointFound || !chrFound) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Expiry: CVCA Link Certificates are exempt; every other certificate
        // must not have expired relative to the ICC current date (§2.5.1).
        if (role != ROLE_CVCA && expirationFound && currentDateValid
                && compare(currentDate, data, expirationOff) > 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        Util.arrayCopyNonAtomic(data, pointOff, importedW, (short) 0, KEY_LENGTH);
        Util.arrayCopyNonAtomic(data, chrOff, importedRef, (short) 0, chrLength);
        importedRefLength = chrLength;
        importedRole = role;
        importedValid = true;

        // Advance the current date (§2.5.2 step i).
        if (effectiveFound && advancesDate(role, issuerRole)) {
            if (!currentDateValid || compare(currentDate, data, effectiveOff) < 0) {
                Util.arrayCopyNonAtomic(data, effectiveOff, currentDate, (short) 0, (short) 6);
                currentDateValid = true;
            }
        }
    }

    /** True for a certificate whose Effective Date may advance the current date. */
    private static boolean advancesDate(byte role, byte issuerRole) {
        if (role == ROLE_CVCA || role == ROLE_DV_DOMESTIC || role == ROLE_DV_FOREIGN) {
            return true;
        }
        // A Terminal Certificate is "accurate" only if issued by a domestic DV
        // (BSI TR-03110-3 §2.5).
        return issuerRole == ROLE_DV_DOMESTIC;
    }

    /** Compares the 6-octet BCD date at currentDate with the one at data[off]. */
    private static short compare(byte[] current, byte[] data, short off) {
        for (short i = 0; i < 6; i++) {
            short a = (short) (current[i] & 0xFF);
            short b = (short) (data[(short) (off + i)] & 0xFF);
            if (a != b) {
                return a < b ? (short) -1 : (short) 1;
            }
        }
        return 0;
    }

    /** The certificate-holder role from the CHAT discretionary byte (b8/b7). */
    private static byte roleOf(byte discretionary) {
        switch (discretionary & 0xC0) {
        case 0xC0:
            return ROLE_CVCA;
        case 0x80:
            return ROLE_DV_DOMESTIC;
        case 0x40:
            return ROLE_DV_FOREIGN;
        default:
            return ROLE_IS;
        }
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

    /** ANDs the CHAT relative authorization and returns the certificate-holder role. */
    private byte andChat(byte[] data, short off, short len) {
        if (Lds2Record.find(data, off, len, EmrtdTags.TAG_TA_DISCRETIONARY, FIND)
                && FIND[1] >= 1) {
            byte chat = data[FIND[0]];
            effectiveAuth[0] = (byte) (effectiveAuth[0] & chat);
            return roleOf(chat);
        }
        return ROLE_IS;
    }

    /** ANDs each application authorization extension into the effective authorization. */
    private void andExtensions(byte[] data, short off, short len) {
        short p = off;
        short end = (short) (off + len);
        while (p < end) {
            short total = Tlv.totalLength(data, p);
            if (total <= 0 || (short) (p + total) > end) {
                break;
            }
            if (Tlv.getTag(data, p) == EmrtdTags.TAG_TA_DISCRETIONARY_TEMPLATE) {
                andExtension(data, Tlv.valueOffset(data, p),
                        Tlv.getLength(data, Tlv.lengthOffset(data, p)));
            }
            p = (short) (p + total);
        }
    }

    private void andExtension(byte[] data, short off, short len) {
        short oidOff = 0;
        short oidLen = 0;
        boolean oidFound = false;
        short bitsOff = 0;
        boolean bitsFound = false;
        short p = off;
        short end = (short) (off + len);
        while (p < end) {
            short total = Tlv.totalLength(data, p);
            if (total <= 0 || (short) (p + total) > end) {
                break;
            }
            short tag = Tlv.getTag(data, p);
            if (tag == EmrtdTags.TAG_TA_OID) {
                oidOff = Tlv.valueOffset(data, p);
                oidLen = Tlv.getLength(data, Tlv.lengthOffset(data, p));
                oidFound = true;
            } else if (tag == EmrtdTags.TAG_TA_DISCRETIONARY) {
                bitsOff = Tlv.valueOffset(data, p);
                bitsFound = true;
            }
            p = (short) (p + total);
        }
        if (!oidFound || !bitsFound) {
            return;
        }
        short index = appIndex(data, oidOff, oidLen);
        if (index >= 0) {
            effectiveAuth[index] = (byte) (effectiveAuth[index] & data[bitsOff]);
        }
    }

    /** 1 = Travel, 2 = Visa, 3 = Biometrics; -1 for an unknown application OID. */
    private static short appIndex(byte[] data, short off, short len) {
        if (matches(data, off, len, OID_TRAVEL)) {
            return (short) 1;
        }
        if (matches(data, off, len, OID_VISA)) {
            return (short) 2;
        }
        if (matches(data, off, len, OID_BIOMETRICS)) {
            return (short) 3;
        }
        return (short) -1;
    }

    private static boolean matches(byte[] data, short off, short len, byte[] oid) {
        return len == (short) oid.length
                && Util.arrayCompare(data, off, oid, (short) 0, len) == 0;
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
