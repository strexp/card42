package card42.emrtd;

import card42.common.IsoStatus;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import card42.common.Tlv;

/* Card-side Terminal Authentication state (ICAO Doc 9303-11 §7.1, BSI
 * TR-03110-3 A.7): the CVCA trust point(s), the certificate chain verification
 * (MSE:Set DST + PSO:Verify Certificate) and the terminal key import.
 *
 * The terminal-signature/certificate algorithm is selected per
 * certificate from its public-key OID: ECDSA-SHA-256 (TR-03111 plain r||s,
 * verified directly with SIG_CIPHER_ECDSA_PLAIN) or RSA-PSS-SHA-256
 * (Signature.ALG_RSA_SHA_256_PKCS1_PSS, salt = SHA-256 length).
 *
 * Up to two CVCA trust points are kept (BSI TR-03110-3 §2.5.1): the initial
 * one(s) from personalization (DGI FF07 / FF09) and any CVCA Link Certificate
 * imported at run time.  A trust point only verifies certificates once its
 * Effective Date has been reached; the newest effective one seeds the
 * authorization (enabled/disabled by Effective Date).
 *
 * All state is package-shared static: a card has a single CVCA key set and
 * current date, and only one instance is selected at a time, so per-instance
 * copies would only waste the scarce persistent heap (docs/specs/common/
 * risks.md §2).  The key/Signature objects are built on first use (at
 * personalization, before any command), never on a command path.
 *
 * @author card42
 */

public final class TaContext {

    /** ECDSA P-256 plain signature length. */
    private static final short ECDSA_SIGNATURE_LENGTH = (short) 64;

    /** Reused TLV search result; a per-command array would leak persistent memory. */
    private static final short[] FIND = new short[2];

    /** The most recently verified certificate's public key (session). */
    static final byte[] importedKey = new byte[TaKeys.MAX_MODULUS];
    static final byte[] importedExp = new byte[TaKeys.MAX_EXPONENT];
    static short importedKeyLength;
    static short importedExpLength;
    static byte importedKind;
    static final byte[] importedRef = new byte[TaTrustStore.REFERENCE_LENGTH];
    static short importedRefLength;
    static boolean importedValid;

    /** The reference set by MSE:Set DST (session). */
    static final byte[] dstRef = new byte[TaTrustStore.REFERENCE_LENGTH];
    static short dstRefLength;
    static boolean dstSet;

    /* Terminal Authentication challenge and the ID_IC / Comp(PKDH,IFD) inputs
     * captured from PACE/Chip Authentication (used by EXTERNAL AUTHENTICATE). */
    static final byte[] challenge = new byte[8];
    static boolean challengeValid;
    static boolean taDone;
    /** True after MSE:Set AT selected the terminal key (awaiting EXTERNAL AUTHENTICATE). */
    static boolean terminalSelected;
    static final byte[] idIc = new byte[32];
    static final byte[] caKeyHash = new byte[32];

    /** Role of the certificate whose public key is the current DST target. */
    private static byte dstIssuerRole;
    /** Role of the most recently imported certificate. */
    private static byte importedRole;

    /*
     * One staging buffer for the key currently parsed from a certificate, the
     * key selected by MSE:Set DST (just verified) and the terminal-signature
     * input.  The three never overlap: resolve+verify (DST key) runs before
     * importCertificate parses the next key, and the terminal message is built
     * after the imported key has been loaded into the Signature engine.  This
     * replaces the former pkKey/vKey/signatureInput trio (docs/specs/common/
     * risks.md §2).
     */
    private static final byte[] stagingKey = new byte[TaKeys.MAX_MODULUS];
    private static final byte[] stagingExp = new byte[TaKeys.MAX_EXPONENT];
    private static short stagingKeyLength;
    private static short stagingExpLength;
    private static byte stagingKind;

    /** Staging for the certificate's own relative authorization (4 bytes). */
    private static final byte[] certAuth = new byte[4];

    /* Certificate-holder roles (CHAT bits b8/b7, BSI TR-03110-4 §2.1.3.2). */
    private static final byte ROLE_IS = 0;
    private static final byte ROLE_DV_FOREIGN = 1;
    private static final byte ROLE_DV_DOMESTIC = 2;
    private static final byte ROLE_CVCA = 3;

    /** Application authorization extension OIDs (ICAO Doc 9303-10 Table 99, §5.4.2). */
    private static final byte[] OID_TRAVEL = {
        0x67, (byte) 0x81, 0x08, 0x01, 0x01, 0x09, 0x01, 0x03 };
    private static final byte[] OID_VISA = {
        0x67, (byte) 0x81, 0x08, 0x01, 0x01, 0x09, 0x02, 0x03 };
    private static final byte[] OID_BIOMETRICS = {
        0x67, (byte) 0x81, 0x08, 0x01, 0x01, 0x09, 0x03, 0x03 };

    /* Terminal-key algorithm OIDs (BSI TR-03110-3 Table 27). */
    private static final byte[] OID_TA_ECDSA_SHA_256 = {
        0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03 };
    private static final byte[] OID_TA_RSA_PSS_SHA_256 = {
        0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x04 };

    public TaContext() {
    }

    /** Clears the per-session state (called on selection). */
    public void clearSession() {
        importedValid = false;
        importedRefLength = 0;
        importedKind = TaKeys.KIND_NONE;
        importedKeyLength = 0;
        dstSet = false;
        dstRefLength = 0;
        challengeValid = false;
        taDone = false;
        terminalSelected = false;
        importedRole = ROLE_IS;
        dstIssuerRole = ROLE_IS;
        TaTrustStore.seedAuthorization();
        Util.arrayFillNonAtomic(idIc, (short) 0, (short) idIc.length, (byte) 0);
        Util.arrayFillNonAtomic(caKeyHash, (short) 0, (short) caKeyHash.length, (byte) 0);
    }

    /** True when the terminal is authenticated and holds the requested bit (0..7). */
    public boolean granted(short application, byte bit) {
        short mask = (short) (1 << bit);
        short value = (short) (TaTrustStore.effectiveAuth[application] & mask);
        return taDone && value != 0;
    }






    /** MSE:Set DST (P1/P2 = 0x81B6): DO'83' names the key that verifies the next certificate. */
    public void mseSetDst(byte[] data, short off, short len) {
        // A CVCA trust point must be personalized to verify any certificate
        // (BSI TR-03110-3 A.7.2).
        if (!hasTrustPoint()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (taDone) {
            // Terminal Authentication establishes the IC security status once
            // per session; re-running it would let the terminal accumulate
            // authorization (ICAO Doc 9303-11 §7.1.3, §7.1.4.3.6).
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (!Tlv.find(data, off, len, EmrtdTags.DO_KEY_REFERENCE, FIND)
                || FIND[1] < 1 || FIND[1] > TaTrustStore.REFERENCE_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Util.arrayCopyNonAtomic(data, FIND[0], dstRef, (short) 0, FIND[1]);
        dstRefLength = FIND[1];
        dstSet = true;
    }

    /**
     * PSO:Verify Certificate (P1/P2 = 0x00BE): data is {@code 7F4E <body> 5F37 <sig>}.
     * Verifies the body signature with the DST key and imports the certificate:
     * a CVCA Link Certificate updates the CVCA trust-point set; any other
     * certificate's public key becomes the next DST target (BSI TR-03110-3 A.7.2).
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
        if (bodyStart < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        if (!resolveDstKey()) {
            ISOException.throwIt(IsoStatus.SW_REFERENCED_DATA_NOT_FOUND);
        }
        short expected = stagingKind == TaKeys.KIND_EC ? ECDSA_SIGNATURE_LENGTH : stagingKeyLength;
        if (signatureLength != expected) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (!TaKeys.verifyKey(stagingKind, stagingKey, stagingKeyLength, stagingExp, stagingExpLength,
                data, bodyStart, bodyTotal, data, signatureOffset, signatureLength)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        importCertificate(data, bodyValueOffset, bodyValueLength, dstIssuerRole);
        dstSet = false;
    }

    /** Records ID_IC = Comp(PKDH,IC) from an uncompressed PICC ephemeral point. */
    public void notePiccEphemeral(byte[] uncompressedW, short off, short len) {
        if (len == TaKeys.EC_KEY_LENGTH && uncompressedW[off] == (byte) 0x04) {
            Util.arrayCopyNonAtomic(uncompressedW, (short) (off + 1), idIc, (short) 0, (short) 32);
        }
    }

    /** Records Comp(PKDH,IFD) from an uncompressed terminal ephemeral point. */
    public void noteTerminalEphemeral(byte[] uncompressedW, short off, short len) {
        if (len == TaKeys.EC_KEY_LENGTH && uncompressedW[off] == (byte) 0x04) {
            Util.arrayCopyNonAtomic(uncompressedW, (short) (off + 1), caKeyHash, (short) 0,
                    (short) 32);
        }
    }

    /** MSE:Set AT (P1/P2 = 0x81A4): selects the terminal public key by holder reference. */
    public void mseSetAt(byte[] data, short off, short len) {
        if (taDone) {
            // Terminal Authentication establishes the IC security status once
            // per session; re-running it would let the terminal accumulate
            // authorization (ICAO Doc 9303-11 §7.1.3, §7.1.4.3.6).
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (!importedValid) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (!Tlv.find(data, off, len, EmrtdTags.DO_KEY_REFERENCE, FIND)
                || FIND[1] < 1 || FIND[1] != importedRefLength
                || Util.arrayCompare(data, FIND[0], importedRef, (short) 0, FIND[1]) != 0) {
            ISOException.throwIt(IsoStatus.SW_REFERENCED_DATA_NOT_FOUND);
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
        short expected = importedKind == TaKeys.KIND_EC ? ECDSA_SIGNATURE_LENGTH : importedKeyLength;
        if (len != expected) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Build ID_IC || rIC || Comp(PKDH,IFD) into the staging buffer; the
        // imported key is verified straight from importedKey/importedExp, so the
        // message does not overlap the key material.
        Util.arrayCopyNonAtomic(idIc, (short) 0, stagingKey, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(challenge, (short) 0, stagingKey, (short) 32, (short) 8);
        Util.arrayCopyNonAtomic(caKeyHash, (short) 0, stagingKey, (short) 40, (short) 32);
        boolean ok = TaKeys.verifyKey(importedKind, importedKey, importedKeyLength,
                importedExp, importedExpLength,
                stagingKey, (short) 0, (short) 72, data, off, len);
        challengeValid = false;
        terminalSelected = false;
        if (!ok) {
            ISOException.throwIt(IsoStatus.SW_AUTHENTICATION_FAILED);
        }
        taDone = true;
    }

    /**
     * Loads the key referenced by the pending MSE:Set DST into the verification
     * staging ({@link #stagingKey}/{@link #stagingExp}/...), or returns false (6A88).  A
     * trust point whose Effective Date has not been reached is not selectable
     * (BSI TR-03110-3 §2.5.1).  Sets the issuer role.
     */
    private static boolean resolveDstKey() {
        for (short i = 0; i < TaTrustStore.SLOTS; i++) {
            if (TaTrustStore.trustKind[i] == TaKeys.KIND_NONE || !TaTrustStore.slotEffective(i)) {
                continue;
            }
            if (dstRefLength == TaTrustStore.trustRefLength[i]
                    && Util.arrayCompare(dstRef, (short) 0, TaTrustStore.trustRef,
                            (short) (i * TaTrustStore.REFERENCE_LENGTH), dstRefLength) == 0) {
                dstIssuerRole = ROLE_CVCA;
                loadVerificationKey(TaTrustStore.trustKind[i], TaTrustStore.trustKey, (short) (i * TaKeys.MAX_MODULUS),
                        TaTrustStore.trustKeyLength[i], TaTrustStore.trustExp, (short) (i * TaKeys.MAX_EXPONENT),
                        TaTrustStore.trustExpLength[i]);
                return true;
            }
        }
        if (importedValid && dstRefLength == importedRefLength
                && Util.arrayCompare(dstRef, (short) 0, importedRef, (short) 0, dstRefLength) == 0) {
            dstIssuerRole = importedRole;
            loadVerificationKey(importedKind, importedKey, (short) 0, importedKeyLength,
                    importedExp, (short) 0, importedExpLength);
            return true;
        }
        return false;
    }

    private static void loadVerificationKey(byte kind, byte[] key, short keyOff, short keyLen,
                                            byte[] exp, short expOff, short expLen) {
        stagingKind = kind;
        stagingKeyLength = keyLen;
        stagingExpLength = expLen;
        Util.arrayCopyNonAtomic(key, keyOff, stagingKey, (short) 0, keyLen);
        if (expLen > 0) {
            Util.arrayCopyNonAtomic(exp, expOff, stagingExp, (short) 0, expLen);
        }
    }

    /**
     * Parses the certificate body, enforces the validity period and imports the
     * key (BSI TR-03110-3 §2.5.2): a CVCA Link Certificate updates the trust
     * set; a non-CVCA-Link certificate whose expiration date is before the
     * current date fails; the current date is advanced to the Effective Date for
     * CVCA/DV and for accurate (domestic-DV-issued) terminal certificates.
     */
    private void importCertificate(byte[] data, short off, short len, byte issuerRole) {
        short p = off;
        short end = (short) (off + len);
        boolean chrFound = false;
        short chrOff = 0;
        short chrLength = 0;
        boolean keyFound = false;
        byte role = ROLE_IS;
        short effectiveOff = 0;
        boolean effectiveFound = false;
        short expirationOff = 0;
        boolean expirationFound = false;

        Util.arrayFillNonAtomic(certAuth, (short) 0, (short) 4, (byte) 0xFF);

        while (p < end) {
            short total = Tlv.totalLength(data, p);
            if (total <= 0 || (short) (p + total) > end) {
                break;
            }
            short tag = Tlv.getTag(data, p);
            short valueOff = Tlv.valueOffset(data, p);
            short valueLength = Tlv.getLength(data, Tlv.lengthOffset(data, p));
            if (tag == EmrtdTags.TAG_TA_PUBLIC_KEY) {
                keyFound = parsePublicKey(data, valueOff, valueLength);
            } else if (tag == EmrtdTags.TAG_TA_CHR) {
                if (valueLength > TaTrustStore.REFERENCE_LENGTH) {
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
        // A certificate body must carry a public key (7F49) and a Certificate
        // Holder Reference (5F20) (BSI TR-03110-3 C.1.2.2 / §2.5.2).
        if (!keyFound || !chrFound) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Expiry: CVCA Link Certificates are exempt; every other certificate
        // must not have expired relative to the ICC current date (§2.5.1).
        if (role != ROLE_CVCA && expirationFound && TaTrustStore.currentDateValid
                && TaTrustStore.compare(TaTrustStore.currentDate, data, expirationOff) > 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        if (role == ROLE_CVCA) {
            // A CVCA Link Certificate: add/replace a CVCA trust-point slot.
            TaTrustStore.storeTrustPoint(data, chrOff, chrLength, stagingKey, stagingKeyLength, stagingKind,
                    stagingExp, stagingExpLength, data, effectiveOff, effectiveFound,
                    certAuth, (short) 0);
        } else {
            Util.arrayCopyNonAtomic(stagingKey, (short) 0, importedKey, (short) 0, stagingKeyLength);
            Util.arrayCopyNonAtomic(stagingExp, (short) 0, importedExp, (short) 0, stagingExpLength);
            importedKind = stagingKind;
            importedKeyLength = stagingKeyLength;
            importedExpLength = stagingExpLength;
            Util.arrayCopyNonAtomic(data, chrOff, importedRef, (short) 0, chrLength);
            importedRefLength = chrLength;
            importedRole = role;
            importedValid = true;
            // Fold the DV/IS relative authorization into the session authorization.
            for (short i = 0; i < 4; i++) {
                TaTrustStore.effectiveAuth[i] = (byte) (TaTrustStore.effectiveAuth[i] & certAuth[i]);
            }
        }

        // Advance the current date (§2.5.2 step i).
        if (effectiveFound && advancesDate(role, issuerRole)) {
            if (!TaTrustStore.currentDateValid || TaTrustStore.compare(TaTrustStore.currentDate, data, effectiveOff) < 0) {
                Util.arrayCopyNonAtomic(data, effectiveOff, TaTrustStore.currentDate, (short) 0, (short) 6);
                TaTrustStore.currentDateValid = true;
            }
        }
    }

    /**
     * Parses the {@code 7F49} public key into the staging buffers.  Supports the
     * ECDSA-SHA-256 (tag 86 point) and RSA-PSS-SHA-256 (tags 81 modulus, 82
     * exponent) profiles (BSI TR-03110-3 C.1.2.2).  Returns false when no
     * usable key is present.
     */
    private boolean parsePublicKey(byte[] data, short off, short len) {
        short p = off;
        short end = (short) (off + len);
        boolean rsaOid = false;
        boolean ecPointFound = false;
        short modOff = 0;
        short modLen = 0;
        short expOff = 0;
        short expLen = 0;
        while (p < end) {
            short total = Tlv.totalLength(data, p);
            if (total <= 0 || (short) (p + total) > end) {
                break;
            }
            short tag = Tlv.getTag(data, p);
            short valueOff = Tlv.valueOffset(data, p);
            short valueLength = Tlv.getLength(data, Tlv.lengthOffset(data, p));
            if (tag == EmrtdTags.TAG_TA_OID) {
                rsaOid = matches(data, valueOff, valueLength, OID_TA_RSA_PSS_SHA_256);
            } else if (tag == EmrtdTags.TAG_TA_EC_POINT) {
                if (valueLength == TaKeys.EC_KEY_LENGTH) {
                    Util.arrayCopyNonAtomic(data, valueOff, stagingKey, (short) 0, TaKeys.EC_KEY_LENGTH);
                    stagingKeyLength = TaKeys.EC_KEY_LENGTH;
                    stagingExpLength = 0;
                    stagingKind = TaKeys.KIND_EC;
                    ecPointFound = true;
                }
            } else if (tag == EmrtdTags.TAG_TA_RSA_MODULUS) {
                modOff = valueOff;
                modLen = valueLength;
            } else if (tag == EmrtdTags.TAG_TA_RSA_EXPONENT) {
                expOff = valueOff;
                expLen = valueLength;
            }
            p = (short) (p + total);
        }
        if (rsaOid) {
            if (modLen < 1 || modLen > TaKeys.MAX_MODULUS || expLen < 1 || expLen > TaKeys.MAX_EXPONENT) {
                return false;
            }
            Util.arrayCopyNonAtomic(data, modOff, stagingKey, (short) 0, modLen);
            Util.arrayCopyNonAtomic(data, expOff, stagingExp, (short) 0, expLen);
            stagingKeyLength = modLen;
            stagingExpLength = expLen;
            stagingKind = TaKeys.KIND_RSA;
            return true;
        }
        return ecPointFound;
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

    /** ANDs the CHAT relative authorization and returns the certificate-holder role. */
    private byte andChat(byte[] data, short off, short len) {
        if (Tlv.find(data, off, len, EmrtdTags.TAG_TA_DISCRETIONARY, FIND)
                && FIND[1] >= 1) {
            byte chat = data[FIND[0]];
            // The ePassport relative authorization is bits b2/b1; the role sits
            // in b8/b7 (BSI TR-03110-4 §2.1.3.2).
            certAuth[0] = (byte) (certAuth[0] & (chat & 0x03));
            return roleOf(chat);
        }
        return ROLE_IS;
    }

    /** ANDs each application authorization extension into the certificate authorization. */
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
            certAuth[index] = (byte) (certAuth[index] & data[bitsOff]);
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
    // --- Trust store / authorization facade (TaTrustStore owns the state) ----

    /** True once at least one CVCA trust point has been personalized. */
    public boolean hasTrustPoint() {
        return TaTrustStore.hasTrustPoint();
    }

    /** Effective authorization byte for an application index (0 epassport, 1..3). */
    public byte authorization(short application) {
        return TaTrustStore.authorization(application);
    }

    /** EF.CVCA content (ICAO Doc 9303-11 Annex K.2). */
    public short cvca(byte[] out, short off) {
        return TaTrustStore.cvca(out, off);
    }

    /** Context CAR data objects 87/88 for PACE (ICAO Doc 9303-11 §4.4.5). */
    public short appendCars(byte[] out, short off) {
        return TaTrustStore.appendCars(out, off);
    }

    /** Personalization (DGI FF07): the primary EC CVCA trust point. */
    public void setTrustPoint(byte[] src, short off, short len) {
        TaTrustStore.setTrustPoint(src, off, len);
    }

    /** Personalization (DGI FF09): the secondary EC CVCA trust point. */
    public void setTrustPointSecondary(byte[] src, short off, short len) {
        TaTrustStore.setTrustPointSecondary(src, off, len);
    }

    /** Personalization (DGI FF0B/FF0C): an RSA CVCA trust point. */
    public void setTrustPointRsa(byte[] src, short off, short len, short slot) {
        TaTrustStore.setTrustPointRsa(src, off, len, slot);
    }

    /** Personalization (DGI FF08): the ICC current date (6 octets BCD YYMMDD). */
    public void setCurrentDate(byte[] src, short off, short len) {
        TaTrustStore.setCurrentDate(src, off, len);
    }

}
