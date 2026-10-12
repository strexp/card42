package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import card42.common.Tlv;

/* Card-side Terminal Authentication state (ICAO Doc 9303-11 §7.1, BSI
 * TR-03110-3 A.7): the CVCA trust point(s), the certificate chain verification
 * (MSE:Set DST + PSO:Verify Certificate) and the terminal key import.
 *
 * The TAv2 terminal-signature/certificate algorithm is selected per
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

    private static final short EC_KEY_LENGTH = (short) 65;
    private static final short MAX_MODULUS = (short) 256;   // RSA-2048
    private static final short MAX_EXPONENT = (short) 8;
    private static final short REFERENCE_LENGTH = (short) 16;
    private static final short SLOTS = (short) 2;

    private static final byte KIND_NONE = 0;
    private static final byte KIND_EC = 1;
    private static final byte KIND_RSA = 2;

    /** ECDSA P-256 plain signature length. */
    private static final short ECDSA_SIGNATURE_LENGTH = (short) 64;

    /** Reused TLV search result; a per-command array would leak persistent memory. */
    private static final short[] FIND = new short[2];

    /*
     * CVCA trust points, up to two slots (BSI TR-03110-3 §2.5.1).  Each slot
     * holds the key material (EC point or RSA modulus+exponent), the holder
     * reference, the Effective Date and the relative authorization.
     */
    static final byte[] trustKind = new byte[SLOTS];
    static final byte[] trustKey = new byte[(short) (SLOTS * MAX_MODULUS)];
    static final byte[] trustExp = new byte[(short) (SLOTS * MAX_EXPONENT)];
    static final short[] trustKeyLength = new short[SLOTS];
    static final short[] trustExpLength = new short[SLOTS];
    static final byte[] trustRef = new byte[(short) (SLOTS * REFERENCE_LENGTH)];
    static final short[] trustRefLength = new short[SLOTS];
    static final byte[] trustEffective = new byte[(short) (SLOTS * 6)];
    static final byte[] trustEffectiveValid = new byte[SLOTS];
    static final byte[] trustAuth = new byte[(short) (SLOTS * 4)];

    /** The most recently verified certificate's public key (session). */
    static final byte[] importedKey = new byte[MAX_MODULUS];
    static final byte[] importedExp = new byte[MAX_EXPONENT];
    static short importedKeyLength;
    static short importedExpLength;
    static byte importedKind;
    static final byte[] importedRef = new byte[REFERENCE_LENGTH];
    static short importedRefLength;
    static boolean importedValid;

    /** The reference set by MSE:Set DST (session). */
    static final byte[] dstRef = new byte[REFERENCE_LENGTH];
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

    /** Session effective authorization: active trust point AND each verified certificate. */
    static final byte[] effectiveAuth = new byte[4];

    /**
     * The ICC's approximated current date (BSI TR-03110-3 §2.5): 6 octets,
     * unpacked BCD YYMMDD.  Set to the personalization date (DGI FF08) and only
     * ever advanced to the most recent valid CVCA/DV/Accurate-Terminal Effective
     * Date; it selects the active CVCA key and rejects expired certificates.
     */
    static final byte[] currentDate = new byte[6];
    static boolean currentDateValid;
    /** Role of the certificate whose public key is the current DST target. */
    private static byte dstIssuerRole;
    /** Role of the most recently imported certificate. */
    private static byte importedRole;

    /* Staging for the key currently being parsed and the key selected by DST. */
    private static final byte[] pkKey = new byte[MAX_MODULUS];
    private static final byte[] pkExp = new byte[MAX_EXPONENT];
    private static short pkKeyLength;
    private static short pkExpLength;
    private static byte pkKind;
    private static final byte[] vKey = new byte[MAX_MODULUS];
    private static final byte[] vExp = new byte[MAX_EXPONENT];
    private static short vKeyLength;
    private static short vExpLength;
    private static byte vKind;

    /** Staging for the certificate's own relative authorization (4 bytes). */
    private static final byte[] certAuth = new byte[4];

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

    /* Terminal-key algorithm OIDs (BSI TR-03110-3 Table 27). */
    private static final byte[] OID_TA_ECDSA_SHA_256 = {
        0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03 };
    private static final byte[] OID_TA_RSA_PSS_SHA_256 = {
        0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x04 };

    /** ID_IC || rIC || Comp(PKDH,IFD) (32 + 8 + 32). */
    private static final byte[] signatureInput = new byte[72];

    private static ECPublicKey ecKey;
    private static RSAPublicKey rsaKey1024;
    private static RSAPublicKey rsaKey2048;
    private static Signature ecSig;
    private static Signature rsaSig;

    public TaContext() {
    }

    /** Clears the per-session state (called on selection). */
    public void clearSession() {
        importedValid = false;
        importedRefLength = 0;
        importedKind = KIND_NONE;
        importedKeyLength = 0;
        dstSet = false;
        dstRefLength = 0;
        challengeValid = false;
        taDone = false;
        terminalSelected = false;
        importedRole = ROLE_IS;
        dstIssuerRole = ROLE_IS;
        seedAuthorization();
        Util.arrayFillNonAtomic(idIc, (short) 0, (short) idIc.length, (byte) 0);
        Util.arrayFillNonAtomic(caKeyHash, (short) 0, (short) caKeyHash.length, (byte) 0);
    }

    /** Seeds the session authorization from the active CVCA trust point. */
    private static void seedAuthorization() {
        short active = activeTrustPoint();
        if (active >= 0) {
            Util.arrayCopyNonAtomic(trustAuth, (short) (active * 4), effectiveAuth,
                    (short) 0, (short) 4);
        } else {
            Util.arrayFillNonAtomic(effectiveAuth, (short) 0, (short) 4, (byte) 0);
        }
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

    /** True once at least one CVCA trust point has been personalized. */
    public boolean hasTrustPoint() {
        return trustKind[0] != KIND_NONE || trustKind[1] != KIND_NONE;
    }

    /**
     * The slot of the CVCA key currently valid for verification: the valid slot
     * with the most recent Effective Date that has been reached (BSI
     * TR-03110-3 §2.5.1).  -1 when none is usable.
     */
    private static short activeTrustPoint() {
        short best = -1;
        for (short i = 0; i < SLOTS; i++) {
            if (trustKind[i] == KIND_NONE || !slotEffective(i)) {
                continue;
            }
            if (best < 0 || effectiveAfter(i, best)) {
                best = i;
            }
        }
        return best;
    }

    /** True when slot i's Effective Date has been reached (or is absent). */
    private static boolean slotEffective(short slot) {
        if (!currentDateValid || trustEffectiveValid[slot] == 0) {
            return true;
        }
        return compare(currentDate, trustEffective, (short) (slot * 6)) >= 0;
    }

    /** True when slot a has a later Effective Date than slot b (absent = earliest). */
    private static boolean effectiveAfter(short a, short b) {
        if (trustEffectiveValid[a] == 0) {
            return false;
        }
        if (trustEffectiveValid[b] == 0) {
            return true;
        }
        return compare(trustEffective, (short) (a * 6), trustEffective, (short) (b * 6)) > 0;
    }

    /**
     * Personalization (DGI FF07): {@code W(65) || refLen(1) || CAR(refLen)
     * || [auth(4)]} for the primary CVCA public key (B3DES or RSA).
     */
    public void setTrustPoint(byte[] src, short off, short len) {
        setTrustPoint(src, off, len, (short) 0);
    }

    /** Personalization (DGI FF09): the secondary CVCA trust point. */
    public void setTrustPointSecondary(byte[] src, short off, short len) {
        setTrustPoint(src, off, len, (short) 1);
    }

    private void setTrustPoint(byte[] src, short off, short len, short slot) {
        // FF07/FF09 carry an EC trust point: W(65) || refLen || CAR || [auth(4)].
        if (len < (short) (EC_KEY_LENGTH + 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short refLen = (short) (src[(short) (off + EC_KEY_LENGTH)] & 0xFF);
        if (refLen < 1 || refLen > REFERENCE_LENGTH
                || (short) (EC_KEY_LENGTH + 1 + refLen) > len) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        ensureKeys();
        Util.arrayCopyNonAtomic(src, off, trustKey, (short) (slot * MAX_MODULUS), EC_KEY_LENGTH);
        trustKind[slot] = KIND_EC;
        trustKeyLength[slot] = EC_KEY_LENGTH;
        trustExpLength[slot] = 0;
        Util.arrayCopyNonAtomic(src, (short) (off + EC_KEY_LENGTH + 1),
                trustRef, (short) (slot * REFERENCE_LENGTH), refLen);
        trustRefLength[slot] = refLen;
        trustEffectiveValid[slot] = 0;
        byte[] slotAuth = trustAuth;
        short authBase = (short) (slot * 4);
        Util.arrayFillNonAtomic(slotAuth, authBase, (short) 4, (byte) 0);
        short authOff = (short) (off + EC_KEY_LENGTH + 1 + refLen);
        if ((short) (authOff + 4) <= (short) (off + len)) {
            Util.arrayCopyNonAtomic(src, authOff, slotAuth, authBase, (short) 4);
        }
        seedAuthorization();
    }

    /**
     * Stores a CVCA public key (from a CVCA Link Certificate verified at run
     * time) in the trust-point set, replacing the same reference or the oldest
     * slot (BSI TR-03110-3 §2.5.1).  Authenticity has already been verified.
     */
    private static void storeTrustPoint(byte[] ref, short refOff, short refLen,
                                        byte[] key, short keyLen, byte kind,
                                        byte[] exp, short expLen,
                                        byte[] effective, short effOff, boolean effValid,
                                        byte[] auth, short authOff) {
        if (refLen < 1 || refLen > REFERENCE_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short slot = -1;
        for (short i = 0; i < SLOTS && slot < 0; i++) {
            if (trustKind[i] != KIND_NONE && trustRefLength[i] == refLen
                    && Util.arrayCompare(trustRef, (short) (i * REFERENCE_LENGTH),
                            ref, refOff, refLen) == 0) {
                slot = i;
            }
        }
        if (slot < 0) {
            for (short i = 0; i < SLOTS && slot < 0; i++) {
                if (trustKind[i] == KIND_NONE) {
                    slot = i;
                }
            }
        }
        if (slot < 0) {
            // Both slots full: evict the oldest effective key.
            slot = 0;
            for (short i = 1; i < SLOTS; i++) {
                if (effectiveAfter(slot, i)) {
                    slot = i;
                }
            }
        }
        trustKind[slot] = kind;
        trustKeyLength[slot] = keyLen;
        Util.arrayCopyNonAtomic(key, (short) 0, trustKey,
                (short) (slot * MAX_MODULUS), keyLen);
        trustExpLength[slot] = expLen;
        if (expLen > 0) {
            Util.arrayCopyNonAtomic(exp, (short) 0, trustExp, (short) (slot * MAX_EXPONENT), expLen);
        }
        Util.arrayCopyNonAtomic(ref, refOff, trustRef, (short) (slot * REFERENCE_LENGTH), refLen);
        trustRefLength[slot] = refLen;
        trustEffectiveValid[slot] = effValid ? (byte) 1 : (byte) 0;
        if (effValid) {
            Util.arrayCopyNonAtomic(effective, effOff, trustEffective,
                    (short) (slot * 6), (short) 6);
        }
        Util.arrayCopyNonAtomic(auth, authOff, trustAuth, (short) (slot * 4), (short) 4);
        seedAuthorization();
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
            ISOException.throwIt((short) 0x6A88); // referenced data not found
        }
        short expected = vKind == KIND_EC ? ECDSA_SIGNATURE_LENGTH : vKeyLength;
        if (signatureLength != expected) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (!verify(data, bodyStart, bodyTotal, data, signatureOffset, signatureLength)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        importCertificate(data, bodyValueOffset, bodyValueLength, dstIssuerRole);
        dstSet = false;
    }

    /** Records ID_IC = Comp(PKDH,IC) from an uncompressed PICC ephemeral point. */
    public void notePiccEphemeral(byte[] uncompressedW, short off, short len) {
        if (len == EC_KEY_LENGTH && uncompressedW[off] == (byte) 0x04) {
            Util.arrayCopyNonAtomic(uncompressedW, (short) (off + 1), idIc, (short) 0, (short) 32);
        }
    }

    /** Records Comp(PKDH,IFD) from an uncompressed terminal ephemeral point. */
    public void noteTerminalEphemeral(byte[] uncompressedW, short off, short len) {
        if (len == EC_KEY_LENGTH && uncompressedW[off] == (byte) 0x04) {
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
        short expected = importedKind == KIND_EC ? ECDSA_SIGNATURE_LENGTH : importedKeyLength;
        if (len != expected) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(idIc, (short) 0, signatureInput, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(challenge, (short) 0, signatureInput, (short) 32, (short) 8);
        Util.arrayCopyNonAtomic(caKeyHash, (short) 0, signatureInput, (short) 40, (short) 32);
        // Load the imported key into the staging buffer used by verify().
        Util.arrayCopyNonAtomic(importedKey, (short) 0, vKey, (short) 0, importedKeyLength);
        Util.arrayCopyNonAtomic(importedExp, (short) 0, vExp, (short) 0, importedExpLength);
        vKeyLength = importedKeyLength;
        vExpLength = importedExpLength;
        vKind = importedKind;
        boolean ok = verify(signatureInput, (short) 0, (short) 72, data, off, len);
        challengeValid = false;
        terminalSelected = false;
        if (!ok) {
            ISOException.throwIt((short) 0x6300); // warning: signature verification failed
        }
        taDone = true;
    }

    /**
     * Loads the key referenced by the pending MSE:Set DST into the verification
     * staging ({@link #vKey}/{@link #vExp}/...), or returns false (6A88).  A
     * trust point whose Effective Date has not been reached is not selectable
     * (BSI TR-03110-3 §2.5.1).  Sets the issuer role.
     */
    private static boolean resolveDstKey() {
        for (short i = 0; i < SLOTS; i++) {
            if (trustKind[i] == KIND_NONE || !slotEffective(i)) {
                continue;
            }
            if (dstRefLength == trustRefLength[i]
                    && Util.arrayCompare(dstRef, (short) 0, trustRef,
                            (short) (i * REFERENCE_LENGTH), dstRefLength) == 0) {
                dstIssuerRole = ROLE_CVCA;
                loadVerificationKey(trustKind[i], trustKey, (short) (i * MAX_MODULUS),
                        trustKeyLength[i], trustExp, (short) (i * MAX_EXPONENT),
                        trustExpLength[i]);
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
        vKind = kind;
        vKeyLength = keyLen;
        vExpLength = expLen;
        Util.arrayCopyNonAtomic(key, keyOff, vKey, (short) 0, keyLen);
        if (expLen > 0) {
            Util.arrayCopyNonAtomic(exp, expOff, vExp, (short) 0, expLen);
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
        if (!keyFound || !chrFound) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Expiry: CVCA Link Certificates are exempt; every other certificate
        // must not have expired relative to the ICC current date (§2.5.1).
        if (role != ROLE_CVCA && expirationFound && currentDateValid
                && compare(currentDate, data, expirationOff) > 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        if (role == ROLE_CVCA) {
            // A CVCA Link Certificate: add/replace a CVCA trust-point slot.
            storeTrustPoint(data, chrOff, chrLength, pkKey, pkKeyLength, pkKind,
                    pkExp, pkExpLength, data, effectiveOff, effectiveFound, certAuth, (short) 0);
        } else {
            Util.arrayCopyNonAtomic(pkKey, (short) 0, importedKey, (short) 0, pkKeyLength);
            Util.arrayCopyNonAtomic(pkExp, (short) 0, importedExp, (short) 0, pkExpLength);
            importedKind = pkKind;
            importedKeyLength = pkKeyLength;
            importedExpLength = pkExpLength;
            Util.arrayCopyNonAtomic(data, chrOff, importedRef, (short) 0, chrLength);
            importedRefLength = chrLength;
            importedRole = role;
            importedValid = true;
            // Fold the DV/IS relative authorization into the session authorization.
            for (short i = 0; i < 4; i++) {
                effectiveAuth[i] = (byte) (effectiveAuth[i] & certAuth[i]);
            }
        }

        // Advance the current date (§2.5.2 step i).
        if (effectiveFound && advancesDate(role, issuerRole)) {
            if (!currentDateValid || compare(currentDate, data, effectiveOff) < 0) {
                Util.arrayCopyNonAtomic(data, effectiveOff, currentDate, (short) 0, (short) 6);
                currentDateValid = true;
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
                if (valueLength == EC_KEY_LENGTH) {
                    Util.arrayCopyNonAtomic(data, valueOff, pkKey, (short) 0, EC_KEY_LENGTH);
                    pkKeyLength = EC_KEY_LENGTH;
                    pkExpLength = 0;
                    pkKind = KIND_EC;
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
            if (modLen < 1 || modLen > MAX_MODULUS || expLen < 1 || expLen > MAX_EXPONENT) {
                return false;
            }
            Util.arrayCopyNonAtomic(data, modOff, pkKey, (short) 0, modLen);
            Util.arrayCopyNonAtomic(data, expOff, pkExp, (short) 0, expLen);
            pkKeyLength = modLen;
            pkExpLength = expLen;
            pkKind = KIND_RSA;
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

    /** Compares two 6-octet BCD dates at the given offsets of the same array. */
    private static short compare(byte[] buf, short offA, byte[] other, short offB) {
        for (short i = 0; i < 6; i++) {
            short a = (short) (buf[(short) (offA + i)] & 0xFF);
            short b = (short) (other[(short) (offB + i)] & 0xFF);
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

    /** ANDs the CHAT relative authorization and returns the certificate-holder role. */
    private byte andChat(byte[] data, short off, short len) {
        if (Lds2Record.find(data, off, len, EmrtdTags.TAG_TA_DISCRETIONARY, FIND)
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

    /**
     * Builds the shared verification keys and Signatures once, at first use
     * (personalization, so no persistent allocation happens on a command path).
     * Failures are left to the platform: a card without the algorithm simply
     * cannot verify that profile.
     */
    static void ensureKeys() {
        if (ecKey == null) {
            ecKey = (ECPublicKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            P256.setCurve(ecKey);
            ecSig = Signature.getInstance(MessageDigest.ALG_SHA_256,
                    Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false);
        }
    }

    private static void ensureRsa() {
        if (rsaKey2048 == null) {
            rsaKey1024 = (RSAPublicKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
            rsaKey2048 = (RSAPublicKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
            rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_256_PKCS1_PSS, false);
        }
    }

    /**
     * Verifies {@code message} against the resolved key with the algorithm
     * selected by the key kind (ECDSA-SHA-256 plain, RSA-PSS-SHA-256).
     */
    private static boolean verify(byte[] message, short messageOff, short messageLength,
                                  byte[] signature, short signatureOff, short signatureLength) {
        try {
            if (vKind == KIND_EC) {
                ensureKeys();
                ecKey.setW(vKey, (short) 0, EC_KEY_LENGTH);
                ecSig.init(ecKey, Signature.MODE_VERIFY);
                return ecSig.verify(message, messageOff, messageLength,
                        signature, signatureOff, signatureLength);
            }
            ensureRsa();
            RSAPublicKey key = vKeyLength <= 128 ? rsaKey1024 : rsaKey2048;
            key.setModulus(vKey, (short) 0, vKeyLength);
            key.setExponent(vExp, (short) 0, vExpLength);
            rsaSig.init(key, Signature.MODE_VERIFY);
            return rsaSig.verify(message, messageOff, messageLength,
                    signature, signatureOff, signatureLength);
        } catch (Exception e) {
            return false;
        }
    }
}
