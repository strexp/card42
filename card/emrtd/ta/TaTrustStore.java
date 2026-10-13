package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* Card-side Terminal Authentication trust store and authorization (ICAO
 * Doc 9303-11 §7.1, BSI TR-03110-3 §2.5, A.7): the CVCA trust point(s), their
 * Effective Dates, the ICC current date and the session authorization folded
 * from the verified certificate chain, plus the CAR/CVCA response building.
 *
 * It owns no per-session protocol state and holds no instance fields: like the
 * former TaContext fields, every buffer is package-shared static so a card with
 * several eMRTD instances keeps a single key set and one current date
 * (docs/specs/common/risks.md §2).  Splitting it out of TaContext is therefore
 * heap-neutral.
 *
 * Up to two CVCA trust points are kept (BSI TR-03110-3 §2.5.1): the initial
 * one(s) from personalization (DGI FF07 / FF09 / FF0B / FF0C) and any CVCA Link
 * Certificate imported at run time.  A trust point only verifies certificates
 * once its Effective Date has been reached; the newest effective one seeds the
 * authorization.
 *
 * @author card42
 */

final class TaTrustStore {

    /** Number of CVCA trust-point slots (BSI TR-03110-3 §2.5.1). */
    static final short SLOTS = (short) 2;
    /** Certificate-holder reference length. */
    static final short REFERENCE_LENGTH = (short) 16;

    /*
     * CVCA trust points, up to two slots.  Each slot holds the key material
     * (EC point or RSA modulus+exponent), the holder reference, the Effective
     * Date and the relative authorization.
     */
    static final byte[] trustKind = new byte[SLOTS];
    static final byte[] trustKey = new byte[(short) (SLOTS * TaKeys.MAX_MODULUS)];
    static final byte[] trustExp = new byte[(short) (SLOTS * TaKeys.MAX_EXPONENT)];
    static final short[] trustKeyLength = new short[SLOTS];
    static final short[] trustExpLength = new short[SLOTS];
    static final byte[] trustRef = new byte[(short) (SLOTS * REFERENCE_LENGTH)];
    static final short[] trustRefLength = new short[SLOTS];
    static final byte[] trustEffective = new byte[(short) (SLOTS * 6)];
    static final byte[] trustEffectiveValid = new byte[SLOTS];
    static final byte[] trustAuth = new byte[(short) (SLOTS * 4)];

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

    private TaTrustStore() {
    }

    /** Seeds the session authorization from the active CVCA trust point. */
    static void seedAuthorization() {
        short active = activeTrustPoint();
        if (active >= 0) {
            Util.arrayCopyNonAtomic(trustAuth, (short) (active * 4), effectiveAuth,
                    (short) 0, (short) 4);
        } else {
            Util.arrayFillNonAtomic(effectiveAuth, (short) 0, (short) 4, (byte) 0);
        }
    }

    /** Effective authorization byte for an application index (0 epassport, 1..3). */
    static byte authorization(short application) {
        return effectiveAuth[application];
    }

    /** True once at least one CVCA trust point has been personalized. */
    static boolean hasTrustPoint() {
        return trustKind[0] != TaKeys.KIND_NONE || trustKind[1] != TaKeys.KIND_NONE;
    }

    /**
     * EF.CVCA content (ICAO Doc 9303-11 Annex K.2): the Certification Authority
     * Reference data objects of the trust points, most recent Effective Date
     * first, padded with 0x00 to the fixed 36-octet size.  Computed on read so a
     * runtime CVCA Link Certificate is reflected without extra state.
     */
    static short cvca(byte[] out, short off) {
        short first = (short) -1;
        short second = (short) -1;
        for (short i = 0; i < SLOTS; i++) {
            if (trustKind[i] == TaKeys.KIND_NONE) {
                continue;
            }
            if (first < 0) {
                first = i;
            } else if (effectiveAfter(i, first)) {
                second = first;
                first = i;
            } else {
                second = i;
            }
        }
        short n = writeCar(out, off, first);
        n = (short) (n + writeCar(out, (short) (off + n), second));
        for (short i = n; i < (short) 36; i++) {
            out[(short) (off + i)] = 0;
        }
        return (short) 36;
    }

    /** Writes one CAR data object {@code 42 <len> <CAR>}; 0 for an empty slot. */
    private static short writeCar(byte[] out, short off, short slot) {
        if (slot < 0 || trustKind[slot] == TaKeys.KIND_NONE) {
            return 0;
        }
        out[off] = 0x42;
        out[(short) (off + 1)] = (byte) trustRefLength[slot];
        Util.arrayCopyNonAtomic(trustRef, (short) (slot * REFERENCE_LENGTH),
                out, (short) (off + 2), trustRefLength[slot]);
        return (short) (2 + trustRefLength[slot]);
    }

    /**
     * Appends the Certification Authority References requested during PACE as
     * context data objects {@code 87} (most recent) and {@code 88} (previous)
     * (ICAO Doc 9303-11 §4.4.5).  Returns the new offset; nothing is appended
     * when no trust point is personalized.
     */
    static short appendCars(byte[] out, short off) {
        short first = (short) -1;
        short second = (short) -1;
        for (short i = 0; i < SLOTS; i++) {
            if (trustKind[i] == TaKeys.KIND_NONE) {
                continue;
            }
            if (first < 0) {
                first = i;
            } else if (effectiveAfter(i, first)) {
                second = first;
                first = i;
            } else {
                second = i;
            }
        }
        off = appendCar(out, off, (byte) 0x87, first);
        off = appendCar(out, off, (byte) 0x88, second);
        return off;
    }

    private static short appendCar(byte[] out, short off, byte tag, short slot) {
        if (slot < 0 || trustKind[slot] == TaKeys.KIND_NONE) {
            return off;
        }
        out[off] = tag;
        out[(short) (off + 1)] = (byte) trustRefLength[slot];
        Util.arrayCopyNonAtomic(trustRef, (short) (slot * REFERENCE_LENGTH),
                out, (short) (off + 2), trustRefLength[slot]);
        return (short) (off + 2 + trustRefLength[slot]);
    }

    /**
     * The slot of the CVCA key currently valid for verification: the valid slot
     * with the most recent Effective Date that has been reached (BSI
     * TR-03110-3 §2.5.1).  -1 when none is usable.
     */
    static short activeTrustPoint() {
        short best = -1;
        for (short i = 0; i < SLOTS; i++) {
            if (trustKind[i] == TaKeys.KIND_NONE || !slotEffective(i)) {
                continue;
            }
            if (best < 0 || effectiveAfter(i, best)) {
                best = i;
            }
        }
        return best;
    }

    /** True when slot i's Effective Date has been reached (or is absent). */
    static boolean slotEffective(short slot) {
        if (!currentDateValid || trustEffectiveValid[slot] == 0) {
            return true;
        }
        return compare(currentDate, trustEffective, (short) (slot * 6)) >= 0;
    }

    /** True when slot a has a later Effective Date than slot b (absent = earliest). */
    static boolean effectiveAfter(short a, short b) {
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
     * || [effective(6)] || [auth(4)]} for the primary CVCA public key.  The
     * Effective Date and the relative authorization are optional (the legacy
     * form carries only the authorization); the Effective Date drives trust-point
     * selection (ICAO Doc 9303-11 §7.1.4.3.1).
     */
    static void setTrustPoint(byte[] src, short off, short len) {
        setTrustPoint(src, off, len, (short) 0);
    }

    /** Personalization (DGI FF09): the secondary CVCA trust point. */
    static void setTrustPointSecondary(byte[] src, short off, short len) {
        setTrustPoint(src, off, len, (short) 1);
    }

    private static void setTrustPoint(byte[] src, short off, short len, short slot) {
        if (len < (short) (TaKeys.EC_KEY_LENGTH + 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short refLen = (short) (src[(short) (off + TaKeys.EC_KEY_LENGTH)] & 0xFF);
        short base = (short) (TaKeys.EC_KEY_LENGTH + 1 + refLen);
        if (refLen < 1 || refLen > REFERENCE_LENGTH || (short) (off + base) > (short) (off + len)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(src, off, trustKey, (short) (slot * TaKeys.MAX_MODULUS),
                TaKeys.EC_KEY_LENGTH);
        trustKind[slot] = TaKeys.KIND_EC;
        trustKeyLength[slot] = TaKeys.EC_KEY_LENGTH;
        trustExpLength[slot] = 0;
        Util.arrayCopyNonAtomic(src, (short) (off + TaKeys.EC_KEY_LENGTH + 1),
                trustRef, (short) (slot * REFERENCE_LENGTH), refLen);
        trustRefLength[slot] = refLen;
        trustEffectiveValid[slot] = 0;
        Util.arrayFillNonAtomic(trustAuth, (short) (slot * 4), (short) 4, (byte) 0);
        parseTrustPointTail(src, off, len, (short) (off + base), slot);
        seedAuthorization();
    }

    /**
     * Personalization (DGI FF0B/FF0C): an RSA CVCA trust point
     * {@code modLen(2) || modulus || expLen(2) || exponent || refLen(1) || CAR
     * || [effective(6)] || [auth(4)]} (BSI TR-03110-3 C.1.2.2).  The card
     * verifies RSA-PSS-SHA-256 certificates against it.
     */
    static void setTrustPointRsa(byte[] src, short off, short len, short slot) {
        if (len < (short) 5) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short modLen = Util.getShort(src, off);
        short expLenOff = (short) (off + 2 + modLen);
        if (modLen < 1 || modLen > TaKeys.MAX_MODULUS
                || (short) (expLenOff + 2) > (short) (off + len)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short expLen = Util.getShort(src, expLenOff);
        short expOff = (short) (expLenOff + 2);
        short refLenOff = (short) (expOff + expLen);
        if (expLen < 1 || expLen > TaKeys.MAX_EXPONENT
                || (short) (refLenOff + 1) > (short) (off + len)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short refLen = (short) (src[refLenOff] & 0xFF);
        short base = (short) (refLenOff + 1 + refLen - off);
        if (refLen < 1 || refLen > REFERENCE_LENGTH || (short) (off + base) > (short) (off + len)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(src, (short) (off + 2), trustKey,
                (short) (slot * TaKeys.MAX_MODULUS), modLen);
        Util.arrayCopyNonAtomic(src, expOff, trustExp,
                (short) (slot * TaKeys.MAX_EXPONENT), expLen);
        trustKind[slot] = TaKeys.KIND_RSA;
        trustKeyLength[slot] = modLen;
        trustExpLength[slot] = expLen;
        Util.arrayCopyNonAtomic(src, (short) (refLenOff + 1), trustRef,
                (short) (slot * REFERENCE_LENGTH), refLen);
        trustRefLength[slot] = refLen;
        trustEffectiveValid[slot] = 0;
        Util.arrayFillNonAtomic(trustAuth, (short) (slot * 4), (short) 4, (byte) 0);
        parseTrustPointTail(src, off, len, (short) (off + base), slot);
        seedAuthorization();
    }

    /**
     * Parses the optional {@code [effective(6)] [auth(4)]} tail shared by the EC
     * (FF07/FF09) and RSA (FF0B/FF0C) trust-point layouts.
     */
    private static void parseTrustPointTail(byte[] src, short off, short len, short p, short slot) {
        short rest = (short) ((short) (off + len) - p);
        if (rest >= (short) 6) {
            // The Effective Date is 6 octets unpacked BCD YYMMDD
            // (BSI TR-03110-3 §2.5.1).
            for (short i = 0; i < 6; i++) {
                if (src[(short) (p + i)] > 9) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
            }
            Util.arrayCopyNonAtomic(src, p, trustEffective, (short) (slot * 6), (short) 6);
            trustEffectiveValid[slot] = (byte) 1;
            p += 6;
            rest -= 6;
        }
        if (rest >= (short) 4) {
            Util.arrayCopyNonAtomic(src, p, trustAuth, (short) (slot * 4), (short) 4);
        }
    }

    /**
     * Stores a CVCA public key (from a CVCA Link Certificate verified at run
     * time) in the trust-point set, replacing the same reference or the oldest
     * slot (BSI TR-03110-3 §2.5.1).  Authenticity has already been verified.
     */
    static void storeTrustPoint(byte[] ref, short refOff, short refLen,
                                byte[] key, short keyLen, byte kind,
                                byte[] exp, short expLen,
                                byte[] effective, short effOff, boolean effValid,
                                byte[] auth, short authOff) {
        if (refLen < 1 || refLen > REFERENCE_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short slot = -1;
        for (short i = 0; i < SLOTS && slot < 0; i++) {
            if (trustKind[i] != TaKeys.KIND_NONE && trustRefLength[i] == refLen
                    && Util.arrayCompare(trustRef, (short) (i * REFERENCE_LENGTH),
                            ref, refOff, refLen) == 0) {
                slot = i;
            }
        }
        if (slot < 0) {
            for (short i = 0; i < SLOTS && slot < 0; i++) {
                if (trustKind[i] == TaKeys.KIND_NONE) {
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
                (short) (slot * TaKeys.MAX_MODULUS), keyLen);
        trustExpLength[slot] = expLen;
        if (expLen > 0) {
            Util.arrayCopyNonAtomic(exp, (short) 0, trustExp,
                    (short) (slot * TaKeys.MAX_EXPONENT), expLen);
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
     * YYMMDD (BSI TR-03110-3 §2.5.1).  A card without it skips the expiration
     * check but still advances from the first certificate it verifies.
     */
    static void setCurrentDate(byte[] src, short off, short len) {
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

    /** Compares the 6-octet BCD date at currentDate with the one at data[off]. */
    static short compare(byte[] current, byte[] data, short off) {
        for (short i = 0; i < 6; i++) {
            short a = (short) (current[i] & 0xFF);
            short b = (short) (data[(short) (off + i)] & 0xFF);
            if (a != b) {
                return a < b ? (short) -1 : (short) 1;
            }
        }
        return 0;
    }

    /** Compares two 6-octet BCD dates at the given offsets of the given arrays. */
    static short compare(byte[] buf, short offA, byte[] other, short offB) {
        for (short i = 0; i < 6; i++) {
            short a = (short) (buf[(short) (offA + i)] & 0xFF);
            short b = (short) (other[(short) (offB + i)] & 0xFF);
            if (a != b) {
                return a < b ? (short) -1 : (short) 1;
            }
        }
        return 0;
    }
}
