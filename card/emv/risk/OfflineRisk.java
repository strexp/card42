package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/* Card-internal offline velocity checking (EMV v4.4 Book 3 §9.2.3.1/§9.2.3.3,
 * Annex C §C9.3/§C10).
 *
 * card42 implements the CCD card-side accumulators rather than the generic
 * terminal velocity checking: the card keeps
 *
 *   - the number of consecutive transactions approved offline since the last
 *     successful online transaction, and
 *   - the cumulative amount approved offline,
 *
 * bounded by the personalised Lower/Upper Consecutive Offline Limits (LCOL /
 * UCOL, tags 9F14 / 9F23) and the cumulative amount limits (LCOTA / UCOTA, DGI
 * E002).  The limits then change the Card Action Analysis outcome:
 *
 *   - a lower limit exceeded forces the first GENERATE AC online (ARQC);
 *   - an upper limit exceeded, at a terminal that cannot go online, declines
 *     the transaction (AAC) at the second GENERATE AC.
 *
 * On a successful online transaction the accumulators are reset, or updated
 * according to the 'Update Counters' bits of the Card Status Update (CSU) of
 * the Issuer Authentication Data (EMV v4.4 Book 3 Annex C §C10).
 *
 * Design note (EMV v4.4 Book 3 §10.8, Annex C §C9.3): the accumulator state is
 * reflected in CVR byte 3, which the AcProcessor writes into the CCD issuer IAD
 * (bytes 4-8) before every GENERATE AC.  cvrByte3() assembles those bits.
 *
 * @author card42
 */

public class OfflineRisk implements ISO7816 {

    /** Amounts are BCD, 6 bytes (12 digits), as EMV numeric amounts. */
    private static final short AMOUNT_LENGTH = (short) 6;

    private boolean countEnabled;
    private byte lcol;
    private byte ucol;

    private boolean amountEnabled;
    private final byte[] lcota = new byte[AMOUNT_LENGTH];
    private final byte[] ucota = new byte[AMOUNT_LENGTH];

    /** Consecutive offline transactions since the last successful online
     * (EMV v4.4 Book 3 Annex C §C9.3). */
    private short offlineCount;

    /** Cumulative offline amount (BCD, AMOUNT_LENGTH bytes). */
    private final byte[] cumulative = new byte[AMOUNT_LENGTH];

    /** CSU 'Set Go Online on Next Transaction' flag (EMV v4.4 Book 3 Annex C §C9.3). */
    private boolean goOnlineNext;

    /** Stores LCOL/UCOL from the EMV CPS v2.0 Annex A DGI '3001' tags 9F14/9F23. */
    public void setCountLimits(byte lower, byte upper) {
        lcol = lower;
        ucol = upper;
        countEnabled = true;
    }

    /** Stores LCOTA/UCOTA from project DGI 'E002' (BCD, LCOTA || UCOTA). */
    public void setAmountLimits(byte[] buf, short off, short len) {
        if (len != (short) (2 * AMOUNT_LENGTH)) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        // LCOTA/UCOTA are BCD amounts (EMV v4.4 Book 3 Annex C §C9.3): every
        // nibble must be a decimal digit.
        if (!isBcd(buf, off, len)) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        Util.arrayCopyNonAtomic(buf, off, lcota, (short) 0, AMOUNT_LENGTH);
        Util.arrayCopyNonAtomic(buf, (short) (off + AMOUNT_LENGTH), ucota,
                (short) 0, AMOUNT_LENGTH);
        amountEnabled = !isZero(lcota) || !isZero(ucota);
    }

    public boolean isEnabled() {
        return countEnabled || amountEnabled;
    }

    public void setGoOnlineNext() {
        goOnlineNext = true;
    }

    public void clearGoOnlineNext() {
        goOnlineNext = false;
    }

    /** Whether the CSU 'Set Go Online on Next Transaction' flag is set. */
    public boolean isGoOnlineNext() {
        return goOnlineNext;
    }

    private boolean lowerCountExceeded() {
        return countEnabled && lcol != 0 && offlineCount >= (short) (lcol & 0xFF);
    }

    private boolean upperCountExceeded() {
        return countEnabled && ucol != 0 && offlineCount >= (short) (ucol & 0xFF);
    }

    private boolean lowerAmountExceeded() {
        return amountEnabled && !isZero(lcota) && bcdCompare(cumulative, lcota) >= 0;
    }

    private boolean upperAmountExceeded() {
        return amountEnabled && !isZero(ucota) && bcdCompare(cumulative, ucota) >= 0;
    }

    /** True when the first AC must be forced online (ARQC) (EMV v4.4 Book 3 §10.8). */
    public boolean forceOnline() {
        return goOnlineNext || lowerCountExceeded() || upperCountExceeded()
                || lowerAmountExceeded() || upperAmountExceeded();
    }

    /** True when an upper limit is exceeded (decline if offline). */
    public boolean upperExceeded() {
        return upperCountExceeded() || upperAmountExceeded();
    }

    /** True when the two-byte ARC means the terminal could not go online. */
    public static boolean unableToGoOnline(byte arcFirstByte, byte arcSecondByte) {
        // EMV v4.4 Book 3 §9.2.3.2: the Authorisation Response Code, tag '8A', is 'Y3'
        // or 'Z3' when the terminal was unable to go online.
        return (arcFirstByte == (byte) 0x59 || arcFirstByte == (byte) 0x5A)
                && arcSecondByte == (byte) 0x33;
    }

    /** Records a transaction approved offline: count++ and amount += amount. */
    public void recordOffline(byte[] amount, short off, short len) {
        addOffline(amount, off, len);
    }

    /** Records a successful online transaction: reset the accumulators. */
    public void recordOnline() {
        reset();
    }

    private void addOffline(byte[] amount, short off, short len) {
        JCSystem.beginTransaction();
        if (offlineCount != (short) 0x7FFF) {
            offlineCount++;
        }
        if (len >= AMOUNT_LENGTH) {
            bcdAdd(cumulative, (short) 0, amount,
                    (short) (off + len - AMOUNT_LENGTH), AMOUNT_LENGTH);
        }
        JCSystem.commitTransaction();
    }

    private void reset() {
        JCSystem.beginTransaction();
        offlineCount = 0;
        Util.arrayFillNonAtomic(cumulative, (short) 0, AMOUNT_LENGTH, (byte) 0);
        // The 'Set Go Online on Next Transaction' flag is independent of the
        // velocity counters: 'Update Counters = Reset Offline Counters to Zero'
        // must not clear it (EMV v4.4 Book 3 §10.11.1.1).  It is cleared only by
        // the issuer-authentication completion rules (IssuerAuth).
        JCSystem.commitTransaction();
    }

    /**
     * Applies the CSU 'Update Counters' bits (EMV v4.4 Book 3 Annex C §C10):
     * 00 do not update, 01 set to the upper limits, 10 reset to zero, 11 add
     * the transaction to the counters.
     */
    public void applyUpdateCounters(byte bits, byte[] amount, short off, short len) {
        switch (bits & 0x03) {
        case 0x00:
            break;
        case 0x01:
            JCSystem.beginTransaction();
            if (countEnabled) {
                // UCOL is the upper limit: a zero value means the limit itself
                // is zero (EMV v4.4 Book 3 §10.11.1.1).
                offlineCount = (short) (ucol & 0xFF);
            }
            if (amountEnabled) {
                Util.arrayCopyNonAtomic(ucota, (short) 0, cumulative,
                        (short) 0, AMOUNT_LENGTH);
            }
            JCSystem.commitTransaction();
            break;
        case 0x02:
            reset();
            break;
        default: // 0x03: add the transaction to the offline counters
            addOffline(amount, off, len);
            break;
        }
    }

    /**
     * Whether the CSU 'Update Counters' bits (byte 2 b2-b1) apply.  When the
     * 'CSU Created by Proxy for the Issuer' bit (b3) is set, this card does not
     * let a proxy drive the offline counters (EMV v4.4 Book 3 §10.11.1.1,
     * "shall not update the offline counters").
     */
    public static boolean updateCountersApply(byte csuByte2) {
        return (csuByte2 & 0x04) == 0;
    }

    /**
     * The CVR byte 3 bits b8-b5 the accumulators set (EMV v4.4 Book 3
     * Annex C §C9.3): lower/upper offline transaction count, lower/upper cumulative
     * offline amount.  AcProcessor writes this into the IAD.
     */
    public byte cvrByte3() {
        byte v = 0;
        if (lowerCountExceeded()) {
            v |= (byte) 0x80;
        }
        if (upperCountExceeded()) {
            v |= (byte) 0x40;
        }
        if (lowerAmountExceeded()) {
            v |= (byte) 0x20;
        }
        if (upperAmountExceeded()) {
            v |= (byte) 0x10;
        }
        return v;
    }

    // --- small BCD helpers --------------------------------------------------

    /** True when every nibble of buf[off..off+len) is a BCD decimal digit. */
    private static boolean isBcd(byte[] buf, short off, short len) {
        for (short i = 0; i < len; i++) {
            short b = (short) (buf[(short) (off + i)] & 0xFF);
            if ((b >> 4) > 9 || (b & 0x0F) > 9) {
                return false;
            }
        }
        return true;
    }

    private static boolean isZero(byte[] a) {
        for (short i = 0; i < AMOUNT_LENGTH; i++) {
            if (a[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /** Unsigned BCD comparison of two equal-length values (-1/0/1). */
    private static short bcdCompare(byte[] a, byte[] b) {
        for (short i = 0; i < AMOUNT_LENGTH; i++) {
            short x = (short) (a[i] & 0xFF);
            short y = (short) (b[i] & 0xFF);
            if (x != y) {
                return x < y ? (short) -1 : (short) 1;
            }
        }
        return 0;
    }

    /** Adds the BCD value src to dst in place (both AMOUNT_LENGTH bytes). */
    private static void bcdAdd(byte[] dst, short dstOff, byte[] src, short srcOff,
                               short len) {
        short carry = 0;
        for (short i = (short) (len - 1); i >= 0; i--) {
            short lo = (short) ((dst[(short) (dstOff + i)] & 0x0F)
                    + (src[(short) (srcOff + i)] & 0x0F) + carry);
            short hi = (short) (((dst[(short) (dstOff + i)] >> 4) & 0x0F)
                    + ((src[(short) (srcOff + i)] >> 4) & 0x0F));
            if (lo > 9) {
                lo -= 10;
                hi++;
            }
            if (hi > 9) {
                hi -= 10;
                carry = 1;
            } else {
                carry = 0;
            }
            dst[(short) (dstOff + i)] = (byte) ((hi << 4) | lo);
        }
    }
}
