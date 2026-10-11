package card42.emv;

import card42.common.*;

import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;

/**
 * Offline PIN state: the platform {@link OwnerPIN} owns the secret and the
 * constant-time comparison, while this wrapper adds a persistent PIN Try
 * Counter / PIN Try Limit that a Card Status Update can set to any value,
 * including 0, which {@link OwnerPIN} cannot express (EMV v4.4 Book 3 Annex C
 * §C10 "Update PIN Try Counter"; DGI '9010' PIN Try Counter / Limit).
 *
 * <p>{@link OwnerPIN} is constructed with the largest legal PIN Try Limit (15)
 * so that a larger limit configured by DGI '9010' can never make the platform
 * block the PIN before the counter tracked here; the effective limit is
 * {@link #maxTries}.  A counter of 0 means the PIN is blocked (6983).
 */
public class OfflinePinState {

    /** Largest PIN Try Limit expressible in the CSU / DGI b4-b1 nibble. */
    public static final byte MAX_TRY_LIMIT = (byte) 15;

    private final OwnerPIN pin;

    /** Effective PIN Try Limit (PTL), persistent. */
    private byte maxTries;
    /** Remaining PIN tries (PTC), persistent; 0 means blocked. */
    private byte triesRemaining;

    public OfflinePinState(byte defaultTryLimit, byte maxSize) {
        this.pin = new OwnerPIN(MAX_TRY_LIMIT, maxSize);
        this.maxTries = defaultTryLimit;
        this.triesRemaining = defaultTryLimit;
    }

    /** Sets (or replaces) the reference PIN and resets the counter to the PTL. */
    public void update(byte[] buf, short off, byte len) {
        pin.update(buf, off, len);
        writeCounter(maxTries);
    }

    /** Remaining PIN tries (reported as tag 9F17). */
    public byte getTriesRemaining() {
        return triesRemaining;
    }

    /** Whether the PIN is blocked (PTC == 0). */
    public boolean isBlocked() {
        return triesRemaining == 0;
    }

    /** Whether the PIN was validated since the last reset (CVR bit). */
    public boolean isValidated() {
        return pin.isValidated();
    }

    /**
     * Checks the PIN; a mismatch decrements the counter and blocks the PIN at
     * 0.  The caller must reject an already-blocked PIN before calling.
     */
    public boolean check(byte[] data, short off, byte len) {
        if (isBlocked()) {
            return false;
        }
        if (pin.check(data, off, len)) {
            writeCounter(maxTries);
            return true;
        }
        writeCounter((byte) (triesRemaining - 1));
        return false;
    }

    /** PIN CHANGE/UNBLOCK: resets the PIN and the counter to the PTL. */
    public void resetAndUnblock() {
        pin.resetAndUnblock();
        writeCounter(maxTries);
    }

    /**
     * CSU "Update PIN Try Counter" (Book 3 Annex C §C10): sets the counter to
     * the value in b4-b1 (0 blocks the PIN).  OwnerPIN is reset so its own
     * counter never blocks before this one.
     */
    public void setTriesRemaining(byte value) {
        pin.resetAndUnblock();
        writeCounter(value);
    }

    /** DGI '9010': initial PIN Try Counter followed by the PIN Try Limit
     * (EMV CPS v2.0 Annex A Table A-6). */
    public void configure(byte ptc, byte ptl) {
        maxTries = ptl;
        pin.resetAndUnblock();
        writeCounter(ptc);
    }

    /**
     * Writes the persistent counter.  A transaction makes the update atomic
     * against a card tear; during personalization the Security Domain already
     * holds a transaction and a nested one is not opened (EMV CPS v2.0 §4.3.4.5,
     * docs/specs/emv/personalization.md §7).
     */
    private void writeCounter(byte value) {
        if (triesRemaining == value) {
            // Same value: skip the EEPROM programming cycle. Java Card does
            // not guarantee that writing a value the cell already holds is
            // free of one.
            return;
        }
        if (JCSystem.getTransactionDepth() == 0) {
            JCSystem.beginTransaction();
            triesRemaining = value;
            JCSystem.commitTransaction();
        } else {
            triesRemaining = value;
        }
    }
}
