package card42.host.emv.kernel.entry;

/**
 * Pre-Processing Indicators (EMV Contactless Book A v2.12 Table 5-3).
 *
 * <p>Entry Point computes them in Start A from the Entry Point Configuration
 * and the transaction amount; they are passed to the selected kernel on
 * activation (Book B §3.4) and preserved across a Restart.
 */
public final class PreProcessingIndicators {

    /** Status Check Requested (b8). */
    public final boolean statusCheckRequested;
    /** Contactless Application Not Allowed (b7). */
    public final boolean contactlessApplicationNotAllowed;
    /** Zero Amount (b6). */
    public final boolean zeroAmount;
    /** Reader CVM Required Limit Exceeded (b5). */
    public final boolean readerCvmRequiredLimitExceeded;
    /** Reader Contactless Floor Limit Exceeded (b4). */
    public final boolean readerContactlessFloorLimitExceeded;
    /** The Terminal Transaction Qualifiers ('9F66') copied from the configuration. */
    public final byte[] ttq;

    /**
     * The Amount, Authorised that is "a single unit of currency" (EMV
     * Contactless Book A Table 5-2, Book B §3.1.1.3): one major unit.  The
     * project models Amount, Authorised in minor units for a 2-decimal
     * currency (ISO 4217), so a single unit is 100 minor units (e.g. EUR 1.00).
     */
    private static final long SINGLE_UNIT_MINOR = 100;

    private PreProcessingIndicators(boolean statusCheckRequested,
            boolean contactlessApplicationNotAllowed, boolean zeroAmount,
            boolean readerCvmRequiredLimitExceeded,
            boolean readerContactlessFloorLimitExceeded, byte[] ttq) {
        this.statusCheckRequested = statusCheckRequested;
        this.contactlessApplicationNotAllowed = contactlessApplicationNotAllowed;
        this.zeroAmount = zeroAmount;
        this.readerCvmRequiredLimitExceeded = readerCvmRequiredLimitExceeded;
        this.readerContactlessFloorLimitExceeded = readerContactlessFloorLimitExceeded;
        this.ttq = ttq;
    }

    /**
     * Start A indicators (Book A §5.7): the reader computes them once per
     * activation from the configuration, the amount and whether any Combination
     * exists for the transaction type.
     *
     * @param amountMinorUnits the Amount, Authorised in minor units
     * @param contactlessApplicationNotAllowed true when the Combination Table
     *        has no Combination for the transaction type (Table 5-3 b7)
     */
    public static PreProcessingIndicators startA(EntryPointConfiguration config,
            long amountMinorUnits, boolean contactlessApplicationNotAllowed) {
        // 3.1.1.3 Status Check Requested: Status Check Support present and set,
        // and the Amount, Authorised is a single unit of currency.
        boolean statusCheck = config.statusCheckSupport
                && amountMinorUnits == SINGLE_UNIT_MINOR;
        boolean cana = contactlessApplicationNotAllowed;
        boolean zeroAmount = false;
        boolean floorExceeded = false;
        boolean cvmExceeded = false;

        // 3.1.1.4 Zero Amount: with 'Zero Amount for Offline Allowed' set the
        // check is skipped; otherwise a disallowed zero amount forbids the
        // application, else the Zero Amount indicator is set.
        if (amountMinorUnits == 0) {
            if (!(config.zeroAmountOfflineAllowedPresent && config.zeroAmountOfflineAllowed)) {
                if (config.zeroAmountAllowedPresent && !config.zeroAmountAllowed) {
                    cana = true;
                } else {
                    zeroAmount = true;
                }
            }
        }
        // 3.1.1.5 Reader Contactless Transaction Limit (greater than or equal).
        if (config.readerContactlessTransactionLimitPresent
                && amountMinorUnits >= config.readerContactlessTransactionLimit) {
            cana = true;
        }
        // 3.1.1.6 Reader Contactless Floor Limit (strictly greater).
        if (config.readerContactlessFloorLimitPresent
                && amountMinorUnits > config.readerContactlessFloorLimit) {
            floorExceeded = true;
        }
        // 3.1.1.7 Terminal Floor Limit ('9F1B') fallback when the Reader
        // Contactless Floor Limit is not present (strictly greater).
        if (!config.readerContactlessFloorLimitPresent
                && config.terminalFloorLimitPresent
                && amountMinorUnits > config.terminalFloorLimit) {
            floorExceeded = true;
        }
        // 3.1.1.8 Reader CVM Required Limit (greater than or equal).
        if (config.readerCvmRequiredLimitPresent
                && amountMinorUnits >= config.readerCvmRequiredLimit) {
            cvmExceeded = true;
        }

        // 3.1.1.2 Copy of TTQ: reset byte 2 b8/b7, then apply 3.1.1.9-.12.
        byte[] ttq = config.ttq.clone();
        if (ttq.length >= 2) {
            ttq[1] &= (byte) 0x3F; // clear byte 2 b8/b7
            if (floorExceeded || statusCheck) {
                ttq[1] |= (byte) 0x80; // online cryptogram required
            }
            if (zeroAmount) {
                if ((ttq[0] & 0x08) == 0) {
                    ttq[1] |= (byte) 0x80; // online capable reader
                } else {
                    cana = true; // offline-only reader
                }
            }
            if (cvmExceeded) {
                ttq[1] |= (byte) 0x40; // CVM required
            }
        }
        return new PreProcessingIndicators(statusCheck, cana, zeroAmount,
                cvmExceeded, floorExceeded, ttq);
    }

    /**
     * Start B indicators (Book A §5.8.1): after a Status Check or a restart the
     * reader uses fixed values (all clear) and only carries the TTQ copy, whose
     * byte 2 b8/b7 are reset (Book B §3.1.1.2).
     */
    public static PreProcessingIndicators startB(EntryPointConfiguration config) {
        byte[] ttq = config.ttq.clone();
        if (ttq.length >= 2) {
            ttq[1] &= (byte) 0x3F;
        }
        return new PreProcessingIndicators(false, false, false, false, false, ttq);
    }
}
