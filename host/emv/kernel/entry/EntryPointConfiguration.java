package card42.host.emv.kernel.entry;

import card42.host.emv.kernel.data.TerminalConfig;

/**
 * Entry Point Configuration Data (EMV Contactless Book A v2.12 Table 5-2).
 *
 * <p>The reader-resident limits and flags Entry Point preprocessing needs.  The
 * defaults are derived from {@link TerminalConfig} (terminal floor limit, CVM
 * required limit and TTQ) so the kernel keeps its EMV v4.4 Book 3/4 behaviour;
 * a caller can override them from a CLI/config file.
 */
public final class EntryPointConfiguration {

    /** Status Check Support (Table 5-2). */
    public boolean statusCheckSupport = false;
    /** Zero Amount Allowed (Table 5-2). */
    public boolean zeroAmountAllowed = true;
    /** True when the Zero Amount Allowed flag is present (Table 5-2). */
    public boolean zeroAmountAllowedPresent = true;
    /** Zero Amount for Offline Allowed (Table 5-2). */
    public boolean zeroAmountOfflineAllowed = true;
    /** True when the Zero Amount for Offline Allowed flag is present (Table 5-2). */
    public boolean zeroAmountOfflineAllowedPresent = true;
    /** Reader Contactless Transaction Limit in minor units (Table 5-2). */
    public long readerContactlessTransactionLimit = 0;
    /** True when the Reader Contactless Transaction Limit is present (Table 5-2). */
    public boolean readerContactlessTransactionLimitPresent = false;
    /** Reader Contactless Floor Limit in minor units (Table 5-2). */
    public long readerContactlessFloorLimit = 0;
    /** True when the Reader Contactless Floor Limit is present (Table 5-2). */
    public boolean readerContactlessFloorLimitPresent = false;
    /** Terminal Floor Limit ('9F1B') in minor units (Table 5-2). */
    public long terminalFloorLimit = 0;
    /** True when the Terminal Floor Limit ('9F1B') is present (Table 5-2). */
    public boolean terminalFloorLimitPresent = false;
    /** Reader CVM Required Limit in minor units (Table 5-2). */
    public long readerCvmRequiredLimit = 0;
    /** True when the Reader CVM Required Limit is present (Table 5-2). */
    public boolean readerCvmRequiredLimitPresent = false;
    /** Extended Selection Support (Book B §3.3.3.3). */
    public boolean extendedSelectionSupported = false;
    /** The reader supports SEND POI INFORMATION when the card advertises it (Book B Annex C). */
    public boolean spiSupport = true;
    /** Force SEND POI INFORMATION even when the card does not advertise '9F3E'/'9F3F'. */
    public boolean forceSpi = false;
    /**
     * Restart with Select Next when the kernel declines and another Combination
     * remains (Book A §6.3, Final Outcome 'Select Next').  Off by default so a
     * decline is final unless the reader opts in.
     */
    public boolean restartOnDecline = false;
    /**
     * Produce the Try Again Final Outcome when the kernel declines
     * (EMV Contactless Book A v2.12 Table 6-3/6-4): the Entry Point restarts
     * with the same Combination instead of ending the application.  Off by
     * default; {@link #restartOnDecline} takes precedence when both are set.
     */
    public boolean tryAgainOnDecline = false;
    /**
     * Autorun (EMV Contactless Book A v2.12 §8.1.1.6): when 'Yes' the reader
     * activates Entry Point directly at Start B (fixed Pre-Processing
     * Indicators) instead of Start A, independently of Status Check.
     */
    public boolean autorun = false;
    /**
     * Reader Field Off Request / Removal Timeout (EMV Contactless Book A v2.12
     * Table 6-2), in seconds; 0 means none.  They are reported on the final
     * Outcome so the reader can power the field off and wait for card removal.
     * These are device parameters, not Entry Point Configuration Table 5-2 data.
     */
    public int fieldOffRequest = 0;
    public int removalTimeout = 0;
    /** Terminal Transaction Qualifiers ('9F66'), copied into the Pre-Processing Indicators. */
    public byte[] ttq = new byte[4];
    /** POI Information ID '0001' Terminal Category (Book B Table A-2). */
    public byte[] terminalCategory = { 0x00, 0x01 };

    public EntryPointConfiguration() {
    }

    /** The configuration derived from the terminal data model. */
    public static EntryPointConfiguration from(TerminalConfig config0) {
        EntryPointConfiguration config = new EntryPointConfiguration();
        config.terminalFloorLimit = config0.floorLimit;
        // A zero terminal floor limit / CVM required limit means the reader did
        // not configure one, so the limit is treated as not present (Table 5-2).
        config.terminalFloorLimitPresent = config0.floorLimit > 0;
        config.readerCvmRequiredLimit = config0.cvmRequiredLimit;
        config.readerCvmRequiredLimitPresent = config0.cvmRequiredLimit > 0;
        config.ttq = config0.ttq.clone();
        // The POI Information ID '0001' Terminal Category is terminal-resident
        // (EMV Contactless Book B v2.12 Annex A Table A-2); the derived reader
        // configuration inherits it so SPI and SDOL tag '8B' agree.
        config.terminalCategory = config0.terminalCategory.clone();
        return config;
    }
}
