package card42.host.emv.kernel.core;

import card42.host.common.codec.Tags;

/**
 * The kernel Outcome (EMV Contactless Book A v2.12 Table 6-2) and the Final
 * Outcome Entry Point consumes (Book A §6.3, Table 6-3/6-4/6-5).
 *
 * <p>The kernel produces an Outcome from the media-neutral
 * {@link TransactionResult}; Entry Point maps the Final Outcome to the next
 * Entry Point state (approve / decline / online / select next / try again /
 * end application / restart).
 */
public final class Outcome {

    // Start (Table 6-2): which Entry Point state activated the kernel.
    public static final int START_A = 0x00;
    public static final int START_B = 0x01;
    public static final int START_C = 0x02;
    public static final int START_D = 0x03;
    public static final int START_N = 0x04;

    // Final Outcome (Table 6-3/6-4/6-5).
    public static final int APPROVE = 0x00;
    public static final int DECLINE = 0x01;
    public static final int ONLINE_REQUEST = 0x02;
    public static final int REQUEST_ONLINE_PIN = 0x03;
    public static final int SELECT_NEXT = 0x04;
    public static final int TRY_AGAIN = 0x05;
    public static final int END_APPLICATION = 0x06;
    /** Try Another Interface (Book A Table 6-1), UI Request message '18'. */
    public static final int TRY_ANOTHER_INTERFACE = 0x07;

    /** Start (Table 6-2). */
    public int start = START_A;
    /** The Final Outcome (Table 6-3/6-4/6-5). */
    public int finalOutcome = APPROVE;
    /** Online Response Data (Table 6-2), or null. */
    public byte[] onlineResponseData;
    /** CVM Results ('9F34'), or null. */
    public byte[] cvmResults;
    /** UI Request on Outcome Present (Table 6-2). */
    public boolean uiRequestOnOutcomePresent;
    /** UI Request on Restart Present (Table 6-2). */
    public boolean uiRequestOnRestartPresent;
    /** Data Record Present (Table 6-2). */
    public boolean dataRecordPresent;
    /** Discretionary Data Present (Table 6-2). */
    public boolean discretionaryDataPresent;
    /** Alternate Interface Preference (Table 6-2). */
    public boolean alternateInterfacePreference;
    /** Receipt (Table 6-2). */
    public boolean receipt;
    /** Field Off Request (Table 6-2), seconds; 0 = none. */
    public int fieldOffRequest;
    /** Removal Timeout (Table 6-2), seconds; 0 = none. */
    public int removalTimeout;
    /** The Final Outcome requests a Restart (Select Next / Try Again). */
    public boolean restart;
    /** The UI Request message identifier when {@link #uiRequestOnOutcomePresent}. */
    public int messageIdentifier;
    /** The Final Outcome ADF Name (EMV Contactless Book B v2.12 §3.5.1.5). */
    public String adfName;
    /**
     * The Kernel Identifier-Terminal (tag '96', 8 bytes) of the Kernel Entry
     * Point selected for the transaction (EMV Contactless Book B v2.12 §3.5.1.5
     * and Table 3-7); null until the kernel fills it from the activation.
     */
    public byte[] kernelIdentifierTerminal;

    public Outcome() {
    }

    /**
     * Maps the media-neutral transaction result to a kernel Outcome
     * (EMV Contactless Book A v2.12 Table 6-2/6-3):
     * a 'Service not allowed' result ends the application, a declined
     * transaction declines, otherwise the transaction is approved.  The
     * Table 6-2 fields that can be derived from the transaction are filled:
     * the Final Outcome ADF Name, whether Data Records / Discretionary Data
     * were present and whether a receipt is requested.  Field Off Request and
     * Removal Timeout are reader parameters and are set by the kernel.
     */
    public static Outcome from(TransactionResult result) {
        Outcome outcome = new Outcome();
        outcome.cvmResults = result.cvmResults();
        outcome.onlineResponseData = result.issuerAuthData();
        outcome.adfName = result.aidHex();
        // Data Record Present: the kernel read at least one AFL record.
        outcome.dataRecordPresent = result.records() != null && !result.records().isEmpty();
        // Discretionary Data Present: the selected FCI carried BF0C.
        outcome.discretionaryDataPresent = result.fci() != null
                && Tags.find(result.fci(), 0xBF0C) != null;
        // Alternate Interface Preference is not modelled (no alternate interface).
        outcome.alternateInterfacePreference = false;
        if (result.serviceNotAllowed()) {
            outcome.finalOutcome = END_APPLICATION;
            outcome.uiRequestOnOutcomePresent = true;
            outcome.messageIdentifier = 0x1C; // Insert, Swipe or Try Another Card
        } else if (result.declined()) {
            outcome.finalOutcome = DECLINE;
        } else {
            outcome.finalOutcome = APPROVE;
            // An approved transaction asks the reader for a receipt
            // (EMV Contactless Book A v2.12 Table 6-2).
            outcome.receipt = true;
        }
        return outcome;
    }

    /** An End Application Final Outcome carrying a UI Request message identifier. */
    public static Outcome endApplication(int messageIdentifier) {
        Outcome outcome = new Outcome();
        outcome.finalOutcome = END_APPLICATION;
        outcome.uiRequestOnOutcomePresent = true;
        outcome.messageIdentifier = messageIdentifier;
        return outcome;
    }

    /** A Select Next Final Outcome: the current Combination is removed and Start C restarts. */
    public static Outcome selectNext() {
        Outcome outcome = new Outcome();
        outcome.finalOutcome = SELECT_NEXT;
        outcome.restart = true;
        return outcome;
    }

    /**
     * A Try Another Interface Final Outcome (Book A Table 6-1): every
     * Combination had 'Contactless Application Not Allowed' set.
     */
    public static Outcome tryAnotherInterface() {
        Outcome outcome = new Outcome();
        outcome.finalOutcome = TRY_ANOTHER_INTERFACE;
        outcome.uiRequestOnOutcomePresent = true;
        outcome.messageIdentifier = 0x18; // Try Another Interface
        return outcome;
    }

    /**
     * A Try Again Final Outcome (EMV Contactless Book A v2.12 Table 6-3/6-4):
     * the Entry Point restarts with the same Combination.  The UI Request on
     * Restart is present when a message identifier is supplied.
     */
    public static Outcome tryAgain(int messageIdentifier) {
        Outcome outcome = new Outcome();
        outcome.finalOutcome = TRY_AGAIN;
        outcome.restart = true;
        if (messageIdentifier != 0) {
            outcome.uiRequestOnRestartPresent = true;
            outcome.messageIdentifier = messageIdentifier;
        }
        return outcome;
    }
}
