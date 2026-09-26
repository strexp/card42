package card42.host.emv.lib;

import card42.host.common.codec.Tags;

/**
 * EMV v4.4 Book 3 §7.5 policy over the data objects an ICC sends in a response
 * buffer: which of them the terminal shall ignore and whose format errors it
 * shall tolerate.  The BER-TLV/DOL parsing itself lives in {@link Tags}; this
 * class only carries the EMV sourcing and format rules.
 */
public final class TagPolicy {

    // Card-sourced data objects whose format errors the terminal shall ignore
    // (EMV v4.4 Book 3 §7.5, Table 34).  The format error may prevent the
    // service that uses the object, but it shall not abort the transaction.
    private static final int[] FORMAT_ERROR_TOLERATED = {
        0x5F20, // Cardholder Name
        0x9F0B, // Cardholder Name Extended
        0x42,   // Issuer Identification Number (IIN)
        0x9F0C, // Issuer Identification Number Extended (IINE)
        0x5F50, // Issuer URL
        0x9F4D, // Log Entry
        0x9F4F, // Log Format
        0x9F1F, // Track 1 Discretionary Data
    };

    private TagPolicy() {
    }

    /**
     * Finds the first value of an ICC-sourced data object, applying the EMV v4.4 Book 3
     * §7.5 rules: a data object that the EMV data elements dictionary designates
     * as terminal- or issuer-sourced is ignored even if the card sends it, and a
     * format error in one of the Table 34 data objects is ignored (the object is
     * treated as absent) instead of aborting the transaction.
     */
    public static byte[] findIcc(byte[] buf, int tag) {
        if (isTerminalOrIssuerSourced(tag)) {
            return null;
        }
        byte[] value = Tags.find(buf, tag);
        if (value == null) {
            return null;
        }
        if (isFormatErrorTolerated(tag) && isMalformed(tag, value)) {
            return null;
        }
        return value;
    }

    /**
     * True when the EMV data elements dictionary (EMV v4.4 Book 3 Annex A Table 37)
     * designates the tag as terminal- or issuer-sourced, i.e. data the terminal
     * itself supplies (or the issuer sends online).  During a transaction the
     * terminal shall ignore such data objects coming from the ICC (EMV v4.4 Book 3 §7.5).
     */
    public static boolean isTerminalOrIssuerSourced(int tag) {
        switch (tag) {
        // Terminal-sourced (EMV v4.4 Book 3 Annex A).
        case 0x5F2A: // Transaction Currency Code
        case 0x5F36: // Transaction Currency Exponent
        case 0x5F57: // Account Type
        case 0x81:   // Amount, Authorised (Binary)
        case 0x95:   // Terminal Verification Results
        case 0x9A:   // Transaction Date
        case 0x9B:   // Transaction Status Information
        case 0x9C:   // Transaction Type
        case 0x9F01: // Acquirer Identifier
        case 0x9F02: // Amount, Authorised (Numeric)
        case 0x9F03: // Amount, Other (Numeric)
        case 0x9F04: // Amount, Other (Binary)
        case 0x9F06: // Application Identifier (AID) - terminal
        case 0x9F09: // Application Version Number - terminal
        case 0x9F15: // Merchant Category Code
        case 0x9F16: // Merchant Identifier
        case 0x9F1A: // Terminal Country Code
        case 0x9F1B: // Terminal Floor Limit
        case 0x9F1C: // Terminal Identification
        case 0x9F1D: // Terminal Risk Management Data
        case 0x9F1E: // Interface Device (IFD) Serial Number
        case 0x9F21: // Transaction Time
        case 0x9F33: // Terminal Capabilities
        case 0x9F34: // CVM Results
        case 0x9F35: // Terminal Type
        case 0x9F37: // Unpredictable Number
        case 0x9F39: // Point-of-Service (POS) Entry Mode
        case 0x9F3A: // Amount, Reference
        case 0x9F40: // Additional Terminal Capabilities
        case 0x9F41: // Transaction Sequence Counter
        case 0x9F4E: // Merchant Name and Location
        case 0x9F66: // Terminal Transaction Qualifiers (EMV Contactless Book A Table 5-4 / Book B Table A-1)
        // Issuer-sourced (EMV v4.4 Book 3 Annex A).
        case 0x86:   // Issuer Script Command
        case 0x89:   // Authorisation Code
        case 0x8A:   // Authorisation Response Code
        case 0x91:   // Issuer Authentication Data
        case 0x9F18: // Issuer Script Identifier
        case 0x9F5B: // Issuer Script Results
        case 0x71:   // Issuer Script Template 1
        case 0x72:   // Issuer Script Template 2
            return true;
        default:
            return false;
        }
    }

    /** True for a data object whose format errors shall be ignored (EMV v4.4 Book 3 Table 34). */
    public static boolean isFormatErrorTolerated(int tag) {
        for (int t : FORMAT_ERROR_TOLERATED) {
            if (t == tag) {
                return true;
            }
        }
        return false;
    }

    /**
     * The format check for an EMV v4.4 Book 3 Table 34 data object: IIN/IINE/Log Entry have a
     * fixed length and the Log Format must be a well-formed list of (tag,
     * length) entries.  The remaining objects are alphanumeric and have no
     * checkable format here, so they are never malformed.
     */
    public static boolean isMalformed(int tag, byte[] value) {
        switch (tag) {
        case 0x42:   // IIN: n 6, i.e. 3 bytes
            return value.length != 3;
        case 0x9F0C: // IINE: n 6 or 8, i.e. 3 or 4 bytes
            return value.length != 3 && value.length != 4;
        case 0x9F4D: // Log Entry: SFI || record count, 2 bytes
            return value.length != 2;
        case 0x9F4F: // Log Format: a list of (tag, length) entries
            return !Tags.isWellFormedDol(value);
        default:
            return false;
        }
    }
}
