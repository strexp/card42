package card42.host.emv.kernel.data;

/**
 * Terminal-side DOL processing (EMV v4.4 Book 3 §5.4): maps a (tag, length)
 * DOL definition onto the terminal data model's values, applying the numeric /
 * compressed-numeric padding rules.  It is separated from {@link TransactionRequest}
 * so the data model stays a plain holder and the DOL logic can be exercised on
 * its own.
 */
public final class TerminalDol {

    private TerminalDol() {
    }

    /**
     * The terminal data object of a tag, or null when the terminal has no value
     * for it.  This is the terminal-source half of EMV v4.4 Book 3 §5.4: a PDOL or
     * CDOL entry is filled from the terminal's transaction data.  Terminal-resident
     * objects come from {@link TerminalConfig}, per-transaction objects from
     * {@link TransactionRequest} and the kernel-computed objects (TVR, TSI, CVM
     * Results, ARC, Issuer Authentication Data) from the live
     * {@link card42.host.emv.kernel.core.TransactionResult}.
     */
    public static byte[] valueFor(TransactionRequest data,
            card42.host.emv.kernel.core.TransactionResult result, int tag) {
        TerminalConfig config = data.config;
        switch (tag) {
        case 0x9F35: return new byte[] { (byte) config.terminalType };
        case 0x9F33: return config.terminalCapabilities;
        case 0x9F40: return config.additionalTerminalCapabilities;
        case 0x9F66: return config.ttq;
        case 0x9F1C: return config.terminalId;
        case 0x9F1E: return config.ifdSerialNumber;
        case 0x9F15: return config.merchantCategoryCode;
        case 0x9F4E: return config.merchantName;
        case 0x9F01: return config.acquirerIdentifier;
        case 0x9F1A: return config.terminalCountryCode;
        case 0x9F09: return config.applicationVersionNumber;
        case 0x9F02: return data.amountAuthorised;
        case 0x9F03: return data.amountOther;
        case 0x5F2A: return data.transactionCurrencyCode;
        case 0x9A: return data.transactionDate;
        case 0x9F21: return data.transactionTime;
        case 0x9C: return new byte[] { (byte) data.transactionType };
        case 0x9F37: return data.unpredictableNumber;
        case 0x9F41: return data.transactionSequenceCounter;
        case 0x9F06: return data.applicationIdentifier;
        case 0x95: return result.tvr();
        case 0x9B: return result.tsi();
        case 0x9F34: return result.cvmResults();
        case 0x8A: return result.arc();
        case 0x91: return result.issuerAuthData();
        case 0x8B:
            // POI Information (EMV Contactless Book B v2.12 Annex A Table A-1 /
            // §C.1.3): the SDOL may request the terminal's POI Information
            // (tag '8B'), whose value is the ID/L/V list.  This terminal only
            // carries the mandatory Terminal Category (POI Information ID
            // '0001', Book B Table A-2), so the value is '0001' + length + value.
            return poiInformation(config.terminalCategory);
        default: return null;
        }
    }

    /**
     * The POI Information value for a Terminal Category: {@code ID1 L1 V1} with
     * the two-byte POI Information identifier '0001' and a one-byte length
     * (EMV Contactless Book B v2.12 Annex A §A.1 and §C.1.3).
     */
    private static byte[] poiInformation(byte[] terminalCategory) {
        byte[] category = terminalCategory != null ? terminalCategory : new byte[] { 0x00, 0x01 };
        byte[] poi = new byte[3 + category.length];
        poi[0] = 0x00;
        poi[1] = 0x01;
        poi[2] = (byte) category.length;
        System.arraycopy(category, 0, poi, 3, category.length);
        return poi;
    }

    /**
     * Builds the command data described by a DOL definition (EMV v4.4 Book 3
     * §5.4): for every (tag, length) entry the terminal value of the tag is
     * copied into a field of the declared length.  A numeric (n) value keeps
     * its rightmost bytes and is left-padded with zeroes; a compressed numeric
     * (cn) value keeps its leftmost bytes and is right-padded with 'FF'; any
     * other format keeps its leftmost bytes and is right-padded with zeroes
     * (EMV v4.4 Book 3 §5.4).  A tag the terminal does not know yields an
     * all-zero field, so the resulting length always matches {@code dol} and
     * the card's length validation succeeds.
     */
    public static byte[] buildDolData(TransactionRequest data,
            card42.host.emv.kernel.core.TransactionResult result, byte[] dol) {
        byte[] out = new byte[dolDataLength(dol)];
        int outOff = 0;
        int p = 0;
        while (p < dol.length) {
            int b = dol[p] & 0xFF;
            int tag;
            if ((b & 0x1F) == 0x1F) {
                tag = (b << 8) | (dol[p + 1] & 0xFF);
                p += 2;
            } else {
                tag = b;
                p += 1;
            }
            int len = dol[p++] & 0xFF;
            if ((len & 0x80) != 0) {
                int n = len & 0x7F;
                len = 0;
                for (int i = 0; i < n; i++) {
                    len = (len << 8) | (dol[p++] & 0xFF);
                }
            }
            byte[] value = valueFor(data, result, tag);
            if (value != null && len > 0) {
                int copy = Math.min(value.length, len);
                if (isNumeric(tag)) {
                    // Numeric: truncate the leftmost bytes and left-pad zeroes.
                    System.arraycopy(value, value.length - copy, out, outOff + len - copy, copy);
                } else if (isCompressedNumeric(tag)) {
                    // Compressed numeric: truncate the rightmost bytes and
                    // right-pad with hexadecimal 'FF' (EMV v4.4 Book 3 §5.4).
                    System.arraycopy(value, 0, out, outOff, copy);
                    for (int i = copy; i < len; i++) {
                        out[outOff + i] = (byte) 0xFF;
                    }
                } else {
                    // Any other format: truncate the rightmost bytes and
                    // right-pad zeroes (the array is already zero-filled).
                    System.arraycopy(value, 0, out, outOff, copy);
                }
            }
            outOff += len;
        }
        return out;
    }

    /**
     * True when the terminal data object of a tag has EMV numeric (n) format
     * (EMV v4.4 Book 3 §4.3); the DOL padding rule depends on it (EMV v4.4 Book 3 §5.4).
     */
    private static boolean isNumeric(int tag) {
        switch (tag) {
        case 0x9F35: // Terminal Type
        case 0x9F02: // Amount, Authorised (Numeric)
        case 0x9F03: // Amount, Other (Numeric)
        case 0x9F1A: // Terminal Country Code
        case 0x5F2A: // Transaction Currency Code
        case 0x9A:   // Transaction Date
        case 0x9C:   // Transaction Type
        case 0x9F21: // Transaction Time
        case 0x9F09: // Application Version Number
        case 0x9F15: // Merchant Category Code
        case 0x9F01: // Acquirer Identifier
            return true;
        default:
            return false;
        }
    }

    /**
     * True when the data object of a tag has EMV compressed numeric (cn) format
     * (EMV v4.4 Book 3 §4.3).  The terminal data model currently carries no cn
     * object (the PAN and track data are ICC-sourced), but the DOL fill applies
     * the cn padding rule so a future terminal cn object is handled correctly.
     */
    public static boolean isCompressedNumeric(int tag) {
        switch (tag) {
        case 0x5A:   // Application PAN
        case 0x57:   // Track 2 Equivalent Data
        case 0x9F20: // Track 2 Discretionary Data
            return true;
        default:
            return false;
        }
    }

    /** The value length described by a DOL definition. */
    public static int dolDataLength(byte[] dol) {
        int total = 0;
        int p = 0;
        while (p < dol.length) {
            int b = dol[p] & 0xFF;
            p += ((b & 0x1F) == 0x1F) ? 2 : 1;
            int len = dol[p++] & 0xFF;
            if ((len & 0x80) != 0) {
                int n = len & 0x7F;
                len = 0;
                for (int i = 0; i < n; i++) {
                    len = (len << 8) | (dol[p++] & 0xFF);
                }
            }
            total += len;
        }
        return total;
    }
}
