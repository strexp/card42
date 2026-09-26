package card42.host.emv.report;

import java.nio.charset.StandardCharsets;

import card42.host.emv.kernel.core.TransactionResult;
import card42.host.common.util.Bcd;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.common.util.Hex;

/**
 * The cardholder receipt of one transaction, built from the media-neutral
 * {@link TransactionResult} and the {@link TransactionRequest} (EMV v4.4 Book 4
 * §6.3).  This is the data model only; the presentation lives in a separate UI
 * project (docs/specs/emv/contact-kernel.md).  {@link ReceiptRenderer} provides the
 * default text / JSON formatting.
 */
public final class Receipt {

    /** True when the terminal approved the transaction (not declined). */
    public boolean approved;
    /** The ADF Name of the selected application, in hex. */
    public String aidHex;
    /** The masked PAN (all but the last four digits), or null. */
    public String panMasked;
    /** Amount, Authorised in BCD (6 bytes), or null. */
    public byte[] amount;
    /** Transaction Currency Code ('5F2A'), or null. */
    public byte[] currency;
    /** Transaction Date ('9A', YYMMDD), or null. */
    public byte[] date;
    /** Transaction Time ('9F21', HHMMSS), or null. */
    public byte[] time;
    /** CVM Results ('9F34') in hex, or null. */
    public String cvmResults;
    /** Authorization Response Code (ARC) in hex, or null. */
    public String arc;
    /** Terminal Identifier ('9F1C') in hex, or null. */
    public String terminalId;
    /** Merchant Name ('9F4E') as text, or null. */
    public String merchantName;

    public Receipt() {
    }

    /** Builds the receipt of a finished transaction. */
    public static Receipt from(TransactionResult result, TransactionRequest data) {
        Receipt r = new Receipt();
        r.approved = !result.declined();
        r.aidHex = result.aidHex();
        r.panMasked = maskPan(result.firstValue(0x5A));
        r.amount = data.amountAuthorised;
        r.currency = data.transactionCurrencyCode;
        r.date = data.transactionDate;
        r.time = data.transactionTime;
        r.cvmResults = result.cvmResults() == null ? null : Hex.format(result.cvmResults());
        r.arc = result.arc() == null ? null : Hex.format(result.arc());
        r.terminalId = data.config.terminalId == null ? null : Hex.format(data.config.terminalId);
        r.merchantName = data.config.merchantName == null ? null
                : new String(data.config.merchantName, StandardCharsets.US_ASCII);
        return r;
    }

    /** The amount in minor units, or 0 when absent. */
    public long amountMinor() {
        return amount == null ? 0 : Bcd.bcdToLong(amount);
    }

    /** Masks a BCD PAN, keeping only its last four digits. */
    private static String maskPan(byte[] pan) {
        if (pan == null) {
            return null;
        }
        StringBuilder digits = new StringBuilder();
        for (byte b : pan) {
            int high = (b >> 4) & 0x0F;
            if (high <= 9) {
                digits.append((char) ('0' + high));
            }
            int low = b & 0x0F;
            if (low <= 9) {
                digits.append((char) ('0' + low));
            }
        }
        String s = digits.toString();
        if (s.length() <= 4) {
            return s;
        }
        StringBuilder masked = new StringBuilder();
        for (int i = 0; i < s.length() - 4; i++) {
            masked.append('*');
        }
        masked.append(s.substring(s.length() - 4));
        return masked.toString();
    }
}
