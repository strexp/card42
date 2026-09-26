package card42.host.emv.kernel.data;

import card42.host.common.util.Bcd;
import card42.host.common.util.Hex;

/**
 * The per-transaction data of a terminal kernel (EMV v4.4 Book 3 §5): the
 * transaction amount, currency, date/time, type and Unpredictable Number, plus
 * the values the kernel derives during the transaction (the selected
 * Application Identifier '9F06' and the Transaction Sequence Counter '9F41').
 *
 * <p>It references the immutable, terminal-resident {@link TerminalConfig} and
 * carries no transaction <em>outcome</em>: the Terminal Verification Results,
 * Transaction Status Information, CVM Results, ARC and Issuer Authentication
 * Data are read from the {@link card42.host.emv.kernel.core.TransactionResult} the
 * kernel returns.
 *
 * <p>A caller builds one request per transaction from the terminal's
 * configuration; the request is mutable so the kernel can fill the derived
 * values, but the caller must not share one request across concurrent
 * transactions.
 */
public final class TransactionRequest {

    /** The terminal-resident configuration of this transaction. */
    public final TerminalConfig config;

    /** Amount, Authorised ('9F02', 6-byte BCD, minor units). */
    public byte[] amountAuthorised = Hex.parse("000000000500");
    /** Amount, Other ('9F03', 6-byte BCD, minor units). */
    public byte[] amountOther = Hex.parse("000000000000");
    /** Transaction Currency Code ('5F2A', 2 bytes). */
    public byte[] transactionCurrencyCode = Hex.parse("0978");
    /** Transaction Date ('9A', 3 bytes, YYMMDD). */
    public byte[] transactionDate = Hex.parse("260923");
    /** Transaction Time ('9F21', 3 bytes, HHMMSS). */
    public byte[] transactionTime = Hex.parse("120000");
    /** Transaction Type ('9C'): 00 = purchase. */
    public int transactionType = 0x00;
    /** Unpredictable Number ('9F37', 4 bytes). */
    public byte[] unpredictableNumber = Hex.parse("11223344");
    /**
     * True when the caller fixed the Unpredictable Number (for example the CLI
     * {@code -un} option): the kernel then uses it as-is.  When false the kernel
     * draws a fresh value at each activation (EMV Contactless Book A v2.12
     * §8.1.1.8).
     */
    public boolean unpredictableNumberFixed = false;
    /** Application Identifier of the terminal for this AID ('9F06'). */
    public byte[] applicationIdentifier = Hex.parse("43415244420102");

    /**
     * Transaction Sequence Counter ('9F41', 4 bytes, EMV v4.4 Book 4 §6.5.5):
     * filled by the kernel from the terminal-resident counter before each
     * transaction.
     */
    public byte[] transactionSequenceCounter = new byte[] { 0, 0, 0, 1 };

    /** Merchant forces the transaction online (TAC-Online bit 4). */
    public boolean merchantForcedOnline = false;

    public TransactionRequest(TerminalConfig config) {
        this.config = config;
    }

    /**
     * True when the transaction has a cashback amount: Transaction Type
     * 'purchase with cashback' ('09') or a non-zero Amount, Other ('9F03')
     * (EMV v4.4 Book 3 §10.4.2 Table 36).
     */
    public boolean hasCashback() {
        return transactionType == 0x09 || Bcd.bcdToLong(amountOther) > 0;
    }
}
