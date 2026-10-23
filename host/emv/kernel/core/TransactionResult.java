package card42.host.emv.kernel.core;

/**
 * Everything a terminal kernel observed during one transaction (EMV v4.4
 * Book 3/4), as a read-only contract.
 *
 * <p>This is the media-neutral result shared by the contact and the contactless
 * kernel: the application selection differs (PSE/ADF vs PPSE/Entry Point) and
 * the CVM execution differs (offline PIN vs no offline CVM), but the transaction
 * data, the ODA outcome, the cryptograms and the online decision are the same.
 * Both kernels return this type directly.
 *
 * <p>The contract is split into read views ({@link TransactionData},
 * {@link TransactionOda}, {@link TransactionCvm}, {@link TransactionCryptogram},
 * {@link TransactionOnline}) so a consumer can depend on the slice it needs.
 * Kernel implementations obtain a writer through {@link #newWriter()}; the
 * concrete mutable implementation is package-private.
 */
public interface TransactionResult extends TransactionData, TransactionOda,
        TransactionCvm, TransactionCryptogram, TransactionOnline {

    /**
     * The media-neutral transaction decision.  It unifies the terminal decision
     * of EMV v4.4 Book 4 §6.3.2 (approve / decline / online) with the Final
     * Outcome of EMV Contactless Book A v2.12 Table 6-1, so a caller can branch
     * without knowing which kernel ran.
     */
    enum Decision {
        /** The transaction is approved (offline or after an online approval). */
        APPROVE,
        /** The transaction is declined. */
        DECLINE,
        /** The transaction requires an online authorisation. */
        ONLINE,
        /** No application can complete the transaction (Book A Table 6-1). */
        END_APPLICATION
    }

    /**
     * Creates the package-private mutable result.  The returned type exposes
     * the write SPI only to code that deliberately opts into
     * {@link TransactionResultWriter}; ordinary consumers see the read views.
     */
    static TransactionResultWriter newWriter() {
        return new MutableTransactionResult();
    }
}
