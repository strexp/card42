package card42.host.emv.kernel.core;

import java.util.List;

/**
 * Progress callback for a terminal kernel transaction.  It mirrors the terminal
 * processing functions of EMV v4.4 Book 3 §10.1–§10.11 (plus application
 * selection, Book 1 §12) and the Contactless Outcome of EMV Contactless Book A
 * v2.12 §6, so a cardholder UI / POS application can follow a transaction
 * without reimplementing the flow.
 *
 * <p>The kernel invokes the listener synchronously from the thread running
 * {@link card42.host.emv.kernel.TerminalKernel#run}; a listener must therefore not
 * block and must not call back into the kernel.  The default methods make every
 * event optional; {@link #NONE} is the no-op default.
 *
 * <p>This is a progress/telemetry hook only: it cannot change the transaction.
 * Cardholder interaction (PIN, confirmation, signature) is a separate concern
 * and is performed through the provider callbacks in this package.
 */
public interface KernelListener {

    /**
     * The terminal processing step that has just completed, named after the
     * EMV v4.4 Book 3 §10 functions.  The order in a transaction is:
     * {@code APPLICATION_SELECTION} (Book 1 §12), then
     * {@code INITIATE_APPLICATION_PROCESSING} (§10.1),
     * {@code READ_APPLICATION_DATA} (§10.2),
     * {@code OFFLINE_DATA_AUTHENTICATION} (§10.3),
     * {@code PROCESSING_RESTRICTIONS} (§10.4),
     * {@code CARDHOLDER_VERIFICATION} (§10.5),
     * {@code TERMINAL_RISK_MANAGEMENT} (§10.6),
     * {@code TERMINAL_ACTION_ANALYSIS} (§10.7),
     * {@code CARD_ACTION_ANALYSIS} (§10.8),
     * {@code ONLINE_PROCESSING} (§10.9, only when the transaction goes online),
     * {@code ISSUER_SCRIPT_PROCESSING} (§10.10, only when scripts are present),
     * {@code COMPLETION} (§10.11).
     */
    enum Step {
        APPLICATION_SELECTION,
        INITIATE_APPLICATION_PROCESSING,
        READ_APPLICATION_DATA,
        OFFLINE_DATA_AUTHENTICATION,
        PROCESSING_RESTRICTIONS,
        CARDHOLDER_VERIFICATION,
        TERMINAL_RISK_MANAGEMENT,
        TERMINAL_ACTION_ANALYSIS,
        CARD_ACTION_ANALYSIS,
        ONLINE_PROCESSING,
        ISSUER_SCRIPT_PROCESSING,
        COMPLETION
    }

    /**
     * Reports that a processing step completed.  The result carries the data
     * observed so far, so a listener can render intermediate values (AIP, TVR,
     * CVM Results, AC, ...) without the kernel exposing internals.
     *
     * @param step   the function that just completed
     * @param result the transaction result, live and mutated until the kernel
     *               returns it
     */
    void onStep(Step step, TransactionResult result);

    /**
     * Reports the Entry Point Candidate List after combination selection
     * (EMV Contactless Book B v2.12 §3.3.2), in priority order.  Fired by the
     * contactless kernel only; contact application selection has no Candidate
     * List concept.
     *
     * @param adfNamesHex the ADF Names of the candidates, in selection order
     */
    default void onCandidateList(List<String> adfNamesHex) {
    }

    /**
     * Reports the kernel Final Outcome (EMV Contactless Book A v2.12 Table 6-2).
     * Fired by the contactless kernel only; the contact kernel produces no
     * Outcome (EMV v4.4 Book 1–4 has no Outcome concept) and reports its
     * decision through {@link TransactionResult#decision()}.
     *
     * @param outcome the Final Outcome and its parameters
     */
    default void onOutcome(Outcome outcome) {
    }

    /** The no-op listener. */
    KernelListener NONE = new KernelListener() {
        @Override
        public void onStep(Step step, TransactionResult result) {
        }
    };
}
