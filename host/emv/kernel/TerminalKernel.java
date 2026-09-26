package card42.host.emv.kernel;

import card42.host.emv.kernel.core.Issuer;
import card42.host.emv.kernel.core.KernelException;
import card42.host.emv.kernel.core.KernelListener;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.lib.Terminal;

/**
 * The terminal kernel entry point shared by {@link ContactKernel} and
 * {@link ContactlessKernel}: one transaction from application selection to the
 * final GENERATE AC, returning the media-neutral {@link TransactionResult}.
 *
 * <p>The two kernels differ in their application selection (contact PSE /
 * direct ADF vs contactless PPSE Entry Point) and in the CVM performer (only
 * the contact kernel performs offline PIN), not in this contract.  The
 * concrete kernels expose their configuration through their constructors
 * (contact: offline PIN / online PIN / signature / confirmation providers;
 * contactless: the Combination Table and Entry Point configuration).
 * A {@link KernelListener} reports progress and is set through {@link #listener}.
 */
public interface TerminalKernel {

    /**
     * Sets the progress listener (defaults to {@link KernelListener#NONE}).
     *
     * @return this kernel, for chaining
     */
    TerminalKernel listener(KernelListener listener);

    /**
     * Runs one transaction and returns the media-neutral result.
     *
     * @param terminal the transport to the card (contact or contactless)
     * @param request  the per-transaction data (referencing the terminal's
     *                 immutable configuration), mutated with the values the
     *                 kernel derives (selected AID, TSC, ...)
     * @param issuer   the online authorisation callback
     * @throws KernelException on a processing, transport or End Application failure
     */
    TransactionResult run(Terminal terminal, TransactionRequest request, Issuer issuer)
            throws KernelException;
}
