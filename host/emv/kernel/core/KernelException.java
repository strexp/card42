package card42.host.emv.kernel.core;

/**
 * A terminal kernel failure.  This is the checked base type of
 * {@link card42.host.emv.kernel.TerminalKernel#run}, so a caller handles the
 * kernel's declared failure modes instead of a bare {@code Exception}.
 *
 * <p>The hierarchy separates the two spec-relevant cases: an Entry Point
 * <em>End Application</em> Outcome ({@link EndApplicationException}, EMV
 * Contactless Book B v2.12 §3.3.3.5) and a processing/transport failure
 * ({@link TransactionException} / {@link TransportException}).
 */
public class KernelException extends Exception {

    private static final long serialVersionUID = 1L;

    public KernelException(String message) {
        super(message);
    }

    public KernelException(String message, Throwable cause) {
        super(message, cause);
    }
}
