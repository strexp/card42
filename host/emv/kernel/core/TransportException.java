package card42.host.emv.kernel.core;

/**
 * A Level 1 / card transport failure (for example a lost card or a reader
 * error) while the kernel was exchanging APDUs.  It is distinct from
 * {@link TransactionException}, which is an EMV-level processing failure.
 */
public class TransportException extends KernelException {

    private static final long serialVersionUID = 1L;

    public TransportException(String message, Throwable cause) {
        super(message, cause);
    }
}
