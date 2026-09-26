package card42.host.emv.kernel.core;

/**
 * A terminal processing failure that terminates the transaction: a malformed or
 * missing ICC data object, an unexpected status word, or a CVM List formatting
 * error (EMV v4.4 Book 3 §7.5/§10.2/§10.5).
 */
public class TransactionException extends KernelException {

    private static final long serialVersionUID = 1L;

    public TransactionException(String message) {
        super(message);
    }

    public TransactionException(String message, Throwable cause) {
        super(message, cause);
    }
}
