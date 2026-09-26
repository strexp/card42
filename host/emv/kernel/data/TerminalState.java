package card42.host.emv.kernel.data;

/**
 * Terminal-resident state that persists across transactions: the Transaction
 * Sequence Counter (EMV v4.4 Book 4 §6.5.5).
 *
 * <p>The counter starts at 1, is exposed for the current transaction and
 * advanced for the next; a value of zero is not allowed.  It lives outside the
 * immutable {@link TerminalConfig} because it is the one terminal-resident value
 * the kernel changes as transactions are processed.
 */
public final class TerminalState {

    private long tscCounter = 1;

    /**
     * The Transaction Sequence Counter value ('9F41') for the current
     * transaction, advancing the terminal-resident counter for the next
     * (EMV v4.4 Book 4 §6.5.5).
     */
    public synchronized byte[] nextTransactionSequenceCounter() {
        byte[] tsc = new byte[] {
            (byte) (tscCounter >>> 24), (byte) (tscCounter >>> 16),
            (byte) (tscCounter >>> 8), (byte) tscCounter
        };
        tscCounter++;
        if (tscCounter > 0xFFFFFFFFL) {
            tscCounter = 1;
        }
        return tsc;
    }
}
