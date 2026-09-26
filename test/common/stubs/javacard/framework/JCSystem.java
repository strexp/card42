package javacard.framework;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code JCSystem}, used only by
 * the pure-JVM unit tests (docs/specs/common/toolchain.md §6).  It is placed before the
 * {@code api_classic} jar on the classpath so the card sources link against
 * this implementation instead of the native one.  Only the transient-array
 * factory needed by {@code EMVProtocolState} is provided.
 */
public final class JCSystem {

    public static final byte CLEAR_ON_RESET = (byte) 1;
    public static final byte CLEAR_ON_DESELECT = (byte) 2;

    private JCSystem() {
    }

    public static byte[] makeTransientByteArray(short length, byte event) {
        return new byte[length];
    }

    /**
     * No-op transaction hooks for the unit tests: the stubs back the arrays
     * with plain Java arrays, so atomicity is not modelled.  The card classes
     * under test still exercise the calls (TransactionLog, OfflineRisk).
     */
    public static void beginTransaction() {
    }

    public static void commitTransaction() {
    }

    public static void abortTransaction() {
    }
}
