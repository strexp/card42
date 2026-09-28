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
        byte[] b = new byte[length];
        NvmWrite.register(b, length);
        return b;
    }

    /**
     * RAM-backed short array, registered with {@link NvmWrite} like the byte
     * variant.  The card sources that need it ({@code DdaCrypto}, and the DOL
     * cursor once it moves off EEPROM) link against this factory in the
     * pure-JVM build.
     */
    public static short[] makeTransientShortArray(short length, byte event) {
        short[] a = new short[length];
        NvmWrite.register(a, (int) length * 2);
        return a;
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

    /**
     * No-op object-deletion request for the unit tests.  The card sources call
     * it after dropping a large persistent object (a re-keyed DDA key, a
     * replaced page array) to ask the platform to reclaim it; a plain JVM
     * reclaims via its own garbage collector, so there is nothing to model.
     */
    public static void requestObjectDeletion() {
    }
}
