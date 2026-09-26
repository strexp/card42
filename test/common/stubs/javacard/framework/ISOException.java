package javacard.framework;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code ISOException}, used only
 * by the pure-JVM unit tests (docs/specs/common/toolchain.md §6).  {@link #throwIt(short)}
 * throws a real Java exception carrying the status word, so tests can assert on
 * it instead of the card's native trap.
 */
public class ISOException extends RuntimeException {

    private final short reason;

    private ISOException(short reason) {
        super(String.format("ISOException %04X", reason & 0xFFFF));
        this.reason = reason;
    }

    public static void throwIt(short sw) {
        throw new ISOException(sw);
    }

    public short getReason() {
        return reason;
    }
}
