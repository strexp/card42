package javacard.security;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code CryptoException}, used
 * only by the pure-JVM unit tests (docs/specs/common/toolchain.md §6).  The real class
 * cannot be instantiated by a test (its constructor is not public), so this
 * stub exists to exercise the {@code PersoErrors} exception mapping.  It is
 * placed before the {@code api_classic} jar on the unit-test classpath.
 */
public class CryptoException extends RuntimeException {

    public CryptoException(short reason) {
        super(String.format("CryptoException %04X", reason & 0xFFFF));
    }
}
