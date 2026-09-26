package javacard.security;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code Key} interface, used only
 * by the pure-JVM unit tests (docs/specs/common/toolchain.md §6).  Together with
 * {@link DESKey}/{@link AESKey}/{@link KeyBuilder} and
 * {@code javacardx.crypto.Cipher} it lets the card-side crypto classes run on a
 * plain JVM so their constructions can be checked against independent JCE
 * vectors.
 */
public interface Key {

    boolean isInitialized();

    void clearKey();

    byte getType();

    short getSize();
}
