package card42.host.emv.kernel.core;

/**
 * Host callback for the online PIN CVM (EMV v4.4 Book 3 §10.5,
 * EMV v4.4 Book 4 §6.3.4.4).
 *
 * <p>The terminal captures the PIN and encrypts the ISO 9564-1 format 0 PIN
 * block; the PIN encryption key and its management are outside this project, so
 * the host supplies the encryption through this callback.
 */
public interface OnlinePinProvider {

    /** The PIN digits, or null when the cardholder or merchant bypassed entry. */
    String pin();

    /**
     * Encrypts the 8-byte ISO 9564-1 format 0 PIN block, or returns null when no
     * encryption key is available (the CVM then fails).
     */
    byte[] encryptPinBlock(byte[] pinBlock);
}
