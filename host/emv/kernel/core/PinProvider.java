package card42.host.emv.kernel.core;

/**
 * Supplies the offline PIN the contact kernel verifies
 * (EMV v4.4 Book 3 §10.5).  The kernel does not capture the PIN itself; the
 * terminal/UI provides it, so tests and applications can inject a PIN pad or a
 * fixed PIN.
 */
public interface PinProvider {

    /**
     * The PIN to verify for the current transaction, or null when no PIN can be
     * entered (the CVM then fails).
     */
    String pin();
}
