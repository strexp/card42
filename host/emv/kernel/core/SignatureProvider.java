package card42.host.emv.kernel.core;

/**
 * Host callback for the signature CVM (EMV v4.4 Book 3 §10.5, Book 4 Table 2).
 *
 * <p>The terminal captures the cardholder signature (on paper or electronically)
 * and reports it to the acquirer; the terminal cannot verify it, so the CVM
 * result is 'unknown'.  The capture device is outside this project.
 */
public interface SignatureProvider {

    /**
     * Captures the signature and returns the captured data, or null when the
     * cardholder refused or no capture device is available (the CVM fails).
     */
    byte[] capture();
}
