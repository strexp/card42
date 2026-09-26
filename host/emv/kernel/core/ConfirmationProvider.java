package card42.host.emv.kernel.core;

/**
 * Cardholder confirmation callback (EMV v4.4 Book 1 §12.4 step 5).
 *
 * <p>A terminal that provides cardholder confirmation asks whether an
 * application entry whose Application Priority Indicator ('87') bit 8 is set
 * may be selected.  A null provider (the default) means the terminal does not
 * provide cardholder confirmation: such entries are skipped when another
 * candidate exists and terminate the session when they are the only one
 * (EMV v4.4 Book 1 §12.4 steps 2/5).
 *
 * <p>The actual cardholder interaction (screen, PIN pad, ...) is out of scope
 * of this project and lives in a separate UI project; the reference CLI maps
 * {@code -confirm=always|never} onto this callback.
 */
public interface ConfirmationProvider {

    /**
     * Asks the cardholder to confirm the selection of an application.
     *
     * @param adfName the ADF Name of the candidate, in hex
     * @param label   the Application Label ('50') as text, or null when absent
     * @return true when the cardholder confirms the selection
     */
    boolean confirm(String adfName, String label);
}
