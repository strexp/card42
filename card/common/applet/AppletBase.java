package card42.common;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* Shared applet skeleton for the card42 applets (EMV and eMRTD).
 *
 * It owns only the mechanical part of APDU processing that every applet needs:
 * the class-byte hook, the SELECT entry point and the dispatch to the concrete
 * command handler.  It carries no EMV or eMRTD semantics; the concrete base
 * class implements {@link #onSelect}, {@link #processCommand} and, when needed,
 * {@link #validateCla}.
 *
 * A SELECT that reaches an applet without matching its instance AID is reported
 * as file-not-found uniformly, so the JCRE can continue the SELECT loop.
 *
 * @author card42
 */

public abstract class AppletBase extends Applet {

    protected AppletBase() {
    }

    /**
     * Processes incoming APDUs.
     *
     * @see javacard.framework.Applet#process(javacard.framework.APDU)
     */
    public void process(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        validateCla(apduBuffer);

        if (selectingApplet()) {
            onSelect(apdu, apduBuffer);
            return;
        }

        if (apduBuffer[ISO7816.OFFSET_INS] == (byte) ISO7816.INS_SELECT
                && rejectUnmatchedSelect()) {
            // A SELECT by name that reaches this applet did not match its AID,
            // so the applet is not selected: report file-not-found so the JCRE
            // can continue the SELECT loop.
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        processCommand(apdu, apduBuffer);
    }

    /**
     * Whether a non-selecting SELECT (INS=A4) must be answered with
     * file-not-found.  True by default (the EMV SELECT-by-name contract); an
     * applet that uses A4 for SELECT FILE (eMRTD, ISO/IEC 7816-4) overrides it
     * to false so the command reaches {@link #processCommand}.
     */
    protected boolean rejectUnmatchedSelect() {
        return true;
    }

    /**
     * Validates the class byte before any command is dispatched.  The default
     * accepts every class byte; a concrete applet overrides it to enforce the
     * class categories of its specification.
     */
    protected void validateCla(byte[] apduBuffer) {
    }

    /**
     * Handles a SELECT that selected this applet: sends the FCI and resets the
     * per-session state.  Implemented by the concrete base class.
     */
    protected abstract void onSelect(APDU apdu, byte[] apduBuffer);

    /**
     * Handles a command APDU addressed to this applet (i.e. after SELECT).
     * Implemented by the concrete applet.
     */
    protected abstract void processCommand(APDU apdu, byte[] apduBuffer);

    /**
     * Zeroizes session-derived material when the applet is deselected.  The
     * default is a no-op.
     */
    public void deselect() {
        onDeselect();
    }

    /** Called on deselection; the default is a no-op. */
    protected void onDeselect() {
    }
}
