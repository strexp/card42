package card42.emv;

import card42.common.*;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* Post-issuance commands (EMV v4.4 Book 3 §10.10): APPLICATION BLOCK /
 * UNBLOCK, CARD BLOCK and PIN CHANGE/UNBLOCK.
 *
 * Every one of them must be Format 1 secure messaging (CLA low nibble C) with
 * a valid MAC; a plaintext request is refused with 6985.  CARD BLOCK is
 * applied to the whole card, so it calls back into the applet base.
 *
 * PIN CHANGE/UNBLOCK is chainable (EMV v4.4 Book 3 §6.5.13): a non-final
 * fragment (CLA b5=1) is unwrapped and MAC-verified but performs no state
 * change; the applet applies the action only for the last fragment.
 *
 * @author card42
 */

public class PostIssuance implements ISO7816 {

    private final EMVAppletBase applet;
    private final EMVProtocolState protocolState;
    private final SecureMessaging secureMessaging;
    private final OfflinePinState pin;

    public PostIssuance(EMVAppletBase applet, EMVProtocolState protocolState,
            SecureMessaging secureMessaging, OfflinePinState pin) {
        this.applet = applet;
        this.protocolState = protocolState;
        this.secureMessaging = secureMessaging;
        this.pin = pin;
    }

    public void postIssuance(APDU apdu, byte[] apduBuffer, byte ins, byte[] response,
            boolean chained) {
        // A repeated CARD BLOCK is accepted and reports 9000 (EMV v4.4 Book 3
        // §6.5.3.5); every other post-issuance command is refused once blocked.
        if (protocolState.getLifecycle() == EMVRoles.CARD_BLOCKED && ins != EMVCommands.INS_CARD_BLOCK) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
        }
        if ((apduBuffer[OFFSET_CLA] & 0x0F) != 0x0C) {
            // Only Format 1 secure messaging is accepted (EMV v4.4 Book 2 §9.2).
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // 6985
        }
        if (!secureMessaging.hasMacKey()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // 6985
        }
        if (protocolState.getFirstACGenerated() == EMVCodes.NONE) {
            // The MAC chain starts from the first GENERATE AC of the session.
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // 6985
        }
        if (apduBuffer[OFFSET_P1] != 0x00) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }
        // Every post-issuance command of this set requires P2='00'; any other
        // value is RFU (EMV v4.4 Book 3 Tables 6/7/8).
        if (apduBuffer[OFFSET_P2] != 0x00) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }

        short lc = ApduIo.receive(apdu, apduBuffer);

        secureMessaging.prepare(protocolState.getArqc(), (short) 0);
        secureMessaging.unwrap(apduBuffer, OFFSET_CDATA, lc,
                protocolState.getArqc(), response, (short) 0);

        if (chained) {
            // Not the last command of the chain: the secure-messaging data was
            // verified and the MAC chain advanced, but the state change is
            // deferred to the last command (EMV v4.4 Book 3 §6.5.13).
            apdu.setOutgoingAndSend((short) 0, (short) 0); // 9000
            return;
        }

        switch (ins) {
        case EMVCommands.INS_APPLICATION_BLOCK:
            // Invalidate the application (EMV v4.4 Book 3 section 6.5.1).
            protocolState.setLifecycle(EMVRoles.BLOCKED);
            break;
        case EMVCommands.INS_APPLICATION_UNBLOCK:
            // Remove the APPLICATION BLOCK restriction (EMV v4.4 Book 3 section 6.5.2).
            if (protocolState.getLifecycle() == EMVRoles.BLOCKED) {
                protocolState.setLifecycle(EMVRoles.READY);
            }
            break;
        case EMVCommands.INS_CARD_BLOCK:
            // Permanently disable every application (EMV v4.4 Book 3 section 6.5.3).
            protocolState.setLifecycle(EMVRoles.CARD_BLOCKED);
            applet.blockCard();
            break;
        case EMVCommands.INS_PIN_CHANGE_UNBLOCK:
            // P2=00 only (P2=01/02, PIN change, is payment-system proprietary
            // and is already refused above as a non-zero P2): reset the PIN Try
            // Counter to the PIN Try Limit and unblock the PIN (EMV v4.4 Book 3 §6.5.10).
            pin.resetAndUnblock();
            break;
        default:
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            break;
        }

        apdu.setOutgoingAndSend((short) 0, (short) 0); // 9000
    }
}
