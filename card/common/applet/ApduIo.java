package card42.common;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* Shared short-APDU command-data reception and response transmission.
 *
 * Every command handler that consumes a short-APDU data field has to pull the
 * declared Lc bytes into apduBuffer[OFFSET_CDATA...], looping because the card
 * may deliver them in more than one setIncomingAndReceive()/receiveBytes()
 * chunk.  Keeping the loop in one place avoids five copies that could drift
 * (PaymentApplet, PostIssuance, IssuerAuth, DynamicAuth).
 *
 * The response side already had the same shape: setOutgoing(),
 * setOutgoingLength(), sendBytesLong().  {@link #send} keeps that in one place
 * too.
 *
 * This is the short-APDU path only; extended-length command data is out of
 * scope for this implementation (EMV v4.4 Book 3 §6.3).
 *
 * @author card42
 */

public final class ApduIo implements ISO7816 {

    private ApduIo() {
    }

    /**
     * Receives the command data field of the current APDU into the APDU buffer
     * and returns its declared length Lc.  Throws 6700 (wrong length) when fewer
     * bytes than Lc are delivered, so a truncated command never reaches a
     * handler.
     */
    public static short receive(APDU apdu, byte[] apduBuffer) {
        short lc = (short) (apduBuffer[OFFSET_LC] & 0xFF);
        short received = apdu.setIncomingAndReceive();
        while (received < lc) {
            short more = apdu.receiveBytes((short) (OFFSET_CDATA + received));
            if (more <= 0) {
                break;
            }
            received += more;
        }
        if (received < lc) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        return lc;
    }

    /**
     * Sends {@code len} bytes of {@code buf} as the response data field:
     * setOutgoing() + setOutgoingLength() + sendBytesLong().  The caller keeps
     * ownership of the buffer; the JCRE copies to the transport.
     */
    public static void send(APDU apdu, byte[] buf, short off, short len) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(buf, off, len);
    }
}
