package card42.host.common.transport;

import java.io.ByteArrayOutputStream;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.util.Hex;

/**
 * Generic card terminal: a thin wrapper around a {@link CardChannel} that sends
 * raw APDUs and performs a SELECT by name (ISO/IEC 7816-4).  It carries no EMV
 * or eMRTD semantics; the media-specific convenience methods live in the
 * business modules ({@code card42.host.emv.lib.Terminal} and, later,
 * {@code card42.host.emrtd.*}).
 */
public class Terminal {

    private final CardChannel channel;

    public Terminal(CardChannel channel) {
        this.channel = channel;
    }

    /** The underlying channel (e.g. to build a traced or business wrapper). */
    public CardChannel getChannel() {
        return channel;
    }

    /**
     * Sends a command APDU and completes the T=0 response retrieval.
     *
     * <p>EMV v4.4 Book 1 removed Part II (transport protocols) and defers to
     * the EMV Contact Interface Specification; the equivalent EMV v4.1 Book 1
     * §9.3.1.2 step 4 / §9.3.1.3 Table 32 defines the GET RESPONSE command as
     * {@code CLA='00' INS='C0' P1='00' P2='00' Le=length}.  The JDK's SunPCSC
     * implicit handling instead reuses the CLA of the command that returned
     * {@code '61 xx'} (a {@code '80 C0'} GET RESPONSE for GPO), which strict
     * cards reject with {@code '6E00'}; {@link Terminals} therefore disables it
     * and this method performs the retrieval itself.
     */
    public ResponseAPDU transmit(CommandAPDU command) throws Exception {
        ResponseAPDU response = channel.transmit(command);
        ByteArrayOutputStream data = null;
        for (int iterations = 0; ; iterations++) {
            if (iterations > MAX_RESPONSE_ITERATIONS) {
                throw new IllegalStateException("T=0 response iterations exceeded");
            }
            int sw1 = response.getSW1();
            int sw2 = response.getSW2();
            if (sw1 == 0x61) {
                // '61 xx': xx bytes are available; retrieve them with GET
                // RESPONSE (EMV v4.1 Book 1 §9.3.1.3 Table 32).
                data = collect(data, response);
                response = channel.transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, sw2));
                continue;
            }
            if (sw1 == 0x6C) {
                // '6C xx': wrong Le; resend the command with Le='xx'
                // (EMV v4.1 Book 1 §9.3.1.2 step 4, Annex A).
                data = collect(data, response);
                response = channel.transmit(withLe(command, sw2));
                continue;
            }
            if (data == null) {
                return response; // no retrieval was needed
            }
            data = collect(data, response);
            byte[] out = new byte[data.size() + 2];
            System.arraycopy(data.toByteArray(), 0, out, 0, data.size());
            out[out.length - 2] = (byte) sw1;
            out[out.length - 1] = (byte) sw2;
            return new ResponseAPDU(out);
        }
    }

    /** Appends a response's data to the accumulator, creating it on first use. */
    private static ByteArrayOutputStream collect(ByteArrayOutputStream data, ResponseAPDU response) {
        ByteArrayOutputStream out = data == null ? new ByteArrayOutputStream() : data;
        byte[] bytes = response.getData();
        out.write(bytes, 0, bytes.length);
        return out;
    }

    /** Bound on the T=0 '61 xx'/'6C xx' retrieval loop (a runaway card). */
    private static final int MAX_RESPONSE_ITERATIONS = 64;

    /** The command with Le replaced by (or appended as) {@code le}. */
    private static CommandAPDU withLe(CommandAPDU command, int le) {
        byte[] bytes = command.getBytes();
        if (command.getNe() >= 0) {
            bytes[bytes.length - 1] = (byte) le;
            return new CommandAPDU(bytes);
        }
        byte[] extended = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0, extended, 0, bytes.length);
        extended[bytes.length] = (byte) le;
        return new CommandAPDU(extended);
    }

    /** Sends a raw command APDU. */
    public ResponseAPDU transmit(byte[] rawCommand) throws Exception {
        return transmit(new CommandAPDU(rawCommand));
    }

    /** SELECT by AID (hex string). */
    public ResponseAPDU select(String aidHex) throws Exception {
        return select(Hex.parse(aidHex));
    }

    /** SELECT by AID (raw bytes): CLA=00 INS=A4 P1=04 P2=00 Lc AID. */
    public ResponseAPDU select(byte[] aid) throws Exception {
        byte[] c = new byte[5 + aid.length];
        c[0] = (byte) 0x00;
        c[1] = (byte) 0xA4;
        c[2] = (byte) 0x04;
        c[3] = (byte) 0x00;
        c[4] = (byte) aid.length;
        System.arraycopy(aid, 0, c, 5, aid.length);
        return transmit(new CommandAPDU(c));
    }
}
