package card42.test;

import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.transport.Terminal;
import card42.host.common.util.Hex;

/**
 * Unit tests for the T=0 response retrieval in the host transport
 * (EMV v4.1 Book 1 §9.3.1.2 step 4 / §9.3.1.3 Table 32; the transport moved
 * to the EMV Contact Interface Specification in v4.4 Book 1).
 *
 * <p>The JDK's implicit handling is disabled in {@code Terminals} because it
 * issues the GET RESPONSE with the CLA of the command that returned
 * {@code '61 xx'}; these tests pin the EMV {@code CLA='00'} behaviour.
 */
final class TerminalT0Test {

    private TerminalT0Test() {
    }

    static void run() throws Exception {
        System.out.println("TerminalT0");

        // '61 0C': the terminal retrieves the 12 bytes with GET RESPONSE
        // CLA='00' and concatenates them with the final status word.
        ScriptedChannel getResponse = new ScriptedChannel();
        getResponse.add("610C");
        getResponse.add("800A180008010100180102009000");
        ResponseAPDU r = new Terminal(getResponse).transmit(new CommandAPDU(
                0x80, 0xA8, 0x00, 0x00, new byte[] { (byte) 0x83, 0x00 }, 256));
        Asserts.eq(0x9000, r.getSW(), "final SW is the GET RESPONSE SW");
        Asserts.bytes(Hex.parse("800A18000801010018010200"), r.getData(),
                "data retrieved via GET RESPONSE");
        Asserts.eq(2, getResponse.commands.size(), "one GET RESPONSE was issued");
        Asserts.bytes(Hex.parse("00C000000C"), getResponse.commands.get(1).getBytes(),
                "GET RESPONSE is CLA='00' INS='C0' Le=SW2");

        // A normal '9000' response passes through unchanged.
        ScriptedChannel normal = new ScriptedChannel();
        normal.add("6F0384009000");
        ResponseAPDU n = new Terminal(normal).transmit(Hex.parse("00A4040000"));
        Asserts.eq(0x9000, n.getSW(), "normal response SW");
        Asserts.eq(1, normal.commands.size(), "no extra exchange for a normal response");

        // '6C xx': the command is resent with Le='xx'.
        ScriptedChannel wrongLe = new ScriptedChannel();
        wrongLe.add("6C0C");
        wrongLe.add("9000");
        ResponseAPDU l = new Terminal(wrongLe).transmit(Hex.parse("00B2010C00"));
        Asserts.eq(0x9000, l.getSW(), "resend SW");
        Asserts.bytes(Hex.parse("00B2010C0C"), wrongLe.commands.get(1).getBytes(),
                "resend uses Le=SW2");
    }

    /** A CardChannel that answers a scripted list of R-APDUs in order. */
    private static final class ScriptedChannel extends CardChannel {

        final List<CommandAPDU> commands = new ArrayList<CommandAPDU>();
        private final Deque<ResponseAPDU> responses = new ArrayDeque<ResponseAPDU>();

        void add(String responseHex) {
            responses.add(new ResponseAPDU(Hex.parse(responseHex)));
        }

        @Override
        public Card getCard() {
            throw new UnsupportedOperationException();
        }

        @Override
        public int getChannelNumber() {
            return 0;
        }

        @Override
        public ResponseAPDU transmit(CommandAPDU command) {
            commands.add(command);
            ResponseAPDU response = responses.poll();
            if (response == null) {
                throw new IllegalStateException("unexpected command "
                        + Hex.format(command.getBytes()));
            }
            return response;
        }

        @Override
        public int transmit(ByteBuffer command, ByteBuffer response) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void close() {
        }
    }
}
