package card42.test;

import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Deque;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.kernel.data.Cvm;
import card42.host.common.codec.TlvWriter;
import card42.host.emv.kernel.core.PinProvider;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.cvm.OfflinePinCvm;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.data.Tvr;
import card42.host.emv.lib.Terminal;

/**
 * Pure-JVM tests for {@link OfflinePinCvm}: the PIN Try
 * Counter read before offline PIN (EMV v4.4 Book 4 §6.3.4.1), the blocked-PIN
 * status words, and the PIN-not-entered path.  A scripted {@link CardChannel}
 * serves GET DATA '9F17' and the VERIFY response.
 */
final class OfflinePinCvmTest {

    private OfflinePinCvmTest() {
    }

    static void run() {
        System.out.println("OfflinePinCvm");

        // A zero PIN Try Counter skips PIN entry, sets 'PIN try limit exceeded'
        // and sends no VERIFY (EMV v4.4 Book 4 §6.3.4.1).
        PinChannel ch = new PinChannel();
        ch.ptc = 0;
        TransactionRequest data = new TransactionRequest(TerminalConfig.forContact().build());
        TransactionResult.Mutable result = new TransactionResult.Mutable().tvr(Tvr.blank());
        OfflinePinCvm cvm = new OfflinePinCvm(pin("1234"), new Terminal(ch), data,
                result);
        Asserts.eq(Cvm.RESULT_FAILED, cvm.perform(Cvm.CVM_PLAINTEXT_PIN_ICC, 0),
                "PTC=0 offline PIN fails");
        Asserts.check(Tvr.isSet(result.tvr(), 2, Tvr.PIN_TRY_LIMIT_EXCEEDED),
                "PTC=0 sets PIN try limit exceeded");
        Asserts.eq(0, ch.verifies, "PTC=0 sends no VERIFY");

        // A successful VERIFY reports successful and sets no failure bit.
        ch = new PinChannel();
        ch.ptc = 3;
        ch.push(0x9000);
        data = new TransactionRequest(TerminalConfig.forContact().build());
        result = new TransactionResult.Mutable().tvr(Tvr.blank());
        cvm = new OfflinePinCvm(pin("1234"), new Terminal(ch), data, result);
        Asserts.eq(Cvm.RESULT_SUCCESSFUL, cvm.perform(Cvm.CVM_PLAINTEXT_PIN_ICC, 0),
                "successful offline PIN");
        Asserts.eq(1, ch.verifies, "one VERIFY was sent");
        Asserts.check(!Tvr.isSet(result.tvr(), 2, Tvr.PIN_TRY_LIMIT_EXCEEDED),
                "successful PIN leaves the try limit bit clear");

        // VERIFY '6984' (PIN data unusable) fails and sets the try limit bit.
        ch = new PinChannel();
        ch.ptc = 3;
        ch.push(0x6984);
        data = new TransactionRequest(TerminalConfig.forContact().build());
        result = new TransactionResult.Mutable().tvr(Tvr.blank());
        cvm = new OfflinePinCvm(pin("1234"), new Terminal(ch), data, result);
        Asserts.eq(Cvm.RESULT_FAILED, cvm.perform(Cvm.CVM_PLAINTEXT_PIN_ICC, 0),
                "6984 offline PIN fails");
        Asserts.check(Tvr.isSet(result.tvr(), 2, Tvr.PIN_TRY_LIMIT_EXCEEDED),
                "6984 sets PIN try limit exceeded");

        // VERIFY '63C0' (no tries left) also sets the bit.
        ch = new PinChannel();
        ch.ptc = 1;
        ch.push(0x63C0);
        data = new TransactionRequest(TerminalConfig.forContact().build());
        result = new TransactionResult.Mutable().tvr(Tvr.blank());
        cvm = new OfflinePinCvm(pin("1234"), new Terminal(ch), data, result);
        Asserts.eq(Cvm.RESULT_FAILED, cvm.perform(Cvm.CVM_PLAINTEXT_PIN_ICC, 0),
                "63C0 offline PIN fails");
        Asserts.check(Tvr.isSet(result.tvr(), 2, Tvr.PIN_TRY_LIMIT_EXCEEDED),
                "63C0 sets PIN try limit exceeded");

        // VERIFY '63C1' (one try remaining) fails but does not set the bit.
        ch = new PinChannel();
        ch.ptc = 2;
        ch.push(0x63C1);
        data = new TransactionRequest(TerminalConfig.forContact().build());
        result = new TransactionResult.Mutable().tvr(Tvr.blank());
        cvm = new OfflinePinCvm(pin("1234"), new Terminal(ch), data, result);
        Asserts.eq(Cvm.RESULT_FAILED, cvm.perform(Cvm.CVM_PLAINTEXT_PIN_ICC, 0),
                "63C1 offline PIN fails");
        Asserts.check(!Tvr.isSet(result.tvr(), 2, Tvr.PIN_TRY_LIMIT_EXCEEDED),
                "63C1 leaves the try limit bit clear");

        // A bypassed PIN entry (provider returns null) sets 'PIN not entered'.
        ch = new PinChannel();
        ch.ptc = 3;
        data = new TransactionRequest(TerminalConfig.forContact().build());
        result = new TransactionResult.Mutable().tvr(Tvr.blank());
        cvm = new OfflinePinCvm(pin(null), new Terminal(ch), data, result);
        Asserts.eq(Cvm.RESULT_FAILED, cvm.perform(Cvm.CVM_PLAINTEXT_PIN_ICC, 0),
                "bypassed PIN fails");
        Asserts.check(Tvr.isSet(result.tvr(), 2, Tvr.PIN_NOT_ENTERED),
                "bypassed PIN sets PIN not entered");
        Asserts.eq(0, ch.verifies, "bypassed PIN sends no VERIFY");
    }

    private static PinProvider pin(final String value) {
        return new PinProvider() {
            @Override
            public String pin() {
                return value;
            }
        };
    }

    /** A CardChannel serving GET DATA '9F17' and queued VERIFY responses. */
    private static final class PinChannel extends CardChannel {
        int ptc = 3;
        int verifies;
        private final Deque<ResponseAPDU> responses = new ArrayDeque<ResponseAPDU>();

        void push(int sw) {
            responses.add(new ResponseAPDU(new byte[] { (byte) (sw >> 8), (byte) sw }));
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
        public ResponseAPDU transmit(CommandAPDU command) throws CardException {
            if (command.getINS() == 0xCA) { // GET DATA '9F17'
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                TlvWriter.writeTlv(out, 0x9F17, new byte[] { (byte) ptc });
                return ok(out.toByteArray());
            }
            if (command.getINS() == 0x20) { // VERIFY
                verifies++;
                ResponseAPDU r = responses.poll();
                return r != null ? r : ok(new byte[0]);
            }
            throw new CardException("unexpected command");
        }

        private static ResponseAPDU ok(byte[] data) {
            byte[] full = new byte[data.length + 2];
            System.arraycopy(data, 0, full, 0, data.length);
            full[data.length] = (byte) 0x90;
            full[data.length + 1] = 0x00;
            return new ResponseAPDU(full);
        }

        @Override
        public int transmit(ByteBuffer command, ByteBuffer response) throws CardException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void close() throws CardException {
        }
    }
}
