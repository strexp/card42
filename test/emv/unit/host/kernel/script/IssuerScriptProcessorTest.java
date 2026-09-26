package card42.test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Deque;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.TlvWriter;
import card42.host.emv.kernel.data.Tvr;
import card42.host.emv.kernel.script.IssuerScriptProcessor;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for {@link IssuerScriptProcessor}
 * (EMV v4.4 Book 3 §10.10, Book 4 §6.3.9/§12.2.4): the script template
 * parsing, the 128-byte cumulative command-data limit, and the warning status
 * word rule, none of which the end-to-end suites exercised.
 *
 * <p>A scripted {@link CardChannel} returns the status words in order, so the
 * processor can be driven without a card.
 */
final class IssuerScriptProcessorTest {

    private IssuerScriptProcessorTest() {
    }

    static void run() throws Exception {
        System.out.println("IssuerScriptProcessor");

        // A 'warning' SW1 ('62'/'63') is not a failure: the next command is
        // still sent and the script is reported successful (result 2).
        ScriptChannel ch = new ScriptChannel();
        ch.push(0x6200);
        ch.push(0x9000);
        IssuerScriptProcessor.Result r = IssuerScriptProcessor.process(
                new Terminal(ch), false, script(0x71, Hex.parse("01020304"), cmd(), cmd()));
        Asserts.check(!r.anyFailed, "warning SW does not fail the script");
        Asserts.eq(2, r.commandsSent, "commands after a warning are still sent");
        Asserts.eq(0x20, r.results[0] & 0xFF, "successful script result nibble");
        Asserts.bytes(Hex.parse("01020304"),
                java.util.Arrays.copyOfRange(r.results, 1, 5), "script identifier reported");

        // A '63' warning SW1 continues as well.
        ch = new ScriptChannel();
        ch.push(0x6300);
        ch.push(0x9000);
        r = IssuerScriptProcessor.process(new Terminal(ch), false,
                script(0x71, null, cmd(), cmd()));
        Asserts.check(!r.anyFailed, "63 warning SW does not fail the script");
        Asserts.eq(2, r.commandsSent, "commands after a 63 warning are still sent");

        // An 'error' SW1 stops the script; the failing sequence is reported and
        // the before-final-AC flag is set.
        ch = new ScriptChannel();
        ch.push(0x6A80);
        ch.push(0x9000);
        r = IssuerScriptProcessor.process(new Terminal(ch), false,
                script(0x71, Hex.parse("0A0B0C0D"), cmd(), cmd()));
        Asserts.check(r.anyFailed, "hard failure fails the script");
        Asserts.check(r.failedBeforeFinalAc, "before-final-AC failure flag set");
        Asserts.check(!r.failedAfterFinalAc, "after-final-AC failure flag clear");
        Asserts.eq(1, r.commandsSent, "the script stops at the failing command");
        Asserts.eq(0x11, r.results[0] & 0xFF, "failed script result with sequence 1");
        byte[] tvr = Tvr.blank();
        IssuerScriptProcessor.applyToTvr(r, tvr);
        Asserts.check(Tvr.isSet(tvr, 4, Tvr.SCRIPT_FAILED_BEFORE_FINAL_AC),
                "TVR before-final-AC bit set");

        // A script received after the final GENERATE AC selects the other TVR bit.
        ch = new ScriptChannel();
        ch.push(0x6A80);
        r = IssuerScriptProcessor.process(new Terminal(ch), true, script(0x72, null, cmd()));
        Asserts.check(r.failedAfterFinalAc && !r.failedBeforeFinalAc,
                "after-final-AC failure flag set");
        tvr = Tvr.blank();
        IssuerScriptProcessor.applyToTvr(r, tvr);
        Asserts.check(Tvr.isSet(tvr, 4, Tvr.SCRIPT_FAILED_AFTER_FINAL_AC),
                "TVR after-final-AC bit set");

        // A template that does not parse is reported as 'not performed'
        // (9F5B byte 1 result 0) and the remaining scripts are still processed.
        ch = new ScriptChannel();
        ch.push(0x9000);
        r = IssuerScriptProcessor.process(new Terminal(ch), false,
                Hex.parse("6F00"), script(0x71, null, cmd()));
        Asserts.eq(0x00, r.results[0] & 0xFF, "unparseable script result 0");
        // Annex E Scenario 3: an unparseable script sets the TVR script bit.
        Asserts.check(r.anyFailed && r.failedBeforeFinalAc,
                "unparseable script is a failure (Book 3 Annex E Scenario 3)");
        Asserts.eq(1, r.commandsSent, "only the later script was sent");
        Asserts.eq(0x20, r.results[5] & 0xFF, "later script reported successful");

        // More than 128 bytes of command data is reported as 'not performed'
        // (EMV v4.4 Book 4 §6.3.9/§12.2.4), sets the TVR bits, and no command
        // is sent.
        ch = new ScriptChannel();
        r = IssuerScriptProcessor.process(new Terminal(ch), false,
                script(0x71, Hex.parse("01020304"), new byte[129]),
                script(0x71, null, cmd()));
        Asserts.eq(0x00, r.results[0] & 0xFF, "oversized script result 0");
        Asserts.check(r.anyFailed && r.failedBeforeFinalAc, "oversized script is a failure");
        Asserts.eq(0, r.commandsSent, "no command is sent after a length error");
        Asserts.eq(0x00, r.results[5] & 0xFF,
                "later script is not performed once the total exceeds 128 bytes");

        // The 128-byte limit is cumulative across all Issuer Scripts in the
        // response: two 100-byte scripts exceed it, so the second is not
        // performed (EMV v4.4 Book 4 §6.3.9/§12.2.4).
        ch = new ScriptChannel();
        r = IssuerScriptProcessor.process(new Terminal(ch), false,
                script(0x71, null, cmds(20)),
                script(0x71, null, cmds(20)));
        Asserts.eq(0x20, r.results[0] & 0xFF, "first 100-byte script is performed");
        Asserts.eq(0x00, r.results[5] & 0xFF,
                "script exceeding the cumulative 128-byte limit is not performed");
        Asserts.check(r.anyFailed, "cumulative length error is a failure");
        Asserts.eq(20, r.commandsSent, "only the first script was sent");
    }

    /** n copies of the short command APDU (5 bytes each). */
    private static byte[][] cmds(int n) {
        byte[][] commands = new byte[n][];
        for (int i = 0; i < n; i++) {
            commands[i] = cmd();
        }
        return commands;
    }

    /** A valid short command APDU used as an 86 Issuer Script Command value. */
    private static byte[] cmd() {
        return Hex.parse("00A4040000");
    }

    /** Builds a 71/72 Issuer Script template with an optional 9F18 and 86 commands. */
    private static byte[] script(int tag, byte[] scriptId, byte[]... commands) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        if (scriptId != null) {
            TlvWriter.writeTlv(body, 0x9F18, scriptId);
        }
        for (byte[] command : commands) {
            TlvWriter.writeTlv(body, 0x86, command);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, body.toByteArray());
        return out.toByteArray();
    }

    /** A CardChannel returning queued status words in order. */
    private static final class ScriptChannel extends CardChannel {
        private final Deque<ResponseAPDU> responses = new ArrayDeque<ResponseAPDU>();

        void push(int sw) {
            responses.add(new ResponseAPDU(
                    new byte[] { (byte) (sw >> 8), (byte) sw }));
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
            ResponseAPDU r = responses.poll();
            return r != null ? r : new ResponseAPDU(new byte[] { (byte) 0x90, 0x00 });
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
