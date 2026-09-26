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
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.entry.PseSelection;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Hex;

/**
 * APDU-level unit tests for {@link PseSelection} (EMV v4.4 Book 1 §12.3):
 * PSE directory selection, the List of AIDs fallback, the 6A81 terminate-session
 * rule and the candidate reselection used after a GET PROCESSING OPTIONS '6985'.
 */
final class PseSelectionTest {

    private static final String PSE_AID = "315041592E5359532E4444463031";
    private static final String AID_A = "43415244420101";
    private static final String AID_B = "43415244420102";

    private PseSelectionTest() {
    }

    static void run() throws Exception {
        System.out.println("PseSelectionTest");

        // PSE directory: two candidates, AID_A (priority 1) first.
        QueueChannel pse = new QueueChannel();
        pse.add(0x9000, pseFci());
        pse.add(0x9000, directoryRecord(AID_A, 0x01, AID_B, 0x02));
        pse.add(0x6A83, null);
        pse.add(0x9000, adfFci(AID_A));
        pse.add(0x9000, adfFci(AID_B));
        PseSelection selection = new PseSelection(new String[] { AID_A, AID_B });
        Terminal terminal = new Terminal(pse);
        TransactionResult.Mutable result = new TransactionResult.Mutable();
        Asserts.eq(AID_A, selection.select(terminal, new TransactionRequest(TerminalConfig.builder().build()), result),
                "PSE directory selects the highest priority ADF");
        Asserts.eq(AID_A, result.aidHex(), "result carries the PSE-selected AID");
        Asserts.eq(AID_B, selection.reselect(terminal, new TransactionRequest(TerminalConfig.builder().build()), result),
                "reselect tries the next PSE candidate");
        Asserts.check(selection.reselect(terminal, new TransactionRequest(TerminalConfig.builder().build()), result) == null,
                "reselect returns null when the PSE candidates are exhausted");

        // PSE not supported: fall back to the List of AIDs.
        QueueChannel fallback = new QueueChannel();
        fallback.add(0x6A82, null);
        fallback.add(0x6A82, null); // SELECT AID_A refused
        fallback.add(0x9000, adfFci(AID_B));
        Asserts.eq(AID_B, new PseSelection(new String[] { AID_A, AID_B }).select(
                        new Terminal(fallback), new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable()),
                "List of AIDs fallback selects a supported ADF");

        // PSE SELECT 6A81 terminates the session (EMV v4.4 Book 1 §12.3.2 step 1).
        QueueChannel blocked = new QueueChannel();
        blocked.add(0x6A81, null);
        boolean terminated = false;
        try {
            new PseSelection(new String[] { AID_A }).select(
                    new Terminal(blocked), new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable());
        } catch (IllegalStateException e) {
            terminated = true;
        }
        Asserts.check(terminated, "PSE 6A81 terminates the session");

        // Any PSE status other than 9000/6A81 (e.g. 6283 blocked) falls back to
        // the List of AIDs method (EMV v4.4 Book 1 §12.3.2 step 1).
        QueueChannel other = new QueueChannel();
        other.add(0x6283, null);
        other.add(0x6A82, null); // SELECT AID_A refused
        other.add(0x9000, adfFci(AID_B));
        Asserts.eq(AID_B, new PseSelection(new String[] { AID_A, AID_B }).select(
                        new Terminal(other), new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable()),
                "PSE 6283 falls back to the List of AIDs");

        // A directory READ RECORD error clears the candidates and falls back to
        // the List of AIDs (EMV v4.4 Book 1 §12.3.2 step 2).
        QueueChannel readFail = new QueueChannel();
        readFail.add(0x9000, pseFci());
        readFail.add(0x6A80, null); // directory record read error
        readFail.add(0x6A82, null);
        readFail.add(0x9000, adfFci(AID_B));
        Asserts.eq(AID_B, new PseSelection(new String[] { AID_A, AID_B }).select(
                        new Terminal(readFail), new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable()),
                "directory read failure falls back to the List of AIDs");

        // A PSE FCI whose Directory SFI ('88') is missing, not one byte, or
        // outside 1-10 yields no candidate and falls back to the List of AIDs
        // (EMV v4.4 Book 1 §12.3.2 step 1).
        assertSfiFallback("missing 88", pseFciNoSfi());
        assertSfiFallback("88 length != 1", pseFciSfi(new byte[] { 0x00, 0x01 }));
        assertSfiFallback("88 = 00", pseFciSfi(new byte[] { 0x00 }));
        assertSfiFallback("88 = 0B", pseFciSfi(new byte[] { 0x0B }));

        // A successful PSE whose directory holds no supported candidate falls
        // back to the List of AIDs (EMV v4.4 Book 1 §12.3.2 step 5).
        QueueChannel noMatch = new QueueChannel();
        noMatch.add(0x9000, pseFci());
        noMatch.add(0x9000, directoryRecord(AID_B, 0x01, AID_B, 0x02));
        noMatch.add(0x6A83, null);
        noMatch.add(0x9000, adfFci(AID_A));
        Asserts.eq(AID_A, new PseSelection(new String[] { AID_A }).select(
                        new Terminal(noMatch), new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable()),
                "PSE with no supported candidate falls back to the List of AIDs");

        // The selected DF Name is written to terminal data object 9F06
        // (EMV v4.4 Book 1 §12.4).
        QueueChannel idChannel = new QueueChannel();
        idChannel.add(0x9000, pseFci());
        idChannel.add(0x9000, directoryRecord(AID_A, 0x01, AID_B, 0x02));
        idChannel.add(0x6A83, null);
        idChannel.add(0x9000, adfFci(AID_A));
        TransactionRequest tdata = new TransactionRequest(TerminalConfig.builder().build());
        new PseSelection(new String[] { AID_A, AID_B }).select(
                new Terminal(idChannel), tdata, new TransactionResult.Mutable());
        Asserts.bytes(Hex.parse(AID_A), tdata.applicationIdentifier,
                "terminal 9F06 set to the selected DF Name");

        // When the FCI returns a longer DF Name than the supported AID, 9F06
        // carries the full returned DF Name, not the terminal's AID.
        String longer = AID_A + "0102";
        QueueChannel prefixChannel = new QueueChannel();
        prefixChannel.add(0x9000, pseFci());
        prefixChannel.add(0x9000, directoryRecord(longer, 0x01, AID_B, 0x02));
        prefixChannel.add(0x6A83, null);
        prefixChannel.add(0x9000, adfFci(longer));
        TransactionRequest prefixData = new TransactionRequest(TerminalConfig.builder().build());
        new PseSelection(new String[] { AID_A, AID_B }).select(
                new Terminal(prefixChannel), prefixData, new TransactionResult.Mutable());
        Asserts.bytes(Hex.parse(longer), prefixData.applicationIdentifier,
                "terminal 9F06 set to the returned longer DF Name");
    }

    /** PSE SELECT 9000 with the given FCI, then the List of AIDs selects AID_B. */
    private static void assertSfiFallback(String what, byte[] fci) throws Exception {
        QueueChannel channel = new QueueChannel();
        channel.add(0x9000, fci);
        channel.add(0x6A82, null); // SELECT AID_A refused
        channel.add(0x9000, adfFci(AID_B));
        Asserts.eq(AID_B, new PseSelection(new String[] { AID_A, AID_B }).select(
                        new Terminal(channel), new TransactionRequest(TerminalConfig.builder().build()), new TransactionResult.Mutable()),
                "PSE with " + what + " falls back to the List of AIDs");
    }

    /** A PSE FCI: 6F { 84 <PSE DF Name>, 88 01 01 }. */
    private static byte[] pseFci() {
        return pseFciSfi(new byte[] { 0x01 });
    }

    /** A PSE FCI advertising the given Directory SFI ('88') value. */
    private static byte[] pseFciSfi(byte[] sfi) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x84, Hex.parse(PSE_AID));
        TlvWriter.writeTlv(body, 0x88, sfi);
        ByteArrayOutputStream fci = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fci, 0x6F, body.toByteArray());
        return fci.toByteArray();
    }

    /** A PSE FCI without the Directory SFI ('88'). */
    private static byte[] pseFciNoSfi() {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x84, Hex.parse(PSE_AID));
        ByteArrayOutputStream fci = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fci, 0x6F, body.toByteArray());
        return fci.toByteArray();
    }

    /** One PSE directory record: 70 { 61 { 4F a, 87 p } ... }. */
    private static byte[] directoryRecord(String aidA, int priorityA,
                                          String aidB, int priorityB) {
        ByteArrayOutputStream entries = new ByteArrayOutputStream();
        TlvWriter.writeTlv(entries, 0x61, entry(aidA, priorityA));
        TlvWriter.writeTlv(entries, 0x61, entry(aidB, priorityB));
        ByteArrayOutputStream record = new ByteArrayOutputStream();
        TlvWriter.writeTlv(record, 0x70, entries.toByteArray());
        return record.toByteArray();
    }

    private static byte[] entry(String aidHex, int priority) {
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(entry, 0x4F, Hex.parse(aidHex));
        TlvWriter.writeTlv(entry, 0x87, new byte[] { (byte) priority });
        return entry.toByteArray();
    }

    /** A minimal ADF FCI: 6F { 84 <AID> }. */
    private static byte[] adfFci(String aidHex) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x84, Hex.parse(aidHex));
        ByteArrayOutputStream fci = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fci, 0x6F, body.toByteArray());
        return fci.toByteArray();
    }

    /** A CardChannel answering from a FIFO of scripted responses. */
    private static final class QueueChannel extends CardChannel {
        private final Deque<ResponseAPDU> queue = new ArrayDeque<ResponseAPDU>();

        void add(int sw, byte[] data) {
            byte[] body = data == null ? new byte[0] : data;
            byte[] full = new byte[body.length + 2];
            System.arraycopy(body, 0, full, 0, body.length);
            full[body.length] = (byte) (sw >> 8);
            full[body.length + 1] = (byte) sw;
            queue.add(new ResponseAPDU(full));
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
            if (queue.isEmpty()) {
                throw new CardException("unexpected command INS=" + command.getINS());
            }
            return queue.removeFirst();
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
