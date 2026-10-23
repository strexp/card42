package card42.host.emv.cli.command;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.cli.Args;
import card42.host.common.util.Hex;
import card42.host.common.util.Sw;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.kernel.data.TerminalDol;
import card42.host.emv.crypto.ScriptSession;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.core.TransactionResultWriter;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.lib.Responses;
import card42.host.emv.lib.TagPolicy;
import card42.host.emv.lib.Terminal;
import card42.host.common.codec.Tags;

/**
 * Transport/session bootstrap for the {@code card} command family: the option
 * arrays, the AID, the interactive CARD BLOCK confirmation and the
 * secure-messaging session establishment (SELECT -&gt; GPO -&gt; first
 * GENERATE AC -&gt; derive the MAC/ENC session keys, EMV v4.4 Book 2 §9.2).
 *
 * <p>Split out of {@link CardCommand} so the command class holds only the
 * subcommand dispatch and the usage text.
 */
final class CardSession {

    static final String DEFAULT_AID = "43415244420101";

    static final String[] BASE_VALUE = { "host", "wait", "aid" };
    static final String[] BASE_FLAG = { "trace" };
    static final String[] POST_VALUE = { "host", "wait", "aid", "mac-key", "enc-key" };
    static final String[] BLOCK_VALUE = { "host", "wait", "aid", "mac-key", "enc-key" };
    static final String[] BLOCK_FLAG = { "trace", "yes" };
    static final String[] GET_VALUE = { "host", "wait", "aid", "tag" };
    static final String[] PIN_CHANGE_VALUE = {
        "host", "wait", "aid", "mac-key", "enc-key", "old", "new",
    };
    static final String[] PIN_FLAG = { "trace", "yes" };
    static final String[] PIN_UNBLOCK_VALUE = {
        "host", "wait", "aid", "mac-key", "enc-key", "puk", "new",
    };

    private CardSession() {
    }

    static String aid(Args args) {
        return args.get("aid", DEFAULT_AID);
    }

    /**
     * Opens a transaction and returns a secure-messaging session keyed on its
     * first AC.  A blocked application answers SELECT with 6283 and no FCI, so
     * the GPO is skipped for it (the card still serves GENERATE AC and the
     * post-issuance commands).  The steps are SELECT → GET PROCESSING OPTIONS
     * (EMV v4.4 Book 3 §6.5.8) → READ RECORD 1 → first GENERATE AC
     * (EMV v4.4 Book 3 §6.5.5); the AC/ARPC session keys derive from the first
     * AC (EMV v4.4 Book 2 §8.2).
     */
    static ScriptSession establishSession(Terminal terminal, String aid,
            byte[] macKey, byte[] encKey) throws Exception {
        ResponseAPDU sel = terminal.select(aid);
        if (sel.getSW() == 0x9000) {
            TransactionRequest data = new TransactionRequest(TerminalConfig.forContact().build());
            TransactionResultWriter result = TransactionResult.newWriter();
            data.applicationIdentifier = Hex.parse(aid);
            byte[] pdol = TagPolicy.findIcc(sel.getData(), 0x9F38);
            byte[] pdolData = TerminalDol.buildDolData(data, result,
                    pdol == null ? new byte[0] : pdol);
            ResponseAPDU gpo = terminal.gpo(pdolData);
            if (gpo.getSW() != 0x9000) {
                throw new IllegalStateException("GPO -> " + Sw.format(gpo.getSW()));
            }
        } else if (sel.getSW() != 0x6283) {
            throw new IllegalStateException("SELECT " + aid + " -> " + Sw.format(sel.getSW()));
        }
        ResponseAPDU record = terminal.readRecord(1, 1);
        if (record.getSW() != 0x9000) {
            throw new IllegalStateException("READ RECORD 1 -> " + Sw.format(record.getSW()));
        }
        byte[] cdol1 = Tags.find(record.getData(), 0x8C);
        int length = cdol1 == null ? 0 : TerminalDol.dolDataLength(cdol1);
        ResponseAPDU first = terminal.generateAc((byte) 0x80, length);
        if (first.getSW() != 0x9000) {
            throw new IllegalStateException("first GENERATE AC -> " + Sw.format(first.getSW()));
        }
        byte[] arqc = Responses.parseAc(first).ac;
        if (arqc == null || arqc.length != 8) {
            throw new IllegalStateException("first AC is not an 8-byte cryptogram");
        }
        ScriptSession session = new ScriptSession(macKey, encKey);
        session.start(arqc);
        return session;
    }

    /** Interactive confirmation for the irreversible CARD BLOCK. */
    static boolean confirmed(Args args) {
        if (args.has("yes")) {
            return true;
        }
        System.out.print("CARD BLOCK is irreversible; type 'yes' to continue: ");
        System.out.flush();
        try {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(System.in, StandardCharsets.UTF_8));
            String line = reader.readLine();
            return line != null && line.trim().equalsIgnoreCase("yes");
        } catch (Exception e) {
            return false;
        }
    }

    static void print(String name, ResponseAPDU r) {
        String data = r.getData() == null || r.getData().length == 0
                ? "" : " " + Hex.format(r.getData());
        System.out.println(name + ": SW=" + Sw.format(r.getSW()) + data);
    }
}
