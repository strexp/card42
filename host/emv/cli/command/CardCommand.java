package card42.host.emv.cli.command;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.Responses;
import card42.host.emv.lib.TagPolicy;
import card42.host.common.codec.Tags;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.crypto.SmCrypto;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.data.TerminalDol;
import card42.host.emv.lib.Terminal;
import card42.host.common.transport.TerminalSession;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;

/**
 * The {@code card} command family (docs/specs/common/toolchain.md §7.1): card-side
 * post-issuance and GET DATA operations for operations/debugging.
 *
 * <pre>
 *   card block-app [-aid=]        APPLICATION BLOCK   (EMV v4.4 Book 3 §6.5.1)
 *   card unblock-app [-aid=]      APPLICATION UNBLOCK (EMV v4.4 Book 3 §6.5.2)
 *   card block [-yes]             CARD BLOCK, irreversible (EMV v4.4 Book 3 §6.5.3)
 *   card pin-change -old= -new=   PIN change (EMV v4.4 Book 3 §6.5.10)
 *   card pin-unblock [-puk= -new=] PIN CHANGE/UNBLOCK P2=00 (EMV v4.4 Book 3 §6.5.10)
 *   card get-data -tag=           GET DATA for a 9Fxx tag (EMV v4.4 Book 3 §6.5.7)
 *   card atc                      ATC (9F36)
 *   card last-online-atc          last online ATC (9F13)
 * </pre>
 *
 * <p>The post-issuance commands (block/unblock/pin) require Format 1 secure
 * messaging (EMV v4.4 Book 2 §9.2), so the command first opens a transaction
 * (SELECT -> GPO -> first GENERATE AC) and derives the MAC/ENC session keys from
 * the first AC; {@code -mac-key} (and {@code -enc-key} for a PIN change) supply
 * the ICC master keys.  Exit codes: 0 success, 1 the card refused, 2 usage or
 * connection error.
 */
public final class CardCommand {

    private static final String DEFAULT_AID = "43415244420101";

    private static final String[] BASE_VALUE = { "host", "wait", "aid" };
    private static final String[] BASE_FLAG = { "trace" };
    private static final String[] POST_VALUE = { "host", "wait", "aid", "mac-key", "enc-key" };
    private static final String[] BLOCK_VALUE = { "host", "wait", "aid", "mac-key", "enc-key" };
    private static final String[] BLOCK_FLAG = { "trace", "yes" };
    private static final String[] GET_VALUE = { "host", "wait", "aid", "tag" };
    private static final String[] PIN_CHANGE_VALUE = {
        "host", "wait", "aid", "mac-key", "enc-key", "old", "new",
    };
    private static final String[] PIN_UNBLOCK_VALUE = {
        "host", "wait", "aid", "mac-key", "enc-key", "puk", "new",
    };

    private CardCommand() {
    }

    /** Dispatches a {@code card <subcommand>} invocation. */
    public static int run(String[] rest) throws Exception {
        if (rest.length == 0 || isHelp(rest[0])) {
            usage(rest.length == 0 ? System.err : System.out);
            return rest.length == 0 ? 2 : 0;
        }
        String[] options = Arrays.copyOfRange(rest, 1, rest.length);
        switch (rest[0]) {
        case "block-app": return postIssuance(options, 0x1E, "APPLICATION BLOCK", false);
        case "unblock-app": return postIssuance(options, 0x18, "APPLICATION UNBLOCK", false);
        case "block": return postIssuance(options, 0x16, "CARD BLOCK", true);
        case "pin-change": return pinChange(options);
        case "pin-unblock": return pinUnblock(options);
        case "get-data": return getData(options);
        case "atc": return atc(options, 0x36, "ATC");
        case "last-online-atc": return atc(options, 0x13, "last online ATC");
        default:
            System.err.println("Unknown card subcommand: " + rest[0]);
            usage(System.err);
            return 2;
        }
    }

    // --- Post-issuance commands ---------------------------------------------

    /**
     * APPLICATION BLOCK / UNBLOCK and CARD BLOCK (EMV v4.4 Book 3 §10.10).
     * CARD BLOCK is irreversible and asks for confirmation unless {@code -yes}.
     */
    private static int postIssuance(String[] argv, int ins, String name, boolean cardBlock)
            throws Exception {
        Args args = new Args(argv, cardBlock ? BLOCK_VALUE : POST_VALUE,
                cardBlock ? BLOCK_FLAG : BASE_FLAG);
        if (args.help()) {
            usage(name.equals("CARD BLOCK") ? "block" : name.equals("APPLICATION BLOCK")
                    ? "block-app" : "unblock-app", System.out);
            return 0;
        }
        if (cardBlock && !confirmed(args)) {
            System.err.println("card block: aborted (pass -yes to confirm)");
            return 2;
        }
        byte[] macKey = Hex.parse(args.require("mac-key"));
        byte[] encKey = args.has("enc-key") ? Hex.parse(args.get("enc-key", "")) : null;
        try (TerminalSession terminalSession = TerminalSession.open(
                args.get("host", "pcsc:0"),
                Integer.parseInt(args.get("wait", "10")), args.has("trace"), System.err)) {
            Terminal terminal = new Terminal(terminalSession.terminal);
            SmCrypto.ScriptSession session = establishSession(terminal, aid(args), macKey, encKey);
            ResponseAPDU r = terminal.transmit(session.command(ins, 0x00, 0x00).getBytes());
            print(name, r);
            return r.getSW() == 0x9000 ? 0 : 1;
        }
    }

    /**
     * {@code card pin-change}: EMV v4.4 PIN CHANGE/UNBLOCK P2=01 (a
     * payment-system proprietary PIN change).  The old PIN is verified on the
     * terminal side first; the new PIN is enciphered under the secure-messaging
     * ENC session key (EMV v4.4 Book 2 §9.2).
     */
    private static int pinChange(String[] argv) throws Exception {
        Args args = new Args(argv, PIN_CHANGE_VALUE, BASE_FLAG);
        if (args.help()) {
            usage("pin-change", System.out);
            return 0;
        }
        String oldPin = args.require("old");
        String newPin = args.require("new");
        byte[] macKey = Hex.parse(args.require("mac-key"));
        byte[] encKey = args.has("enc-key") ? Hex.parse(args.get("enc-key", "")) : null;
        if (encKey == null) {
            throw new IllegalArgumentException("card pin-change needs -enc-key=<hex>");
        }
        try (TerminalSession terminalSession = TerminalSession.open(
                args.get("host", "pcsc:0"),
                Integer.parseInt(args.get("wait", "10")), args.has("trace"), System.err)) {
            Terminal terminal = new Terminal(terminalSession.terminal);
            String aid = aid(args);
            ResponseAPDU sel = terminal.select(aid);
            if (sel.getSW() != 0x9000 && sel.getSW() != 0x6283) {
                print("PIN CHANGE SELECT", sel);
                return 1;
            }
            ResponseAPDU verify = terminal.verifyOfflinePin(oldPin);
            if (verify.getSW() != 0x9000) {
                print("PIN CHANGE old PIN", verify);
                return 1;
            }
            SmCrypto.ScriptSession session = establishSession(terminal, aid, macKey, encKey);
            ResponseAPDU r = terminal.transmit(session.command(0x24, 0x00, 0x01, null,
                    AcCrypto.iso9564Format2(newPin)).getBytes());
            print("PIN CHANGE", r);
            return r.getSW() == 0x9000 ? 0 : 1;
        }
    }

    /**
     * {@code card pin-unblock}: EMV v4.4 PIN CHANGE/UNBLOCK P2=00 resets the PIN
     * Try Counter and unblocks the reference PIN; it carries no PUK and no new
     * PIN.  With {@code -new} the payment-system P2=01 change-and-unblock is
     * sent instead (the reference card refuses it).
     */
    private static int pinUnblock(String[] argv) throws Exception {
        Args args = new Args(argv, PIN_UNBLOCK_VALUE, BASE_FLAG);
        if (args.help()) {
            usage("pin-unblock", System.out);
            return 0;
        }
        if (args.has("puk")) {
            System.err.println("card pin-unblock: EMV v4.4 P2=00/P2=01 carry no PUK;"
                    + " -puk is not transmitted");
        }
        byte[] macKey = Hex.parse(args.require("mac-key"));
        byte[] encKey = args.has("enc-key") ? Hex.parse(args.get("enc-key", "")) : null;
        boolean change = args.has("new");
        if (change && encKey == null) {
            throw new IllegalArgumentException("card pin-unblock -new needs -enc-key=<hex>");
        }
        try (TerminalSession terminalSession = TerminalSession.open(
                args.get("host", "pcsc:0"),
                Integer.parseInt(args.get("wait", "10")), args.has("trace"), System.err)) {
            Terminal terminal = new Terminal(terminalSession.terminal);
            SmCrypto.ScriptSession session = establishSession(terminal, aid(args), macKey, encKey);
            ResponseAPDU r = change
                    ? terminal.transmit(session.command(0x24, 0x00, 0x01, null,
                            AcCrypto.iso9564Format2(args.get("new", ""))).getBytes())
                    : terminal.transmit(session.command(0x24, 0x00, 0x00).getBytes());
            print(change ? "PIN CHANGE/UNBLOCK (change)" : "PIN CHANGE/UNBLOCK (unblock)", r);
            return r.getSW() == 0x9000 ? 0 : 1;
        }
    }

    // --- GET DATA ------------------------------------------------------------

    /** {@code card get-data -tag=<9Fxx>}: GET DATA and print the TLV value. */
    private static int getData(String[] argv) throws Exception {
        Args args = new Args(argv, GET_VALUE, BASE_FLAG);
        if (args.help()) {
            usage("get-data", System.out);
            return 0;
        }
        byte[] tag = Hex.parse(args.require("tag"));
        if (tag.length != 2 || (tag[0] & 0xFF) != 0x9F) {
            throw new IllegalArgumentException("-tag must be a two-byte 9Fxx tag");
        }
        return getData(args, tag[0] & 0xFF, tag[1] & 0xFF, "GET DATA " + Hex.format(tag));
    }

    /** {@code card atc} / {@code card last-online-atc}. */
    private static int atc(String[] argv, int p2, String name) throws Exception {
        Args args = new Args(argv, BASE_VALUE, BASE_FLAG);
        if (args.help()) {
            usage(name.equals("ATC") ? "atc" : "last-online-atc", System.out);
            return 0;
        }
        return getData(args, 0x9F, p2, name);
    }

    private static int getData(Args args, int p1, int p2, String name) throws Exception {
        try (TerminalSession terminalSession = TerminalSession.open(
                args.get("host", "pcsc:0"),
                Integer.parseInt(args.get("wait", "10")), args.has("trace"), System.err)) {
            Terminal terminal = new Terminal(terminalSession.terminal);
            ResponseAPDU sel = terminal.select(aid(args));
            if (sel.getSW() != 0x9000) {
                print(name + " SELECT", sel);
                return 1;
            }
            ResponseAPDU r = terminal.getData(p1, p2);
            print(name, r);
            if (r.getSW() == 0x9000) {
                byte[] value = Tags.find(r.getData(), (p1 << 8) | p2);
                if (value != null && value.length == 2) {
                    int number = ((value[0] & 0xFF) << 8) | (value[1] & 0xFF);
                    System.out.println(name + ": " + number + " (0x" + Hex.format(value) + ")");
                } else if (value != null && value.length == 1) {
                    System.out.println(name + ": " + (value[0] & 0xFF));
                }
            }
            return r.getSW() == 0x9000 ? 0 : 1;
        }
    }

    // --- Session / transport -------------------------------------------------

    /**
     * Opens a transaction and returns a secure-messaging session keyed on its
     * first AC.  A blocked application answers SELECT with 6283 and no FCI, so
     * the GPO is skipped for it (the card still serves GENERATE AC and the
     * post-issuance commands).
     */
    private static SmCrypto.ScriptSession establishSession(Terminal terminal, String aid,
            byte[] macKey, byte[] encKey) throws Exception {
        ResponseAPDU sel = terminal.select(aid);
        if (sel.getSW() == 0x9000) {
            TransactionRequest data = new TransactionRequest(TerminalConfig.forContact().build());
            TransactionResult.Mutable result = new TransactionResult.Mutable();
            data.applicationIdentifier = Hex.parse(aid);
            byte[] pdol = TagPolicy.findIcc(sel.getData(), 0x9F38);
            byte[] pdolData = TerminalDol.buildDolData(data, result,
                    pdol == null ? new byte[0] : pdol);
            ResponseAPDU gpo = terminal.gpo(pdolData);
            if (gpo.getSW() != 0x9000) {
                throw new IllegalStateException("GPO -> " + sw(gpo.getSW()));
            }
        } else if (sel.getSW() != 0x6283) {
            throw new IllegalStateException("SELECT " + aid + " -> " + sw(sel.getSW()));
        }
        ResponseAPDU record = terminal.readRecord(1, 1);
        if (record.getSW() != 0x9000) {
            throw new IllegalStateException("READ RECORD 1 -> " + sw(record.getSW()));
        }
        byte[] cdol1 = Tags.find(record.getData(), 0x8C);
        int length = cdol1 == null ? 0 : AcCrypto.dolDataLength(cdol1);
        ResponseAPDU first = terminal.generateAc((byte) 0x80, length);
        if (first.getSW() != 0x9000) {
            throw new IllegalStateException("first GENERATE AC -> " + sw(first.getSW()));
        }
        byte[] arqc = Responses.parseAc(first).ac;
        if (arqc == null || arqc.length != 8) {
            throw new IllegalStateException("first AC is not an 8-byte cryptogram");
        }
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(macKey, encKey);
        session.start(arqc);
        return session;
    }

    private static String aid(Args args) {
        return args.get("aid", DEFAULT_AID);
    }

    /** Interactive confirmation for the irreversible CARD BLOCK. */
    private static boolean confirmed(Args args) {
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

    private static void print(String name, ResponseAPDU r) {
        String data = r.getData() == null || r.getData().length == 0
                ? "" : " " + Hex.format(r.getData());
        System.out.println(name + ": SW=" + sw(r.getSW()) + data);
    }

    private static String sw(int sw) {
        return String.format("%04X", sw & 0xFFFF);
    }

    private static boolean isHelp(String arg) {
        return arg.equals("-h") || arg.equals("--help") || arg.equals("help");
    }

    // --- Usage ---------------------------------------------------------------

    public static void usage(PrintStream out) {
        out.println("usage: Main card <block-app|unblock-app|block|pin-change|pin-unblock"
                + "|get-data|atc|last-online-atc> [options]");
        out.println("  transport : -host=pcsc[:i]|socket:h:p -wait=<s> -aid=<hex> -trace");
        out.println("  post-issue: -mac-key=<hex> [-enc-key=<hex>]  (block-app/unblock-app/block)");
        out.println("  block     : -yes (CARD BLOCK is irreversible; otherwise it asks)");
        out.println("  pin-change: -old=<pin> -new=<pin> -mac-key= -enc-key=");
        out.println("  pin-unblock: [-new=<pin>] -mac-key= [-enc-key=] [-puk= (not transmitted)]");
        out.println("  get-data  : -tag=<9Fxx>   atc   last-online-atc");
    }

    public static void usage(String sub, PrintStream out) {
        switch (sub) {
        case "block-app":
            out.println("usage: Main card block-app -mac-key=<hex> [options]");
            out.println("  -aid=<hex>      application to block (default " + DEFAULT_AID + ")");
            out.println("  -host= -wait= -trace");
            break;
        case "unblock-app":
            out.println("usage: Main card unblock-app -mac-key=<hex> [options]");
            out.println("  -aid=<hex>      application to unblock (default " + DEFAULT_AID + ")");
            out.println("  -host= -wait= -trace");
            break;
        case "block":
            out.println("usage: Main card block -mac-key=<hex> [-yes] [options]");
            out.println("  CARD BLOCK permanently disables every application on the card.");
            out.println("  -yes            confirm the irreversible block (otherwise it asks)");
            break;
        case "pin-change":
            out.println("usage: Main card pin-change -old=<pin> -new=<pin> -mac-key=<hex> -enc-key=<hex>");
            out.println("  The old PIN is verified first; the new PIN is enciphered in P2=01.");
            out.println("  EMV v4.4 P2=01 is payment-system proprietary: the reference card");
            out.println("  answers 6A81, which is reported as a card refusal (exit 1).");
            break;
        case "pin-unblock":
            out.println("usage: Main card pin-unblock -mac-key=<hex> [-new=<pin> -enc-key=<hex>]");
            out.println("  P2=00 resets the PIN Try Counter and unblocks the reference PIN;");
            out.println("  it carries no PUK and no new PIN.  -new sends the P2=01 change instead.");
            break;
        case "get-data":
            out.println("usage: Main card get-data -tag=<9Fxx> [options]");
            out.println("  -tag=<hex>      two-byte 9Fxx tag (e.g. 9F36 ATC, 9F17 PTC)");
            out.println("  -host= -wait= -aid= -trace");
            break;
        case "atc":
            out.println("usage: Main card atc [options]   # GET DATA 9F36");
            out.println("  -host= -wait= -aid= -trace");
            break;
        case "last-online-atc":
            out.println("usage: Main card last-online-atc [options]   # GET DATA 9F13");
            out.println("  -host= -wait= -aid= -trace");
            break;
        default:
            usage(out);
            break;
        }
    }
}
