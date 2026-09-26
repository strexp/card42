package card42.host.emv.cli.command;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import card42.host.emv.lib.Apdus;
import card42.host.common.codec.Json;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.crypto.SmCrypto;
import card42.host.emv.app.issuer.IssuerCrypto;
import card42.host.emv.app.issuer.IssuerHost;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;

/**
 * The {@code issuer} command family (docs/specs/common/toolchain.md §7.1): the issuer-side half of
 * the online closed loop.
 *
 * <pre>
 *   issuer authorize   read a one-line JSON authorisation request on stdin and
 *                      write a one-line JSON authorisation (the host bridge of
 *                      {@code terminal pay -issuer-cmd}, decision D)
 *   issuer arpc        ARPC Method 1 / 2 (EMV v4.4 Book 2 §8.2)
 *   issuer script      build a 71/72 issuer script template, optionally under
 *                      Format 1 secure messaging (EMV v4.4 Book 3 §10.10)
 *   issuer keys        A1.3 session key and KCV (EMV v4.4 Book 2 §A1.3.1)
 * </pre>
 *
 * <p>Every command is a thin wrapper over {@link IssuerHost}, {@link AcCrypto}
 * and {@link SmCrypto}; the crypto vectors live in the unit suites.  Exit codes
 * match the rest of the CLI: 0 success, 2 usage error.
 */
public final class IssuerCommand {

    private static final String[] AUTH_VALUE = { "icc-key", "arc", "csu", "script" };
    private static final String[] AUTH_FLAG = { "csu-reset" };
    private static final String[] ARPC_VALUE = { "key", "atc", "arqc", "arc", "csu", "method" };
    private static final String[] SCRIPT_VALUE = {
        "command", "tag", "script-id", "mac-key", "enc-key", "arqc", "mac-length",
    };
    private static final String[] KEYS_VALUE = { "key", "atc", "r" };

    private IssuerCommand() {
    }

    /** Dispatches an {@code issuer <subcommand>} invocation. */
    public static int run(String[] rest) throws Exception {
        if (rest.length == 0 || isHelp(rest[0])) {
            usage(rest.length == 0 ? System.err : System.out);
            return rest.length == 0 ? 2 : 0;
        }
        String[] options = Arrays.copyOfRange(rest, 1, rest.length);
        switch (rest[0]) {
        case "authorize": return authorize(options);
        case "arpc": return arpc(options);
        case "script": return script(options);
        case "keys": return keys(options);
        default:
            System.err.println("Unknown issuer subcommand: " + rest[0]);
            usage(System.err);
            return 2;
        }
    }

    // --- issuer authorize ----------------------------------------------------

    /**
     * {@code issuer authorize}: reads one line of JSON from stdin and writes the
     * matching authorisation to stdout.  Request fields (all optional except
     * {@code arqc}): {@code arqc}, {@code atc}, {@code tvr}, {@code aid}.  The
     * response is {@code {"arc":..,"auth":..[,"scripts":[..]]}}, exactly what
     * {@code terminal pay -issuer-cmd} consumes (decision D).
     */
    private static int authorize(String[] argv) throws Exception {
        Args args = new Args(argv, AUTH_VALUE, AUTH_FLAG);
        if (args.help()) {
            usage("authorize", System.out);
            return 0;
        }
        byte[] iccKey = Hex.parse(args.require("icc-key"));
        byte[] arc = twoBytes(Hex.parse(args.get("arc", "3030")), "arc");
        byte[] csu = args.has("csu-reset")
                ? Hex.parse("00820000")
                : fourBytes(Hex.parse(args.get("csu", "00800000")), "csu");
        List<String> scripts = args.all("script");

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line = reader.readLine();
        if (line == null || line.isBlank()) {
            throw new IllegalArgumentException("issuer authorize: no JSON request on stdin");
        }
        System.out.println(authorize(line, iccKey, arc, csu, scripts));
        return 0;
    }

    /**
     * The authorisation core: computes ARPC Method 2 and the inline Issuer
     * Authentication Data (tag 91 = ARPC || CSU) and renders the JSON response.
     * Package-private so the unit suite can exercise it without a process.
     */
    static String authorize(String requestLine, byte[] iccKey, byte[] arc, byte[] csu,
            List<String> scripts) throws Exception {
        Map<String, Object> request = Json.parseObject(requestLine);
        String arqcHex = Json.string(request, "arqc");
        if (arqcHex == null) {
            throw new IllegalArgumentException("issuer authorize: request has no \"arqc\"");
        }
        int atc = Json.integer(request, "atc", 0);
        byte[] arqc = eightBytes(Hex.parse(arqcHex), "arqc");
        byte[] auth = IssuerCrypto.inlineAuthData(iccKey, atc, arqc, csu);

        StringBuilder out = new StringBuilder();
        out.append("{\"arc\":").append(Json.quote(Hex.format(arc)))
                .append(",\"auth\":").append(Json.quote(Hex.format(auth)));
        if (scripts != null && !scripts.isEmpty()) {
            out.append(",\"scripts\":[");
            for (int i = 0; i < scripts.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                out.append(Json.quote(Hex.format(Hex.parse(scripts.get(i)))));
            }
            out.append(']');
        }
        out.append('}');
        return out.toString();
    }

    // --- issuer arpc ---------------------------------------------------------

    /** {@code issuer arpc}: ARPC Method 1 (needs -arc) or Method 2 (needs -csu). */
    private static int arpc(String[] argv) throws Exception {
        Args args = new Args(argv, ARPC_VALUE, new String[0]);
        if (args.help()) {
            usage("arpc", System.out);
            return 0;
        }
        int method = Integer.parseInt(args.get("method", "2"));
        byte[] key = Hex.parse(args.require("key"));
        int atc = parseAtc(args.require("atc"));
        byte[] arqc = eightBytes(Hex.parse(args.require("arqc")), "arqc");
        byte[] arc = args.has("arc") ? twoBytes(Hex.parse(args.get("arc", "3030")), "arc") : null;
        byte[] csu = fourBytes(Hex.parse(args.get("csu", "00800000")), "csu");
        System.out.println(Hex.format(IssuerCrypto.arpc(method, key, atc, arqc, arc, csu)));
        return 0;
    }

    // --- issuer script -------------------------------------------------------

    /**
     * {@code issuer script}: wraps one or more {@code -command} APDUs into a
     * 71/72 template (EMV v4.4 Book 3 Figure 11).  With {@code -mac-key} (and
     * {@code -arqc}) each plaintext command is re-emitted as a Format 1
     * secure-messaging command (EMV v4.4 Book 2 §9.2).
     */
    private static int script(String[] argv) throws Exception {
        Args args = new Args(argv, SCRIPT_VALUE, new String[0]);
        if (args.help()) {
            usage("script", System.out);
            return 0;
        }
        int tag = Integer.parseInt(args.get("tag", "72"), 16);
        if (tag != 0x71 && tag != 0x72) {
            throw new IllegalArgumentException("-tag must be 71 or 72");
        }
        byte[] scriptId = args.has("script-id") ? Hex.parse(args.get("script-id", "")) : null;
        List<String> commandHex = args.all("command");
        if (commandHex.isEmpty()) {
            throw new IllegalArgumentException("issuer script needs at least one -command=<hex>");
        }

        byte[][] commands = new byte[commandHex.size()][];
        if (args.has("mac-key")) {
            byte[] macKey = Hex.parse(args.get("mac-key", ""));
            byte[] encKey = args.has("enc-key") ? Hex.parse(args.get("enc-key", "")) : null;
            byte[] arqc = eightBytes(Hex.parse(args.require("arqc")), "arqc");
            SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(macKey, encKey);
            if (args.has("mac-length")) {
                session.setMacLength(Integer.parseInt(args.get("mac-length", "8")));
            }
            session.start(arqc);
            for (int i = 0; i < commandHex.size(); i++) {
                Apdus.Command command = Apdus.parse(commandHex.get(i));
                commands[i] = session.commandWithObjects(command.ins, command.p1,
                        command.p2, command.data).getBytes();
            }
        } else {
            for (int i = 0; i < commandHex.size(); i++) {
                commands[i] = Hex.parse(commandHex.get(i));
            }
        }

        byte[] template = IssuerHost.script(tag,
                scriptId == null ? null : Hex.format(scriptId), commands);
        System.out.println(Hex.format(template));
        return 0;
    }

    // --- issuer keys ---------------------------------------------------------

    /**
     * {@code issuer keys}: prints the block-cipher KCV (leftmost 3 bytes of
     * DES3(key)[00 x8]) and, with {@code -atc} or {@code -r}, the A1.3 session
     * key (EMV v4.4 Book 2 §A1.3.1).
     */
    private static int keys(String[] argv) throws Exception {
        Args args = new Args(argv, KEYS_VALUE, new String[0]);
        if (args.help()) {
            usage("keys", System.out);
            return 0;
        }
        byte[] key = Hex.parse(args.require("key"));
        System.out.println("KCV     " + Hex.format(IssuerCrypto.kcv(key)));
        if (args.has("atc")) {
            System.out.println("SK_AC   "
                    + Hex.format(AcCrypto.sessionKey(key, parseAtc(args.get("atc", "0")))));
        } else if (args.has("r")) {
            System.out.println("SK      "
                    + Hex.format(AcCrypto.sessionKey(key, eightBytes(
                            Hex.parse(args.get("r", "")), "r"))));
        }
        return 0;
    }

    // --- Helpers -------------------------------------------------------------

    private static int parseAtc(String text) {
        int atc = text.startsWith("0x") || text.startsWith("0X")
                ? Integer.parseInt(text.substring(2), 16)
                : Integer.parseInt(text);
        if (atc < 0 || atc > 0xFFFF) {
            throw new IllegalArgumentException("-atc must be 0..65535");
        }
        return atc;
    }

    private static byte[] twoBytes(byte[] value, String name) {
        if (value.length != 2) {
            throw new IllegalArgumentException("-" + name + " must be 2 bytes");
        }
        return value;
    }

    private static byte[] fourBytes(byte[] value, String name) {
        if (value.length != 4) {
            throw new IllegalArgumentException("-" + name + " must be 4 bytes");
        }
        return value;
    }

    private static byte[] eightBytes(byte[] value, String name) {
        if (value.length != 8) {
            throw new IllegalArgumentException("-" + name + " must be 8 bytes");
        }
        return value;
    }

    private static boolean isHelp(String arg) {
        return arg.equals("-h") || arg.equals("--help") || arg.equals("help");
    }

    // --- Usage ---------------------------------------------------------------

    public static void usage(PrintStream out) {
        out.println("usage: Main issuer <authorize|arpc|script|keys> [options]");
        out.println("  authorize   stdin JSON authorisation request -> stdout JSON authorisation");
        out.println("  arpc        ARPC Method 1/2 (see: Main help \"issuer arpc\")");
        out.println("  script      build a 71/72 issuer script template");
        out.println("  keys        session key / KCV");
    }

    public static void usage(String sub, PrintStream out) {
        switch (sub) {
        case "authorize":
            out.println("usage: Main issuer authorize -icc-key=<hex> [options]");
            out.println("  -icc-key=<hex>    ICC AC master key (required)");
            out.println("  -arc=<hex>        authorisation response code (default 3030)");
            out.println("  -csu=<hex>        Card Status Update (default 00800000)");
            out.println("  -csu-reset        CSU 00820000 (reset the offline counters)");
            out.println("  -script=<hex>     71/72 script template to return (repeatable)");
            out.println("  stdin             one JSON request: {\"arqc\":..,\"atc\":..,\"tvr\":..,\"aid\":..}");
            break;
        case "arpc":
            out.println("usage: Main issuer arpc -key=<hex> -atc=<n> -arqc=<hex> [options]");
            out.println("  -key=<hex>        ICC AC master key (required)");
            out.println("  -atc=<n>          ATC, decimal or 0x-prefixed hex (required)");
            out.println("  -arqc=<hex>       first Application Cryptogram, 8 bytes (required)");
            out.println("  -method=1|2       ARPC method (default 2)");
            out.println("  -arc=<hex>        ARC, 2 bytes (required for -method=1)");
            out.println("  -csu=<hex>        CSU, 4 bytes (default 00800000, method 2)");
            break;
        case "script":
            out.println("usage: Main issuer script -command=<hex> [options]");
            out.println("  -command=<hex>    plaintext command APDU (repeatable, required)");
            out.println("  -tag=71|72        template tag (default 72)");
            out.println("  -script-id=<hex>  optional 9F18 Script Identifier");
            out.println("  -mac-key=<hex>    wrap each command in Format 1 SM (needs -arqc)");
            out.println("  -enc-key=<hex>    SM encipherment key");
            out.println("  -arqc=<hex>       first AC: the SM diversification value (8 bytes)");
            out.println("  -mac-length=4..8  transmitted MAC length (default 8)");
            break;
        case "keys":
            out.println("usage: Main issuer keys -key=<hex> [options]");
            out.println("  -key=<hex>        master key (required)");
            out.println("  -atc=<n>          print the A1.3 session key for this ATC");
            out.println("  -r=<hex>          print the A1.3 session key for an 8-byte value");
            break;
        default:
            usage(out);
            break;
        }
    }
}
