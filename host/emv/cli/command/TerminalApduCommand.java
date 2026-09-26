package card42.host.emv.cli.command;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.ResponseAPDU;

import card42.host.emv.lib.Terminal;
import card42.host.common.transport.TerminalSession;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;

/**
 * {@code terminal apdu}: sends raw command APDUs to the card and prints each
 * R-APDU with its status word (docs/specs/common/toolchain.md §7.1).  It is the low-level debug
 * companion of {@code terminal pay} / {@code terminal inspect}: the APDUs come
 * from repeated {@code -apdu=<hex>}, from {@code -file=<path>} (one per line,
 * {@code #} comments and blank lines ignored) or, when neither is given, from
 * stdin.  Exit codes: 0 success, 2 usage or connection error.
 */
public final class TerminalApduCommand {

    private static final String[] VALUE_OPTIONS = { "host", "wait", "apdu", "file" };
    private static final String[] FLAG_OPTIONS = { "trace" };

    private TerminalApduCommand() {
    }

    /** Runs the command and returns its exit code. */
    public static int run(String[] argv) throws Exception {
        Args args = new Args(argv, VALUE_OPTIONS, FLAG_OPTIONS);
        if (args.help()) {
            usage(System.out);
            return 0;
        }
        String host = args.get("host", "pcsc:0");
        int wait = Integer.parseInt(args.get("wait", "10"));

        List<String> commands = new ArrayList<>(args.all("apdu"));
        if (args.has("file")) {
            commands.addAll(readFile(args.get("file", "")));
        }
        if (commands.isEmpty()) {
            commands.addAll(readStream(System.in));
        }
        if (commands.isEmpty()) {
            throw new IllegalArgumentException("terminal apdu: no APDU given (-apdu, -file or stdin)");
        }

        try (TerminalSession session = TerminalSession.open(
                host, wait, args.has("trace"), System.err)) {
            Terminal terminal = new Terminal(session.terminal);
            for (String command : commands) {
                byte[] raw = Hex.parse(command);
                if (raw.length < 4) {
                    throw new IllegalArgumentException("not a command APDU: " + command);
                }
                ResponseAPDU response = terminal.transmit(raw);
                System.out.println("> " + Hex.format(raw));
                System.out.println("< " + Hex.format(response.getBytes())
                        + " SW=" + String.format("%04X", response.getSW()));
            }
        }
        return 0;
    }

    private static List<String> readFile(String path) throws Exception {
        return readLines(Files.newBufferedReader(Path.of(path), StandardCharsets.UTF_8));
    }

    private static List<String> readStream(java.io.InputStream in) throws Exception {
        return readLines(new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)));
    }

    private static List<String> readLines(BufferedReader reader) throws Exception {
        List<String> lines = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null) {
            int comment = line.indexOf('#');
            if (comment >= 0) {
                line = line.substring(0, comment);
            }
            line = line.trim();
            if (!line.isEmpty()) {
                lines.add(line);
            }
        }
        return lines;
    }

    public static void usage(PrintStream out) {
        out.println("usage: Main terminal apdu [options]");
        out.println("  -apdu=<hex>      command APDU to send (repeatable)");
        out.println("  -file=<path>     one command APDU per line ('#' comments allowed)");
        out.println("  (no -apdu/-file: read command APDUs from stdin)");
        out.println("  -host=pcsc[:i]|socket:h:p -wait=<s> -trace");
        out.println("Prints '> C-APDU' and '< R-APDU SW=xxxx' for each command.");
    }
}
