package card42.host.emrtd.cli.command;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.cli.Args;
import card42.host.common.cli.CliSupport;
import card42.host.common.transport.TerminalSession;
import card42.host.common.util.Hex;

/** {@code terminal emrtd apdu}: send one raw APDU and print the response. */
final class EmrtdApduCommand {

    private EmrtdApduCommand() {
    }

    static int run(String[] args) throws Exception {
        Args parsed = new Args(args, new String[] { "host", "wait", "apdu" }, new String[] { "trace" });
        if (parsed.help()) {
            usage(System.out);
            return CliSupport.EXIT_OK;
        }
        parsed.requireNoPositionals();
        String host = parsed.get("host", "socket:localhost:9025");
        int wait = Integer.parseInt(parsed.get("wait", "10"));
        if (wait < 0) {
            throw new IllegalArgumentException("-wait must be >= 0 seconds: " + wait);
        }
        String hex = parsed.get("apdu", null);
        if (hex == null) {
            return CliSupport.fail("apdu needs -apdu=<hex>");
        }
        try (TerminalSession session = TerminalSession.open(host, wait, parsed.has("trace"), System.err)) {
            ResponseAPDU r = session.terminal.transmit(Hex.parse(hex));
            System.out.println("SW=" + String.format("%04X", r.getSW()));
            if (r.getData().length > 0) {
                System.out.println(Hex.format(r.getData()));
            }
            return CliSupport.EXIT_OK;
        }
    }

    static void usage(java.io.PrintStream out) {
        out.println("usage: Main terminal emrtd apdu -apdu=<hex> [options]");
        out.println("  -host=pcsc[:i]|socket:host:port -wait=<s> -trace");
        out.println("  -apdu=<hex>                       one command APDU to send");
        out.println("  note: the transport trace is written to stderr; stdout carries the response only");
    }
}
