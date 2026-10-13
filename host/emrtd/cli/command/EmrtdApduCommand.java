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
        Args parsed = new Args(args, new String[] { "host", "apdu" }, new String[0]);
        String host = parsed.get("host", "socket:localhost:9025");
        String hex = parsed.get("apdu", null);
        if (hex == null) {
            return CliSupport.fail("apdu needs -apdu=<hex>");
        }
        try (TerminalSession session = TerminalSession.open(host, 0, true, System.out)) {
            ResponseAPDU r = session.terminal.transmit(Hex.parse(hex));
            System.out.println("SW=" + String.format("%04X", r.getSW()));
            if (r.getData().length > 0) {
                System.out.println(Hex.format(r.getData()));
            }
            return CliSupport.EXIT_OK;
        }
    }
}
