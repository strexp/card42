package card42.host.emv.cli.command;

import card42.host.emv.app.perso.PersoExporter;
import card42.host.emv.app.perso.PersoScript;
import card42.host.emv.app.perso.SdaKeyProfile;
import card42.host.emv.oda.SdaKeys;
import card42.host.common.util.Args;

/**
 * Exports the DGI sequence of every instance in a personalization script
 * (docs/specs/common/toolchain.md §5, docs/specs/emv/personalization.md §1) as
 * GPPro-ready hex.
 *
 * <p>Each output line is {@code <instance-AID> <DGI-sequence-hex>}, in script
 * order.  The {@code make card-emv-perso} target feeds these lines to
 * {@code gp --personalize <AID> --store-data <hex>} on a real card; GPPro's
 * {@code --store-data} splits the blob and manages {@code P1}/{@code P2}, so the
 * applet sees the same block sequence as the simulator path (both now driven by
 * GPPro) and completion is the last block's {@code P1.b8} (EMV CPS v2.0 §4.3.4.2).
 *
 * <p>Usage: {@code Main perso export [-script=perso/emv/sample.perso] [-keys=&lt;path&gt;]}.
 * The {@code -keys} profile is required when the script uses {@code @sda}
 * (EMV v4.4 Book 2 §5); only the {@code AID HEX} lines go to stdout, any
 * diagnostics go to stderr, so the output can be piped straight into the
 * Makefile loop.
 */
public final class PersoCommand {

    private static final String[] VALUE_OPTIONS = { "script", "keys" };

    private PersoCommand() {
    }

    /** Runs the command and returns its exit code. */
    public static int run(String[] argv) throws Exception {
        Args args = new Args(argv, VALUE_OPTIONS, new String[0]);
        if (args.help()) {
            usage(System.out);
            return 0;
        }
        String scriptPath = args.get("script", "perso/emv/sample.perso");
        String keysPath = args.get("keys", null);
        SdaKeys sdaKeys = keysPath == null ? null : SdaKeyProfile.load(keysPath);
        PersoScript script = PersoScript.parse(scriptPath, sdaKeys);
        System.err.println("Export      : " + scriptPath);
        System.err.println("Instances   : " + script.entries.size());
        for (String line : PersoExporter.lines(script)) {
            System.out.println(line);
        }
        return 0;
    }

    public static void usage(java.io.PrintStream out) {
        out.println("usage: Main perso export [-script=<path>] [-keys=<path>]");
    }
}
