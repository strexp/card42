package card42.host.emv.cli;

import java.util.Arrays;

import card42.host.common.cli.CliSupport;
import card42.host.emv.cli.command.CardCommand;
import card42.host.emv.cli.command.IssuerCommand;
import card42.host.emv.cli.command.PersoCommand;
import card42.host.emv.cli.command.TerminalApduCommand;
import card42.host.emv.cli.command.TerminalEntryPointCommand;
import card42.host.emv.cli.command.TerminalInspectCommand;
import card42.host.emv.cli.command.TerminalPayCommand;

/**
 * Entry point of the host CLI tools (issuance and terminal interaction).
 *
 * <p>The first argument selects a command and the second a subcommand; the
 * remaining arguments are the options (decision C):
 *
 * <pre>
 *   Main perso    export [-script=&lt;path&gt;] [-keys=&lt;path&gt;]
 *   Main terminal pay     [options]
 *   Main terminal inspect [options]
 *   Main terminal apdu    [options]
 *   Main issuer   authorize | arpc | script | keys
 *   Main card     block-app | unblock-app | block | pin-change | pin-unblock
 *                 | get-data | atc | last-online-atc
 *   Main version
 *   Main help [command]
 * </pre>
 *
 * <p>Exit codes: 0 success/approved, 1 declined, 2 usage or connection error.
 */
public final class Main {

    /** The host CLI version, mirrored from the EMV baseline in docs/specs. */
    static final String VERSION = "4.4";

    private Main() {
    }

    public static void main(String[] args) {
        int code = run(args);
        if (code != 0) {
            System.exit(code);
        }
    }

    /**
     * Runs the dispatcher without exiting and maps usage / connection errors to
     * exit code 2, so tests can call it directly.
     */
    public static int run(String[] args) {
        try {
            return dispatch(args);
        } catch (IllegalArgumentException e) {
            return CliSupport.fail(e.getMessage());
        } catch (Exception e) {
            return CliSupport.fail(e.getMessage());
        }
    }

    private static int dispatch(String[] args) throws Exception {
        if (args.length == 0) {
            usage(System.err);
            return 2;
        }
        String command = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        switch (command) {
        case "perso":
            return perso(rest);
        case "terminal":
            return terminal(rest);
        case "issuer":
            return IssuerCommand.run(rest);
        case "card":
            return CardCommand.run(rest);
        case "version":
        case "-v":
        case "--version":
            System.out.println("card42-emv " + VERSION);
            return 0;
        case "help":
        case "-h":
        case "--help":
            return help(rest);
        default:
            System.err.println("Unknown command: " + command);
            usage(System.err);
            return 2;
        }
    }

    private static int perso(String[] rest) throws Exception {
        if (rest.length == 0 || isHelp(rest[0])) {
            PersoCommand.usage(rest.length == 0 ? System.err : System.out);
            return rest.length == 0 ? 2 : 0;
        }
        switch (rest[0]) {
        case "export":
            return PersoCommand.run(Arrays.copyOfRange(rest, 1, rest.length));
        default:
            System.err.println("Unknown perso subcommand: " + rest[0]);
            PersoCommand.usage(System.err);
            return 2;
        }
    }

    private static int terminal(String[] rest) throws Exception {
        if (rest.length == 0 || isHelp(rest[0])) {
            terminalUsage(rest.length == 0 ? System.err : System.out);
            return rest.length == 0 ? 2 : 0;
        }
        String[] options = Arrays.copyOfRange(rest, 1, rest.length);
        switch (rest[0]) {
        case "pay":
            return TerminalPayCommand.run(options);
        case "entrypoint":
            return TerminalEntryPointCommand.run(options);
        case "inspect":
            return TerminalInspectCommand.run(options);
        case "apdu":
            return TerminalApduCommand.run(options);
        default:
            System.err.println("Unknown terminal subcommand: " + rest[0]);
            terminalUsage(System.err);
            return 2;
        }
    }

    private static int help(String[] rest) {
        if (rest.length == 0) {
            usage(System.out);
            return 0;
        }
        String topic = String.join(" ", rest);
        switch (topic) {
        case "perso":
            PersoCommand.usage(System.out);
            return 0;
        case "terminal":
            terminalUsage(System.out);
            return 0;
        case "terminal pay":
            TerminalPayCommand.usage(System.out);
            return 0;
        case "terminal entrypoint":
            TerminalEntryPointCommand.usage(System.out);
            return 0;
        case "terminal inspect":
            TerminalInspectCommand.usage(System.out);
            return 0;
        case "terminal apdu":
            TerminalApduCommand.usage(System.out);
            return 0;
        case "issuer":
            IssuerCommand.usage(System.out);
            return 0;
        case "card":
            CardCommand.usage(System.out);
            return 0;
        default:
            if (topic.startsWith("issuer ")) {
                IssuerCommand.usage(topic.substring("issuer ".length()), System.out);
                return 0;
            }
            if (topic.startsWith("card ")) {
                CardCommand.usage(topic.substring("card ".length()), System.out);
                return 0;
            }
            System.err.println("Unknown command: " + topic);
            usage(System.err);
            return 2;
        }
    }

    private static boolean isHelp(String arg) {
        return CliSupport.isHelp(arg);
    }

    private static void usage(java.io.PrintStream out) {
        out.println("usage: card42.host.emv.cli.Main <command> <subcommand> [options]");
        out.println("  perso    export             personalization script -> GPPro hex");
        out.println("  terminal pay                run a contact/contactless transaction");
        out.println("  terminal entrypoint         run the Entry Point diagnostic");
        out.println("  terminal inspect            read-only card reconnaissance");
        out.println("  terminal apdu               send raw command APDUs");
        out.println("  issuer   authorize|arpc|script|keys   issuer host / online crypto");
        out.println("  card     block-app|unblock-app|block|pin-change|pin-unblock");
        out.println("           |get-data|atc|last-online-atc   card-side commands");
        out.println("  version                     print the host CLI version");
        out.println("  help [command]              show help");
    }

    private static void terminalUsage(java.io.PrintStream out) {
        out.println("usage: Main terminal <pay|entrypoint|inspect|apdu> [options]");
        out.println("  pay        run a transaction (see: Main help \"terminal pay\")");
        out.println("  entrypoint run the Entry Point diagnostic (see: Main help \"terminal entrypoint\")");
        out.println("  inspect    read-only reconnaissance (see: Main help \"terminal inspect\")");
        out.println("  apdu       send raw command APDUs (see: Main help \"terminal apdu\")");
    }
}
