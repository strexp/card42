package card42.host.emrtd.cli;

import java.util.Arrays;

import card42.host.common.cli.CliSupport;
import card42.host.emrtd.cli.command.EmrtdCommand;

/**
 * Entry point of the eMRTD host CLI.
 *
 * <pre>
 *   Main terminal emrtd read    [options]   BAC/PACE + SM + read all DGs + PA + AA
 *   Main terminal emrtd inspect [options]   read-only reconnaissance
 *   Main terminal emrtd apdu    [options]   raw APDUs
 *   Main version
 *   Main help [command]
 * </pre>
 *
 * <p>The dispatcher exposes the version and the command grammar so the
 * card42-emrtd.jar is independently runnable.
 */
public final class Main {

    static final String VERSION = "1.0";

    private Main() {
    }

    public static void main(String[] args) {
        int code = run(args);
        if (code != 0) {
            System.exit(code);
        }
    }

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
            return CliSupport.EXIT_USAGE;
        }
        String command = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        switch (command) {
        case "version":
        case "-v":
        case "--version":
            System.out.println("card42-emrtd " + VERSION);
            return CliSupport.EXIT_OK;
        case "help":
        case "-h":
        case "--help":
            usage(System.out);
            return CliSupport.EXIT_OK;
        case "terminal":
            if (rest.length >= 1 && "emrtd".equals(rest[0])) {
                if (rest.length == 1) {
                    EmrtdCommand.usage(System.err);
                    return CliSupport.EXIT_USAGE;
                }
                return EmrtdCommand.run(rest[1], Arrays.copyOfRange(rest, 2, rest.length));
            }
            System.err.println("usage: Main terminal emrtd <read|inspect|apdu>");
            return CliSupport.EXIT_USAGE;
        default:
            System.err.println("Unknown command: " + command);
            usage(System.err);
            return CliSupport.EXIT_USAGE;
        }
    }

    private static void usage(java.io.PrintStream out) {
        out.println("usage: card42.host.emrtd.cli.Main <command> <subcommand> [options]");
        out.println("  terminal emrtd read|inspect|lds2|apdu   eMRTD LDS1/LDS2 reader (BAC/PACE + SM)");
        out.println("  version                            print the host CLI version");
        out.println("  help                               show help");
    }
}
