package card42.host.common.cli;

import java.io.PrintStream;

/**
 * Shared CLI conventions (exit codes and usage helpers) for the host command
 * line tools.  It carries no concrete command, so the EMV and eMRTD CLIs can
 * both build on it.
 *
 * <p>Exit codes: {@link #EXIT_OK 0} success/approved, {@link #EXIT_DECLINED 1}
 * declined, {@link #EXIT_USAGE 2} usage or connection error.
 */
public final class CliSupport {

    /** Success / approved. */
    public static final int EXIT_OK = 0;
    /** Declined (e.g. a transaction not approved). */
    public static final int EXIT_DECLINED = 1;
    /** Usage or connection error. */
    public static final int EXIT_USAGE = 2;

    private CliSupport() {
    }

    /** True for the {@code -h}/{@code --help}/{@code help} help spellings. */
    public static boolean isHelp(String arg) {
        return arg.equals("-h") || arg.equals("--help") || arg.equals("help");
    }

    /** Prints {@code error: <message>} to stderr and returns {@link #EXIT_USAGE}. */
    public static int fail(String message) {
        return fail(message, System.err);
    }

    /** Prints {@code error: <message>} to {@code err} and returns {@link #EXIT_USAGE}. */
    public static int fail(String message, PrintStream err) {
        err.println("error: " + message);
        return EXIT_USAGE;
    }

    /** Prints an unknown-command diagnostic and returns {@link #EXIT_USAGE}. */
    public static int unknown(String kind, String name, PrintStream err) {
        err.println("Unknown " + kind + ": " + name);
        return EXIT_USAGE;
    }
}
