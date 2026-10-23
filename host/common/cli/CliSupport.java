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

    /**
     * Reads the shared {@code -json} switch: bare {@code -json} means enabled,
     * {@code -json=1}/{@code -json=0} select explicitly; any other value is a
     * usage error so a typo cannot silently select text output.
     */
    public static boolean json(Args args) {
        String value = args.get("json", null);
        if (value == null) {
            return args.has("json");
        }
        if ("1".equals(value) || "true".equalsIgnoreCase(value)) {
            return true;
        }
        if ("0".equals(value) || "false".equalsIgnoreCase(value)) {
            return false;
        }
        throw new IllegalArgumentException("-json must be 1 or 0 (bare -json means 1)");
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

    /**
     * Prints {@code error: <message>} to stderr and returns
     * {@link #EXIT_DECLINED}: the command was well-formed but the card or a
     * verification check refused/failed.
     */
    public static int failDeclined(String message) {
        System.err.println("error: " + message);
        return EXIT_DECLINED;
    }

    /** Prints an unknown-command diagnostic and returns {@link #EXIT_USAGE}. */
    public static int unknown(String kind, String name, PrintStream err) {
        err.println("Unknown " + kind + ": " + name);
        return EXIT_USAGE;
    }
}
