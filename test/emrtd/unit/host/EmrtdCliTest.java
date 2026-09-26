package card42.test;

import card42.host.common.cli.CliSupport;
import card42.host.emrtd.cli.Main;
import card42.host.emrtd.cli.command.EmrtdCommand;

/**
 * CLI flow coverage for {@code card42.host.emrtd.cli.Main} and
 * {@code EmrtdCommand} beyond the exit codes already asserted by
 * {@code EmrtdHostNegativeTest}.
 *
 * <p>The card transport has no injectable seam ({@code TerminalSession.open}
 * builds the terminal directly), so the full {@code read}/{@code inspect}/
 * {@code apdu} exchanges are covered by the simulator suites
 * ({@code EmrtdBacTest}, {@code EmrtdLds2IntegrationTest}).  What can be tested
 * without a card is the dispatcher and the argument grammar documented in
 * {@code docs/specs/common/toolchain.md §7.1}: the version/help/usage paths, the
 * option errors that are detected before the transport is opened, and that the
 * documented {@code -json=1} and {@code -pace} options are accepted and reach
 * the transport.
 */
final class EmrtdCliTest {

    private EmrtdCliTest() {
    }

    static void run() throws Exception {
        System.out.println("EmrtdCli");
        dispatch();
        argumentHandling();
        jsonOptionAccepted();
        flowReachesTransport();
    }

    /** The dispatcher's version/help/usage surface (toolchain.md §7.1). */
    private static void dispatch() {
        Asserts.eq(CliSupport.EXIT_OK, Main.run(new String[] { "version" }), "CLI 'version' exits 0");
        Asserts.eq(CliSupport.EXIT_OK, Main.run(new String[] { "-v" }), "CLI '-v' exits 0");
        Asserts.eq(CliSupport.EXIT_OK, Main.run(new String[] { "--version" }),
                "CLI '--version' exits 0");
        Asserts.eq(CliSupport.EXIT_OK, Main.run(new String[] { "help" }), "CLI 'help' exits 0");
        Asserts.eq(CliSupport.EXIT_OK, Main.run(new String[] { "-h" }), "CLI '-h' exits 0");
        Asserts.eq(CliSupport.EXIT_OK, Main.run(new String[] { "--help" }), "CLI '--help' exits 0");
        Asserts.eq(CliSupport.EXIT_USAGE, Main.run(new String[] { "terminal" }),
                "CLI 'terminal' without 'emrtd' exits 2");
        Asserts.eq(CliSupport.EXIT_USAGE, Main.run(new String[] { "terminal", "emv" }),
                "CLI 'terminal emv' is not eMRTD and exits 2");
    }

    /** Option errors that are detected before any transport is opened (§7.1). */
    private static void argumentHandling() {
        Asserts.eq(CliSupport.EXIT_USAGE, Main.run(
                new String[] { "terminal", "emrtd", "apdu", "-apdu" }),
                "apdu with a value-less -apdu exits 2");
        Asserts.eq(CliSupport.EXIT_USAGE, Main.run(
                new String[] { "terminal", "emrtd", "read", "-bogus" }),
                "read with an unknown option exits 2");
        Asserts.eq(CliSupport.EXIT_USAGE, Main.run(
                new String[] { "terminal", "emrtd", "inspect", "-json=1", "-bogus" }),
                "inspect with an unknown option exits 2");
        Asserts.eq(CliSupport.EXIT_USAGE, Main.run(
                new String[] { "terminal", "emrtd", "lds2", "-app=bogus" }),
                "lds2 with an unknown app exits 2");
        Asserts.eq(CliSupport.EXIT_USAGE, Main.run(
                new String[] { "terminal", "emrtd", "lds2", "-app=visa", "-bogus" }),
                "lds2 with an unknown option exits 2");
    }

    /**
     * The usage text advertises {@code -json=1} (§7.1) and the command reads
     * {@code parsed.get("json", ...)}, so the option must be accepted.  A bad
     * LDS2 app is validated before the transport is opened, which lets the
     * check run without a card.
     */
    private static void jsonOptionAccepted() {
        Asserts.eq(CliSupport.EXIT_USAGE, runQuietly("lds2",
                        new String[] { "-app=bogus", "-json=1" }),
                "lds2 accepts -json=1 (rejected only the app, §7.1)");
        Asserts.eq(CliSupport.EXIT_USAGE, runQuietly("lds2",
                        new String[] { "-app=bogus", "-json=0" }),
                "lds2 accepts -json=0 (§7.1)");
        Asserts.eq(-1, runQuietly("lds2", new String[] { "-app=bogus", "-json" }),
                "lds2 rejects a value-less -json (ArityError)");
    }

    /**
     * {@code read}/{@code inspect}/{@code apdu} open the transport before doing
     * any card work; with an unusable {@code socket:} descriptor they fail there
     * (non-zero), which proves the options were parsed.  A rejected option
     * instead surfaces as {@link IllegalArgumentException}, so the two are
     * distinguishable.
     */
    private static void flowReachesTransport() {
        Asserts.check(reachesTransport("read", new String[] {
                "-host=socket:localhost:1", "-doc=123456789", "-dob=000101",
                "-doe=300101", "-json=1" }),
                "read flow accepts -doc/-dob/-doe and -json=1 and reaches the transport");
        Asserts.check(reachesTransport("read", new String[] {
                "-host=socket:localhost:1", "-doc=123456789", "-dob=000101",
                "-doe=300101", "-pace" }),
                "read flow accepts the -pace flag (Doc 9303-11 §4.4)");
        Asserts.check(reachesTransport("inspect", new String[] {
                "-host=socket:localhost:1", "-json=1" }),
                "inspect flow accepts -json=1 and reaches the transport");
        Asserts.check(reachesTransport("apdu", new String[] {
                "-host=socket:localhost:1", "-apdu=00A4040000" }),
                "apdu flow reaches the transport");
    }

    /**
     * Runs a subcommand and reports whether it got past argument parsing:
     * {@code true} when it failed at the transport (or returned), {@code false}
     * only for an {@link IllegalArgumentException} from {@code Args}.
     */
    private static boolean reachesTransport(String subcommand, String[] args) {
        try {
            EmrtdCommand.run(subcommand, args);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        } catch (Exception e) {
            return true;
        }
    }

    /** Runs a subcommand and maps an {@code Args} rejection to -1. */
    private static int runQuietly(String subcommand, String[] args) {
        try {
            return EmrtdCommand.run(subcommand, args);
        } catch (IllegalArgumentException e) {
            return -1;
        } catch (Exception e) {
            return -2;
        }
    }
}
