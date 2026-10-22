package card42.host.emrtd.cli.command;

import java.io.PrintStream;

import card42.host.common.cli.CliSupport;

/**
 * {@code terminal emrtd}: dispatches the eMRTD subcommands
 * (ICAO Doc 9303-10/-11).  Each subcommand lives in its own focused class:
 *
 * <ul>
 *   <li>{@link EmrtdReadCommand} - {@code read} / {@code inspect};</li>
 *   <li>{@link EmrtdLds2Command} - {@code lds2};</li>
 *   <li>{@link EmrtdApduCommand} - {@code apdu};</li>
 *   <li>{@link EmrtdTaExportCommand} - {@code ta-export}.</li>
 * </ul>
 */
public final class EmrtdCommand {

    private EmrtdCommand() {
    }

    public static int run(String subcommand, String[] args) throws Exception {
        switch (subcommand) {
        case "read":
            return EmrtdReadCommand.run(args, false);
        case "inspect":
            return EmrtdReadCommand.run(args, true);
        case "lds2":
            return EmrtdLds2Command.run(args);
        case "apdu":
            return EmrtdApduCommand.run(args);
        case "ta-export":
            return EmrtdTaExportCommand.run(args);
        default:
            usage(System.err);
            return CliSupport.EXIT_USAGE;
        }
    }

    public static void usage(PrintStream out) {
        out.println("usage: Main terminal emrtd <read|inspect|lds2|apdu|ta-export> [options]");
        out.println("  read    -host=... -doc=... -dob=YYMMDD -doe=YYMMDD [-pace] [-can=<6 digits>] [-ca]");
        out.println("          [-ta -ta-chain=<file> -ta-key=<hex>] [-csca=<cert>] [-json=1]");
        out.println("  inspect -host=... [-json=1]");
        out.println("  lds2    -host=... [-app=travel|visa|biometrics] "
                + "(-pace -doc=... -dob=YYMMDD -doe=YYMMDD | -can=<CAN>)");
        out.println("          [-ca] [-ta -ta-chain=<file> -ta-key=<hex>] "
                + "[-record=entry|exit|visa|cert|all] [-json=1]");
        out.println("          [-append=<json> -ts-key=<pem> [-cert-ref=n]]  "
                + "structured Travel/Visa/Certificate append");
        out.println("  apdu    -host=... -apdu=<hex>");
        out.println("  ta-export -dir=<path>   write a demo CV certificate chain + terminal key");
    }
}
