package card42.test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import card42.host.common.util.Args;
import card42.host.emv.cli.Main;

/**
 * End-to-end CLI suite (docs/specs/common/toolchain.md §7.1): it drives {@link Main} directly
 * against the {@code socket:} simulator, so the option → {@code TerminalConfig} /
 * {@code TransactionRequest} mapping, the reports and the exit codes are
 * exercised without a shell.
 *
 * <p>It covers the CLI scenarios (docs/specs/common/toolchain.md §7.1) that do not
 * need a real contactless reader:
 * offline/online approval, terminal and issuer decline, unable-to-go-online,
 * cash/refund, multiple transactions, ODA disabled, the external issuer process
 * and the wrong-PIN CVM.  The contactless flow runs only in a
 * {@code TEST_CONTACTLESS=1} build and reports a skip otherwise, matching
 * {@link ContactlessTest}.
 */
public class TerminalCliTest {

    private static final String ICC_KEY_HEX = "343864C2E085AB3E433D2F982945E61F";
    private static final String SM_MAC_KEY_HEX = "911C3404804CCEBF458AA1191C152A3E";
    private static final String CONTACT_AID = "43415244420101";
    private static final String CONTACTLESS_AID = "43415244420102";

    private static String host;
    private static String caKeys;

    public static void main(String[] argv) throws Exception {
        Args args = new Args(argv, new String[] { "host" }, new String[0]);
        host = args.get("host", "socket:localhost:9025");
        caKeys = writeCaKeys();
        try {
            run();
        } finally {
            Files.deleteIfExists(Path.of(caKeys));
        }
        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " terminal CLI check(s)");
            System.exit(1);
        }
        System.out.println("ALL TERMINAL CLI CHECKS PASSED");
    }

    static void run() throws Exception {
        inspect();
        resetCounters();
        offlineApprove();
        onlineApprove();
        terminalDecline();
        issuerDecline();
        unableToGoOnline();
        cashAndRefund();
        multipleTransactions();
        odaDisabled();
        issuerCommand();
        wrongPinThenRecover();
        stage2Commands();
        contactless();
    }

    // --- Scenarios -----------------------------------------------------------

    private static void inspect() throws Exception {
        Result r = cli("terminal", "inspect", "-iface=contact", "-host=" + host,
                "-dir", "-fci", "-records", "-oda", "-ca-keys=" + caKeys, "-json");
        Checks.check("inspect exits 0", r.code == 0);
        Checks.check("inspect reports the FCI", r.out.contains("\"fci\""));
        Checks.check("inspect reads the records", r.out.contains("\"directory\""));
    }

    private static void resetCounters() throws Exception {
        Result r = pay("-floor=0", "-tac-online=0000008000", "-icc-key=" + ICC_KEY_HEX,
                "-csu-reset");
        Checks.check("counter reset transaction approves", r.code == 0);
    }

    private static void offlineApprove() throws Exception {
        Result r = pay("-floor=none");
        Checks.check("offline approve exits 0", r.code == 0);
        Checks.check("offline report is APPROVED", r.out.contains("APPROVED"));
    }

    private static void onlineApprove() throws Exception {
        Result r = pay("-floor=0", "-tac-online=0000008000", "-icc-key=" + ICC_KEY_HEX);
        Checks.check("online approve exits 0", r.code == 0);
        Checks.check("online report shows issuer auth",
                r.out.contains("issuer auth") && r.out.contains("yes"));
    }

    private static void terminalDecline() throws Exception {
        Result r = pay("-floor=0", "-tac-denial=0000008000");
        Checks.check("terminal decline exits 1", r.code == 1);
        Checks.check("terminal decline report is DECLINED", r.out.contains("DECLINED"));
    }

    private static void issuerDecline() throws Exception {
        Result r = pay("-floor=0", "-tac-online=0000008000", "-icc-key=" + ICC_KEY_HEX,
                "-arc=3035");
        Checks.check("issuer decline exits 1", r.code == 1);
    }

    private static void unableToGoOnline() throws Exception {
        Result r = pay("-floor=0", "-tac-online=0000008000", "-online=never",
                "-tac-default=0000008000");
        Checks.check("unable to go online exits 1", r.code == 1);
    }

    private static void cashAndRefund() throws Exception {
        // Online so the offline cumulative-amount limit (E002 UCOTA=10.00) is
        // not consumed: only one offline TC per reset is available.
        Checks.check("cash exits 0", pay("-type=cash", "-floor=0",
                "-tac-online=0000008000", "-icc-key=" + ICC_KEY_HEX).code == 0);
        Checks.check("refund exits 0", pay("-type=refund", "-floor=0",
                "-tac-online=0000008000", "-icc-key=" + ICC_KEY_HEX).code == 0);
        Checks.check("cashback exits 0", pay("-type=cashback", "-other=1.00", "-floor=0",
                "-tac-online=0000008000", "-icc-key=" + ICC_KEY_HEX).code == 0);
    }

    private static void multipleTransactions() throws Exception {
        Result r = pay("-floor=0", "-tac-online=0000008000", "-icc-key=" + ICC_KEY_HEX,
                "-count=2", "-seed=1");
        Checks.check("two transactions exit 0", r.code == 0);
        Checks.check("two reports printed", count(r.out, "APPROVED") == 2);
    }

    private static void odaDisabled() throws Exception {
        Result r = pay("-no-oda", "-floor=0", "-tac-online=0000008000",
                "-icc-key=" + ICC_KEY_HEX);
        Checks.check("ODA disabled exits 0", r.code == 0);
        // The highest-priority ODA method the card and terminal both support is
        // selected (EMV v4.4 Book 3 §10.3), so a missing CA key fails SDA, DDA
        // or CDA depending on the personalized AIP (CDA on the simulator,
        // SDA on an SDA-only card such as the J3R180).
        Checks.check("ODA disabled report shows the selected ODA failed",
                r.out.contains("SDA failed") || r.out.contains("DDA failed")
                        || r.out.contains("CDA failed"));
    }

    private static void issuerCommand() throws Exception {
        String script = writeIssuerScript();
        try {
            Result r = pay("-floor=0", "-tac-online=0000008000", "-issuer-cmd=" + script);
            // The script returns a declining ARC, so the bridge must produce a
            // decline (exit 1), not a usage/connection error (exit 2).
            Checks.check("issuer-cmd bridge exits 1 (decline)", r.code == 1);
        } finally {
            Files.deleteIfExists(Path.of(script));
        }
    }

    private static void wrongPinThenRecover() throws Exception {
        Result r = pay("-pin=0000", "-floor=0", "-tac-online=0000008000",
                "-icc-key=" + ICC_KEY_HEX);
        Checks.check("wrong PIN exits 0 (online approval)", r.code == 0);
        Checks.check("wrong PIN reports CVM not successful",
                r.out.contains("CVM not successful"));

        Result recovery = pay("-floor=0", "-tac-online=0000008000",
                "-icc-key=" + ICC_KEY_HEX, "-csu-reset");
        Checks.check("correct PIN recovers", recovery.code == 0);
    }

    /**
     * The stage-2 command families (docs/specs/common/toolchain.md §7.1): {@code terminal
     * apdu}, {@code card get-data/atc} and the secure-messaging {@code
     * block-app}/{@code unblock-app} round trip.
     */
    private static void stage2Commands() throws Exception {
        Result apdu = cli("terminal", "apdu", "-host=" + host,
                "-apdu=00A404000E315041592E5359532E4444463031",
                "-apdu=00CA9F3600",
                "-apdu=00FF0000");
        Checks.check("apdu exits 0", apdu.code == 0);
        Checks.check("apdu prints the SELECT response", apdu.out.contains("SW=9000"));
        Checks.check("apdu prints every exchange", count(apdu.out, "> ") == 3);
        Checks.check("apdu reports a refused command", apdu.out.contains("SW=6D00"));

        Result atc = cli("card", "atc", "-host=" + host, "-aid=" + CONTACT_AID);
        Checks.check("card atc exits 0", atc.code == 0);
        Checks.check("card atc prints the counter", atc.out.contains("ATC: "));

        Result data = cli("card", "get-data", "-host=" + host, "-aid=" + CONTACT_AID,
                "-tag=9F36");
        Checks.check("card get-data exits 0", data.code == 0);
        Checks.check("card get-data prints the TLV", data.out.contains("9F36"));

        // A reversible APPLICATION BLOCK/UNBLOCK round trip through Format 1 SM.
        Result block = cli("card", "block-app", "-host=" + host, "-aid=" + CONTACT_AID,
                "-mac-key=" + SM_MAC_KEY_HEX);
        Checks.check("card block-app exits 0", block.code == 0);
        Checks.check("card block-app reports 9000", block.out.contains("SW=9000"));
        Result unblock = cli("card", "unblock-app", "-host=" + host, "-aid=" + CONTACT_AID,
                "-mac-key=" + SM_MAC_KEY_HEX);
        Checks.check("card unblock-app exits 0", unblock.code == 0);
        Checks.check("card unblock-app reports 9000", unblock.out.contains("SW=9000"));
        Checks.check("application is READY again",
                cli("terminal", "inspect", "-host=" + host, "-aid=" + CONTACT_AID,
                        "-fci").code == 0);
    }

    private static void contactless() throws Exception {
        Result inspect = cli("terminal", "inspect", "-iface=contactless",
                "-host=" + host, "-json");
        if (inspect.code == 2 && inspect.err.contains("6A82")) {
            System.out.println("TerminalCliTest contactless skipped: build with TEST_CONTACTLESS=1");
            return;
        }
        Checks.check("contactless inspect exits 0", inspect.code == 0);

        // H7: the Entry Point diagnostic runs Start A / Combination Selection
        // and prints the activation payload.
        Result entrypoint = cli("terminal", "entrypoint", "-iface=contactless",
                "-host=" + host, "-amount=5.00", "-type=purchase", "-json");
        Checks.check("contactless entrypoint exits 0", entrypoint.code == 0);
        Checks.check("entrypoint reports the selected AID",
                entrypoint.out.contains(CONTACTLESS_AID));
        Checks.check("entrypoint reports the Kernel ID",
                entrypoint.out.contains("\"kernelId\""));

        Result pay = cli("terminal", "pay", "-iface=contactless", "-host=" + host,
                "-ca-keys=" + caKeys, "-floor=none");
        if (pay.code == 2 && pay.err.contains("6A82")) {
            System.out.println("TerminalCliTest contactless skipped: build with TEST_CONTACTLESS=1");
            return;
        }
        Checks.check("contactless offline approve exits 0", pay.code == 0);
        Checks.check("contactless report is APPROVED", pay.out.contains("APPROVED"));
    }

    // --- Helpers -------------------------------------------------------------

    private static Result pay(String... extra) throws Exception {
        String[] base = { "terminal", "pay", "-iface=contact", "-host=" + host,
                "-ca-keys=" + caKeys, "-pin=1234" };
        String[] args = new String[base.length + extra.length];
        System.arraycopy(base, 0, args, 0, base.length);
        System.arraycopy(extra, 0, args, base.length, extra.length);
        return cli(args);
    }

    private static Result cli(String... args) throws Exception {
        PrintStream oldOut = System.out;
        PrintStream oldErr = System.err;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code;
        try {
            System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
            code = Main.run(args);
        } finally {
            System.setOut(oldOut);
            System.setErr(oldErr);
        }
        return new Result(code, out.toString(StandardCharsets.UTF_8),
                err.toString(StandardCharsets.UTF_8));
    }

    private static int count(String text, String needle) {
        int count = 0;
        int at = 0;
        while ((at = text.indexOf(needle, at)) >= 0) {
            count++;
            at += needle.length();
        }
        return count;
    }

    private static String writeCaKeys() throws Exception {
        Path path = Files.createTempFile("card42-sample", ".ca.keys");
        String modulus = TestKeys.CA_MODULUS.toString(16).toUpperCase();
        Files.writeString(path, "# generated by TerminalCliTest\n"
                + "ca.01.modulus = " + modulus + "\n"
                + "ca.01.exponent = 010001\n");
        return path.toAbsolutePath().toString();
    }

    private static String writeIssuerScript() throws Exception {
        Path path = Files.createTempFile("card42-issuer", ".sh");
        Files.writeString(path, "#!/bin/sh\n"
                + "read request\n"
                + "echo '{\"arc\":\"3035\"}'\n");
        path.toFile().setExecutable(true);
        return path.toAbsolutePath().toString();
    }

    private static final class Result {
        final int code;
        final String out;
        final String err;

        Result(int code, String out, String err) {
            this.code = code;
            this.out = out;
            this.err = err;
        }
    }
}
