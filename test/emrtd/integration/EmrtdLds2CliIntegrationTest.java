package card42.test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import card42.host.common.cli.Args;
import card42.host.common.util.Bytes;
import card42.host.common.util.Hex;
import card42.host.emrtd.cli.Main;
import card42.host.emrtd.tools.EmrtdPersoExporter;
import card42.host.emrtd.tools.TaChain;

/**
 * End-to-end CLI coverage for {@code terminal emrtd lds2} (ICAO Doc 9303-10
 * §3.7/§3.8, Doc 9303-12 §7.1.2).
 *
 * <p>The suite drives the real command dispatcher against the simulator:
 *
 * <ul>
 *   <li>PACE → CA → TA with {@code -csca}, then a JSON report for every Travel
 *       record EF; the report must carry {@code signatureValid} and
 *       {@code trusted} true (the previous suite only checked the exit code);</li>
 *   <li>{@code -append} of a Travel entry, a Visa record and a second LDS2
 *       Signer certificate, each followed by the CLI's own read-back
 *       verification.</li>
 * </ul>
 *
 * <p>The CLI opens its own transport, so this suite does not connect a
 * {@code Card} itself.  The demo {@link TaChain} is written to a temporary file
 * (the chain the demo personalization stores as its trust point).
 */
public final class EmrtdLds2CliIntegrationTest {

    private EmrtdLds2CliIntegrationTest() {
    }

    public static void main(String[] argv) throws Exception {
        Args args = new Args(argv, new String[] { "host" }, new String[0]);
        String host = args.get("host", "socket:localhost:9025");

        TaChain.Chain chain = TaChain.demo(new SecureRandom());
        Path chainFile = Files.createTempFile("card42-lds2-cli-", ".der");
        try {
            Files.write(chainFile, Bytes.concat(chain.dv.encoded(), chain.terminal.encoded()));

            Result read = run(host, chainFile, chain, "travel", "-record=all");
            Checks.check("lds2 CLI read (PACE+CA+TA, all record EFs) exits 0", read.rc, 0);
            Checks.check("lds2 CLI JSON reports signatureValid records",
                    read.out.contains("\"signatureValid\":true"));
            Checks.check("lds2 CLI -csca reports trusted records",
                    read.out.contains("\"trusted\":true"));

            if (!read.out.contains("\"embarkationState\":\"FIN\"")) {
                Result entry = run(host, chainFile, chain, "travel",
                        "-append=perso/emrtd/append-entry-cli.json",
                        "-ts-key=perso/emrtd/lds2.key", "-record=all", "-yes");
                Checks.check("lds2 CLI -append entry exits 0", entry.rc, 0);
                Checks.check("lds2 CLI appended Travel record is reported",
                        entry.out.contains("FIN")
                                && entry.out.contains("\"signatureValid\":true"));
            } else {
                Checks.check("lds2 CLI entry append already present (re-run)", true);
            }

            Result visaRead = run(host, chainFile, chain, "visa", "-record=all");
            Checks.check("lds2 CLI Visa read exits 0", visaRead.rc, 0);
            if (!visaRead.out.contains("\"issuingState\":\"SGP\"")) {
                Result visa = run(host, chainFile, chain, "visa",
                        "-append=perso/emrtd/append-visa-cli.json",
                        "-ts-key=perso/emrtd/lds2.key", "-record=all", "-yes");
                Checks.check("lds2 CLI -append visa exits 0", visa.rc, 0);
                Checks.check("lds2 CLI appended Visa record is reported",
                        visa.out.contains("SGP")
                                && visa.out.contains("\"signatureValid\":true"));
            } else {
                Checks.check("lds2 CLI visa append already present (re-run)", true);
            }

            Result certificate = run(host, chainFile, chain, "travel",
                    "-append=perso/emrtd/append-certificate-cli.json",
                    "-record=cert", "-yes");
            Checks.check("lds2 CLI -append certificate exits 0", certificate.rc, 0);
            Checks.check("lds2 CLI appended certificate is reported and trusted",
                    certificate.out.contains("CN=CARD42CLI")
                            && certificate.out.contains("\"trusted\":true"));
        } finally {
            Files.deleteIfExists(chainFile);
        }
        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " LDS2 CLI check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD LDS2 CLI CHECKS PASSED");
    }

    private static Result run(String host, Path chainFile, TaChain.Chain chain, String app,
                              String... extra) throws Exception {
        List<String> args = new ArrayList<String>();
        args.add("terminal");
        args.add("emrtd");
        args.add("lds2");
        args.add("-host=" + host);
        args.add("-app=" + app);
        args.add("-pace");
        args.add("-doc=" + EmrtdPersoExporter.DOCUMENT_NUMBER);
        args.add("-dob=" + EmrtdPersoExporter.DATE_OF_BIRTH);
        args.add("-doe=" + EmrtdPersoExporter.DATE_OF_EXPIRY);
        args.add("-ca");
        args.add("-ta");
        args.add("-ta-chain=" + chainFile);
        args.add("-ta-key=" + Hex.format(scalar32(chain.terminalPrivateScalar)));
        args.add("-csca=perso/emrtd/csca.crt");
        args.add("-json=1");
        for (String value : extra) {
            args.add(value);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream original = System.out;
        int rc;
        System.setOut(new PrintStream(out, true, "UTF-8"));
        try {
            rc = Main.run(args.toArray(new String[0]));
        } finally {
            System.setOut(original);
        }
        return new Result(rc, out.toString("UTF-8"));
    }

    /** The demo TA key as the 32-byte big-endian scalar accepted by -ta-key. */
    private static byte[] scalar32(BigInteger scalar) {
        byte[] raw = scalar.toByteArray();
        byte[] key = new byte[32];
        System.arraycopy(raw, Math.max(0, raw.length - 32), key,
                Math.max(0, 32 - raw.length), Math.min(32, raw.length));
        return key;
    }

    private static final class Result {
        final int rc;
        final String out;

        Result(int rc, String out) {
            this.rc = rc;
            this.out = out;
        }
    }
}
