package card42.test;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import card42.host.common.cli.Args;
import card42.host.common.util.Bytes;
import card42.host.common.util.Hex;
import card42.host.emrtd.cli.Main;
import card42.host.emrtd.perso.EmrtdPersoExporter;
import card42.host.emrtd.ta.TaChain;

/**
 * End-to-end CLI coverage for {@code terminal emrtd lds2}: SELECT an LDS2 DF,
 * run the same PACE → CA → TA flow as {@code read}, then read Entry/Exit/
 * Certificate records through the extended-Le READ RECORD path.
 *
 * <p>The CLI opens its own transport, so this suite does not connect a
 * {@code Card} itself.  It writes the demo {@link TaChain} (the chain the demo
 * personalization stores as its trust point) to a temporary file, matching what
 * a user would pass as {@code -ta-chain}.
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
            int rc = Main.run(new String[] {
                    "terminal", "emrtd", "lds2",
                    "-host=" + host,
                    "-app=travel",
                    "-pace",
                    "-doc=" + EmrtdPersoExporter.DOCUMENT_NUMBER,
                    "-dob=" + EmrtdPersoExporter.DATE_OF_BIRTH,
                    "-doe=" + EmrtdPersoExporter.DATE_OF_EXPIRY,
                    "-ca",
                    "-ta",
                    "-ta-chain=" + chainFile,
                    "-ta-key=" + Hex.format(scalar32(chain.terminalPrivateScalar)),
                    "-record=all",
                    "-json=1" });
            Checks.check("lds2 CLI (PACE+CA+TA, all record EFs) exits 0", rc, 0);
        } finally {
            Files.deleteIfExists(chainFile);
        }
        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " LDS2 CLI check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD LDS2 CLI CHECKS PASSED");
    }

    /** The demo TA key as the 32-byte big-endian scalar accepted by -ta-key. */
    private static byte[] scalar32(BigInteger scalar) {
        byte[] raw = scalar.toByteArray();
        byte[] key = new byte[32];
        System.arraycopy(raw, Math.max(0, raw.length - 32), key,
                Math.max(0, 32 - raw.length), Math.min(32, raw.length));
        return key;
    }
}
