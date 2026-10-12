package card42.test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;

import card42.host.common.cli.Args;
import card42.host.common.transport.Terminal;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.perso.EmrtdPersoExporter;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * EF.CVCA and the PACE Certification Authority References (ICAO Doc 9303-11
 * Annex K.2 / §4.4.4.1 / §4.4.5).
 *
 * <p>After PACE with the MRZ the LDS1 application exposes EF.CVCA (FID 011C,
 * SFI 1C) as a fixed 36-octet file of {@code 42 <len> <CAR>} data objects, most
 * recent first, padded with 0x00.  When the terminal requests the CARs during
 * PACE (DO'7F4C'), the card returns the same most recent reference as DO'87'
 * in the PACE authentication response.  EF.CVCA read access is PACE, so a
 * plaintext read before PACE is refused.
 */
public final class EmrtdCvcaTest {

    private static final byte[] DEMO_CAR =
            "UTCVCA0000000001".getBytes(StandardCharsets.US_ASCII);

    private EmrtdCvcaTest() {
    }

    public static void main(String[] argv) throws Exception {
        Args args = new Args(argv, new String[] { "host" }, new String[0]);
        String host = args.get("host", "socket:localhost:9025");
        CardTerminal cardTerminal = TestTerminals.getTerminal(host.split(":"));
        if (cardTerminal == null || !cardTerminal.waitForCardPresent(10000)) {
            throw new IllegalStateException("Connection to simulator failed on " + host);
        }
        Card card = cardTerminal.connect("*");
        try {
            run(new EmrtdTerminal(new Terminal(card.getBasicChannel())));
        } finally {
            card.disconnect(false);
        }
        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " EF.CVCA check(s)");
            System.exit(1);
        }
        System.out.println("ALL EF.CVCA CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        Checks.check("SELECT LDS1", terminal.selectLds1().getSW(), 0x9000);

        // EF.CVCA read access is PACE: a plaintext read before PACE is refused
        // (Doc 9303-11 K.2).  SELECT FILE itself is not gated.
        terminal.selectFile(LdsFileUtil.FID_CVCA);
        int beforePace = terminal.readBinary(0, 36).getSW();
        Checks.check("EF.CVCA read before PACE -> 6982", beforePace == 0x6982);

        // PACE requests the CARs (DO'7F4C'); the card returns them as DO'87'.
        Pace.Session pace = Pace.authenticate(terminal,
                EmrtdPersoExporter.DOCUMENT_NUMBER, EmrtdPersoExporter.DATE_OF_BIRTH,
                EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        Checks.check("PACE established on LDS1", true);

        List<byte[]> cars = pace.certificationAuthorityReferences;
        Checks.check("PACE returned a CVCA CAR", cars.size() >= 1);
        Checks.bytes(DEMO_CAR, cars.get(0), "PACE DO'87' is the demo CVCA CAR");

        // EF.CVCA is a fixed 36-octet file: 42 10 <CAR> padded with 0x00.
        byte[] cvca = LdsReader.read(terminal, LdsFileUtil.FID_CVCA);
        Checks.check("EF.CVCA is 36 octets", cvca.length == 36);
        Checks.check("EF.CVCA first CAR is 42 10", (cvca[0] & 0xFF) == 0x42
                && (cvca[1] & 0xFF) == 16);
        Checks.bytes(DEMO_CAR, java.util.Arrays.copyOfRange(cvca, 2, 18),
                "EF.CVCA carries the demo CVCA CAR");
        boolean padded = true;
        for (int i = 18; i < 36; i++) {
            padded &= cvca[i] == 0;
        }
        Checks.check("EF.CVCA is padded with 0x00", padded);
    }
}
