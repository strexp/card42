package card42.test;

import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.transport.Terminal;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.CardAccess;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.lds.LdsReader;
import card42.host.emrtd.perso.EmrtdPersoExporter;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * End-to-end LDS2 Visa Records and Additional Biometrics test: SELECT each
 * application, confirm that its files need PACE, establish PACE (MRZ) and read
 * the personalized EF.VisaRecords / EF.Biometrics1.
 *
 * <p>ICAO Doc 9303-11 §1.2 Note 2 requires PACE before an LDS2 application's
 * data is readable; the record EFs and EF.Biometrics are not public master-file
 * files (Doc 9303-10 §5.4).  These instances make the Visa (`…20 02`) and
 * Additional Biometrics (`…20 03`) regions of the deployment reachable.
 */
public final class EmrtdLds2AppsIntegrationTest {

    private EmrtdLds2AppsIntegrationTest() {
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
            card.disconnect(true);
        }
        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " LDS2 app check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD LDS2 APP CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        // --- Visa Records application ---------------------------------------
        Checks.check("SELECT Visa Records",
                terminal.selectApplication(LdsFileUtil.AID_VISA).getSW(), 0x9000);
        byte[] cardAccessBytes = LdsReader.read(terminal, LdsFileUtil.FID_CARD_ACCESS);
        CardAccess cardAccess = CardAccess.parse(cardAccessBytes);
        Checks.check("Visa EF.CardAccess has a PACE info", !cardAccess.paceInfos().isEmpty());

        ResponseAPDU beforePace = terminal.readRecord(
                LdsFileUtil.sfi(LdsFileUtil.FID_VISA_RECORDS), 1, false, LdsReader.CHUNK);
        Checks.check("Visa READ RECORD before PACE -> 6982", beforePace.getSW(), 0x6982);

        Pace.Session visaPace = Pace.authenticate(terminal, EmrtdPersoExporter.DOCUMENT_NUMBER,
                EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(visaPace.secureMessaging());
        Checks.check("PACE established on the Visa application", true);
        List<byte[]> visa = LdsReader.readAllRecords(terminal,
                LdsFileUtil.sfi(LdsFileUtil.FID_VISA_RECORDS), 1);
        Checks.check("at least the personalized visa record", visa.size() >= 1);
        Checks.check("visa record carries JPN",
                new String(visa.get(0), java.nio.charset.StandardCharsets.US_ASCII)
                        .contains("JPN"));

        // --- Additional Biometrics application ------------------------------
        // Drop the Visa secure messaging before selecting the other applet.
        terminal.setSecureMessaging(null);
        Checks.check("SELECT Additional Biometrics",
                terminal.selectApplication(LdsFileUtil.AID_BIOMETRICS).getSW(), 0x9000);
        // EF.Biometrics is not a public master-file EF: even SELECT FILE needs
        // PACE (Doc 9303-10 §5.4).
        Checks.check("SELECT EF.Biometrics1 before PACE -> 6982",
                terminal.selectFile(LdsFileUtil.FID_BIOMETRICS).getSW(), 0x6982);

        Pace.Session biometricsPace = Pace.authenticate(terminal,
                EmrtdPersoExporter.DOCUMENT_NUMBER, EmrtdPersoExporter.DATE_OF_BIRTH,
                EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(biometricsPace.secureMessaging());
        Checks.check("PACE established on the Biometrics application", true);
        byte[] biometrics = LdsReader.read(terminal, LdsFileUtil.FID_BIOMETRICS);
        Checks.bytes(Hex.parse("7F6108020101020203040506"), biometrics,
                "EF.Biometrics1 content");
    }
}
