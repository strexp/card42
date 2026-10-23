package card42.test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.transport.Terminal;
import card42.host.common.cli.Args;
import card42.host.common.util.Hex;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.CardAccess;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.tools.EmrtdPersoExporter;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * End-to-end Terminal Authentication on the LDS2 Travel Records application
 * (ICAO Doc 9303-11 §7.1, Doc 9303-10 §5.4): the access condition is PACE+TA
 * with the Travel authorization bits, so a record read after PACE but before
 * Terminal Authentication MUST be refused, and only after CA + TA does it
 * succeed.  The card's CVCA trust point is personalized by the demo script
 * (FF07) and the terminal holds the matching demo chain ({@link TaChain}).
 *
 * <p>This suite also exercises the extended-length command path: the TA
 * {@code PSO:Verify Certificate} APDU (SM-wrapped) exceeds 255 bytes.
 */
public final class EmrtdTerminalAuthIntegrationTest {

    private static final int FID_ENTRY = 0x0101;
    private static final byte[] APPENDED = Hex.parse("5F44035553415F37083230323630313031");

    private EmrtdTerminalAuthIntegrationTest() {
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
            System.out.println("FAILED: " + Checks.failures() + " Terminal Authentication check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD TERMINAL AUTH CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        Checks.check("SELECT Travel Records",
                terminal.selectApplication(LdsFileUtil.AID_TRAVEL).getSW(), 0x9000);

        CardAccess cardAccess = CardAccess.parse(
                LdsReader.read(terminal, LdsFileUtil.FID_CARD_ACCESS));
        Checks.check("EF.CardAccess advertises Terminal Authentication",
                !cardAccess.terminalAuthenticationInfos().isEmpty());

        ResponseAPDU beforePace = terminal.readRecord(LdsFileUtil.sfi(FID_ENTRY), 1, false,
                LdsReader.CHUNK);
        Checks.check("READ RECORD before PACE -> 6982", beforePace.getSW(), 0x6982);

        Pace.Session pace = Pace.authenticate(terminal, EmrtdPersoExporter.DOCUMENT_NUMBER,
                EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        Checks.check("PACE established on the Travel application", true);

        // PACE alone is not enough for an LDS2 application: the access
        // condition is PACE+TA (Doc 9303-10 §5.4).
        Checks.check("READ RECORD after PACE, before TA -> 6982",
                terminal.readRecord(LdsFileUtil.sfi(FID_ENTRY), 1, false, LdsReader.CHUNK).getSW(),
                0x6982);
        Checks.check("APPEND RECORD before TA -> 6982",
                terminal.appendRecord(LdsFileUtil.sfi(FID_ENTRY), APPENDED).getSW(), 0x6982);

        TaSupport.authenticate(terminal, pace, new SecureRandom());
        Checks.check("Chip + Terminal Authentication completed", true);

        List<byte[]> records = LdsReader.readAllRecords(terminal, LdsFileUtil.sfi(FID_ENTRY), 1);
        Checks.check("entry record 1 readable after TA",
                records.size() >= 1 && new String(records.get(0), StandardCharsets.US_ASCII)
                        .contains("USA"));
        Checks.check("APPEND RECORD after TA",
                terminal.appendRecord(LdsFileUtil.sfi(FID_ENTRY), APPENDED).getSW(), 0x9000);
        Checks.check("appended record read back",
                java.util.Arrays.equals(APPENDED,
                        LdsReader.readRecord(terminal, LdsFileUtil.sfi(FID_ENTRY),
                                records.size() + 1)));
    }
}
