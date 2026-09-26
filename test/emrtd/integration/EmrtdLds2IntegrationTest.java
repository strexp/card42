package card42.test;

import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.transport.Terminal;
import card42.host.common.util.Args;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.CardAccess;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.lds.LdsReader;
import card42.host.emrtd.perso.EmrtdPersoExporter;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * End-to-end LDS2 Travel Records test: SELECT the Travel Records DF, read
 * EF.CardAccess in the clear, establish PACE (MRZ), then read the personalized
 * Entry Records and append/read a fresh record under the PACE secure messaging.
 *
 * <p>ICAO Doc 9303-11 §1.2 Note 2 requires the execution of PACE for access to
 * LDS2 applications; only EF.CardAccess is readable before PACE (Doc 9303-10
 * §3.11.3 Table 32).  The test therefore checks that a record read before PACE
 * is refused with 6982.
 *
 * <p>The record EF is append-only and persists across sessions, so the test
 * reads the current record count first and appends at the end instead of
 * assuming a pristine two-record card: it is re-runnable against a card that a
 * previous run (or a second personalization) has already appended to.
 */
public final class EmrtdLds2IntegrationTest {

    private EmrtdLds2IntegrationTest() {
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
            System.out.println("FAILED: " + Checks.failures() + " LDS2 check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD LDS2 CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        Checks.check("SELECT Travel Records", terminal.selectApplication(LdsFileUtil.AID_TRAVEL).getSW(),
                0x9000);

        // EF.CardAccess is readable before PACE (Doc 9303-10 §3.11.3 Table 32).
        byte[] cardAccessBytes = LdsReader.read(terminal, LdsFileUtil.FID_CARD_ACCESS);
        CardAccess cardAccess = CardAccess.parse(cardAccessBytes);
        Checks.check("EF.CardAccess has a PACE info", !cardAccess.paceInfos().isEmpty());
        Checks.check("PACE ECDH generic mapping selected",
                cardAccess.selectPace() != null && cardAccess.selectPace().isEcdhGenericMapping());
        Checks.check("EF.CardAccess has a Chip Authentication info",
                !cardAccess.chipAuthenticationInfos().isEmpty());

        // EF.ATR/INFO and EF.DIR are master-file files readable before PACE
        // (Doc 9303-10 §3.11.1/§3.11.2).
        Checks.check("SELECT EF.ATR/INFO before PACE",
                terminal.selectFile(LdsFileUtil.FID_ATR_INFO).getSW(), 0x9000);
        Checks.check("SELECT EF.DIR before PACE",
                terminal.selectFile(LdsFileUtil.FID_DIR).getSW(), 0x9000);

        // Before PACE the LDS2 records must be refused (Doc 9303-11 §1.2 Note 2).
        ResponseAPDU beforePace = terminal.readRecord(LdsFileUtil.sfi(FID_ENTRY), 1, false,
                LdsReader.CHUNK);
        Checks.check("LDS2 READ RECORD before PACE -> 6982", beforePace.getSW(), 0x6982);

        // Establish PACE with the MRZ; every LDS2 access is now authorized.
        Pace.Session pace = Pace.authenticate(terminal, EmrtdPersoExporter.DOCUMENT_NUMBER,
                EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        Checks.check("PACE established on the Travel application", true);

        List<byte[]> records = LdsReader.readAllRecords(terminal, LdsFileUtil.sfi(FID_ENTRY), 1);
        Checks.check("at least the two personalized entry records (" + records.size() + ")",
                records.size() >= 2);
        Checks.check("record 1 carries USA",
                new String(records.get(0), java.nio.charset.StandardCharsets.US_ASCII)
                        .contains("USA"));
        Checks.check("record 2 carries NLD",
                new String(records.get(1), java.nio.charset.StandardCharsets.US_ASCII)
                        .contains("NLD"));

        byte[] appended = card42.host.common.util.Hex.parse("5F440343414E5F37083230323630333031");
        Checks.check("APPEND RECORD", terminal.appendRecord(LdsFileUtil.sfi(FID_ENTRY), appended).getSW(),
                0x9000);
        int appendedNumber = records.size() + 1;
        byte[] readBack = LdsReader.readRecord(terminal, LdsFileUtil.sfi(FID_ENTRY), appendedNumber);
        Checks.check("appended record read back", java.util.Arrays.equals(appended, readBack));
        Checks.check("record " + (appendedNumber + 1) + " is absent",
                terminal.readRecord(LdsFileUtil.sfi(FID_ENTRY), appendedNumber + 1, false,
                        LdsReader.CHUNK).getSW(),
                0x6A83);
    }

    private static final int FID_ENTRY = 0x0101;
}
