package card42.test;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.transport.Terminal;
import card42.host.common.util.Args;
import card42.host.emrtd.access.ChipAuth;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.CardAccess;
import card42.host.emrtd.lds.CardSecurity;
import card42.host.emrtd.lds.ChipAuthenticationInfo;
import card42.host.emrtd.lds.ChipAuthenticationPublicKeyInfo;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.lds.LdsReader;
import card42.host.emrtd.perso.EmrtdPersoExporter;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * End-to-end Chip Authentication on the LDS2 Travel Records application.
 *
 * <p>The LDS2 EF.CardAccess advertises Chip Authentication and is readable
 * before PACE; EF.CardSecurity has Read Access = PACE (Doc 9303-10 §3.11.4
 * Table 34), so the test first establishes PACE with the MRZ, then reads
 * EF.CardSecurity, runs CA to re-key the session and reads a record under the
 * CA secure messaging.  A plaintext read of EF.CardSecurity before PACE must be
 * refused with 6982.
 */
public final class EmrtdChipAuthIntegrationTest {

    private static final int FID_ENTRY = 0x0101;

    private EmrtdChipAuthIntegrationTest() {
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
            System.out.println("FAILED: " + Checks.failures() + " Chip Authentication check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD CHIP AUTH CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        Checks.check("SELECT Travel Records",
                terminal.selectApplication(LdsFileUtil.AID_TRAVEL).getSW(), 0x9000);

        CardAccess cardAccess = CardAccess.parse(
                LdsReader.read(terminal, LdsFileUtil.FID_CARD_ACCESS));
        Checks.check("EF.CardAccess advertises Chip Authentication",
                !cardAccess.chipAuthenticationInfos().isEmpty());
        ChipAuthenticationInfo caInfo = cardAccess.chipAuthenticationInfos().get(0);

        // EF.CardSecurity requires PACE: a plaintext SELECT before PACE is
        // refused (Doc 9303-10 §3.11.4 Table 34).
        ResponseAPDU beforePace = terminal.selectFile(LdsFileUtil.FID_CARD_SECURITY);
        Checks.check("EF.CardSecurity before PACE -> 6982", beforePace.getSW(), 0x6982);

        // Secure messaging first (PACE, MRZ); EF.CardSecurity is read after it.
        Pace.Session pace = Pace.authenticate(terminal,
                EmrtdPersoExporter.DOCUMENT_NUMBER, EmrtdPersoExporter.DATE_OF_BIRTH,
                EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        Checks.check("PACE established on the Travel application", true);

        CardSecurity cardSecurity = CardSecurity.parse(
                LdsReader.read(terminal, LdsFileUtil.FID_CARD_SECURITY));
        Checks.check("EF.CardSecurity publishes a CA public key",
                !cardSecurity.publicKeyInfos().isEmpty());
        ChipAuthenticationPublicKeyInfo caKey = cardSecurity.publicKeyInfos().get(0);
        byte[] chipPublicKeyW = caKey.rawPoint();
        Checks.check("EF.CardSecurity CA public key is an uncompressed P-256 point",
                chipPublicKeyW != null && chipPublicKeyW.length == 65 && chipPublicKeyW[0] == 0x04);

        ChipAuth.authenticate(terminal, chipPublicKeyW, caInfo);
        Checks.check("Chip Authentication re-keyed the secure messaging", true);

        byte[] record = LdsReader.readRecord(terminal, LdsFileUtil.sfi(FID_ENTRY), 1);
        Checks.check("entry record 1 readable under the CA secure messaging",
                new String(record, java.nio.charset.StandardCharsets.US_ASCII).contains("USA"));
    }
}
