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
import card42.host.emrtd.lds.Dg1;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.lds.LdsReader;
import card42.host.emrtd.perso.EmrtdPersoExporter;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * End-to-end Chip Authentication on the LDS1 application (ICAO Doc 9303-11
 * §6.2).  The LDS1 EF.CardAccess advertises PACE and Chip Authentication; the
 * master-file EF.CardSecurity publishes the chip's static P-256 public key and
 * has read access PACE (Doc 9303-10 §3.11.4 Table 34).
 *
 * <p>The test establishes PACE with the MRZ, reads EF.CardSecurity from the
 * master file (FID 011D, which inside the LDS1 DF is EF.SOD), runs CA to
 * re-key the secure messaging and reads DG1 under the new keys.  A plaintext
 * selection of EF.CardSecurity before PACE must be refused with 6982.
 */
public final class EmrtdLds1ChipAuthIntegrationTest {

    private EmrtdLds1ChipAuthIntegrationTest() {
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
            System.out.println("FAILED: " + Checks.failures() + " LDS1 Chip Authentication check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD LDS1 CHIP AUTH CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        Checks.check("SELECT LDS1", terminal.selectLds1().getSW(), 0x9000);

        // EF.CardAccess (master file) advertises PACE and Chip Authentication.
        CardAccess cardAccess = CardAccess.parse(
                LdsReader.read(terminal, LdsFileUtil.FID_CARD_ACCESS));
        Checks.check("LDS1 EF.CardAccess advertises PACE", !cardAccess.paceInfos().isEmpty());
        Checks.check("LDS1 EF.CardAccess advertises Chip Authentication",
                !cardAccess.chipAuthenticationInfos().isEmpty());
        ChipAuthenticationInfo caInfo = cardAccess.chipAuthenticationInfos().get(0);

        // EF.CardSecurity requires PACE: SELECT MF + SELECT 011D before PACE is
        // refused (Doc 9303-10 §3.11.4 Table 34).
        ResponseAPDU mfBefore = terminal.selectMf();
        Checks.check("SELECT MF", mfBefore.getSW(), 0x9000);
        ResponseAPDU beforePace = terminal.selectFile(LdsFileUtil.FID_CARD_SECURITY);
        Checks.check("MF EF.CardSecurity before PACE -> 6982", beforePace.getSW(), 0x6982);

        // Secure messaging first (PACE, MRZ); EF.CardSecurity is read after it.
        Pace.Session pace = Pace.authenticate(terminal,
                EmrtdPersoExporter.DOCUMENT_NUMBER, EmrtdPersoExporter.DATE_OF_BIRTH,
                EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        Checks.check("PACE established on LDS1", true);

        // The master-file EF.CardSecurity is read with SELECT MF then SELECT 011D.
        terminal.selectMf();
        CardSecurity cardSecurity = CardSecurity.parse(
                LdsReader.read(terminal, LdsFileUtil.FID_CARD_SECURITY));
        Checks.check("LDS1 EF.CardSecurity publishes a CA public key",
                !cardSecurity.publicKeyInfos().isEmpty());
        ChipAuthenticationPublicKeyInfo caKey = cardSecurity.publicKeyInfos().get(0);
        byte[] chipPublicKeyW = caKey.rawPoint();
        Checks.check("LDS1 EF.CardSecurity CA public key is an uncompressed P-256 point",
                chipPublicKeyW != null && chipPublicKeyW.length == 65 && chipPublicKeyW[0] == 0x04);

        ChipAuth.authenticate(terminal, chipPublicKeyW, caInfo);
        Checks.check("LDS1 Chip Authentication re-keyed the secure messaging", true);

        // DG1 is readable under the CA secure messaging.
        Dg1 dg1 = Dg1.parse(LdsReader.read(terminal, LdsFileUtil.FID_DG1));
        Checks.check("DG1 under LDS1 CA is the sample document",
                EmrtdPersoExporter.DOCUMENT_NUMBER.equals(dg1.documentNumber));

        // A plain SELECT of FID 011D addresses the DF's EF.SOD, not the MF
        // EF.CardSecurity (both share FID 011D in different files).
        byte[] sod = LdsReader.read(terminal, LdsFileUtil.FID_SOD);
        Checks.check("DF FID 011D still selects EF.SOD", sod.length > 0 && (sod[0] & 0xFF) == 0x77);
    }
}
