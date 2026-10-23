package card42.test;

import card42.host.emrtd.lds.security.*;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;

import card42.host.common.cli.Args;
import card42.host.common.transport.Terminal;
import card42.host.emrtd.access.ChipAuth;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.CardAccess;
import card42.host.emrtd.lds.CardSecurity;
import card42.host.emrtd.lds.security.ChipAuthenticationInfo;
import card42.host.emrtd.lds.security.ChipAuthenticationPublicKeyInfo;
import card42.host.emrtd.lds.Dg1;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.tools.EmrtdPersoExporter;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * End-to-end Chip Authentication v1 with the AES-128 profile on the LDS1
 * application (ICAO Doc 9303-11 §6.2, BSI TR-03110-3 B.2/B.14.3).
 *
 * <p>Unlike CA with 3DES (which uses {@code MSE:Set KAT}), CA v1 with AES uses
 * {@code MSE:Set AT} (DO'80' = the CA OID) followed by {@code GENERAL
 * AUTHENTICATE} (DO'80' = the terminal's ephemeral key), with no protocol
 * response data.  After the re-key the secure messaging runs AES-CBC/AES-CMAC;
 * the test reads DG1 under the new keys to prove the session works.
 */
public final class EmrtdChipAuthAesIntegrationTest {

    private EmrtdChipAuthAesIntegrationTest() {
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
            System.out.println("FAILED: " + Checks.failures() + " CA AES check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD CHIP AUTH AES CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        Checks.check("SELECT LDS1", terminal.selectLds1().getSW(), 0x9000);

        CardAccess cardAccess = CardAccess.parse(
                LdsReader.readMf(terminal, LdsFileUtil.FID_CARD_ACCESS));
        ChipAuthenticationInfo aesInfo = null;
        for (ChipAuthenticationInfo info : cardAccess.chipAuthenticationInfos()) {
            if ("AES".equals(info.cipherAlgorithm())) {
                aesInfo = info;
            }
        }
        Checks.check("LDS1 EF.CardAccess advertises CA ECDH AES-128", aesInfo != null);

        // Secure messaging first (PACE, MRZ); EF.CardSecurity is read after it.
        Pace.Session pace = Pace.authenticate(terminal,
                EmrtdPersoExporter.DOCUMENT_NUMBER, EmrtdPersoExporter.DATE_OF_BIRTH,
                EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        Checks.check("PACE established on LDS1", true);

        terminal.selectMf();
        CardSecurity cardSecurity = CardSecurity.parse(
                LdsReader.read(terminal, LdsFileUtil.FID_CARD_SECURITY));
        Checks.check("LDS1 EF.CardSecurity publishes a CA public key",
                !cardSecurity.publicKeyInfos().isEmpty());
        ChipAuthenticationPublicKeyInfo caKey = cardSecurity.publicKeyInfos().get(0);
        byte[] chipPublicKeyW = caKey.rawPoint();

        ChipAuth.Result ca = ChipAuth.authenticateResult(terminal, chipPublicKeyW, aesInfo);
        Checks.check("CA AES-128 re-keyed the secure messaging",
                ca.secureMessaging != null);

        // DG1 is readable under the AES secure messaging.
        Dg1 dg1 = Dg1.parse(LdsReader.read(terminal, LdsFileUtil.FID_DG1));
        Checks.check("DG1 under CA AES-128 is the sample document",
                EmrtdPersoExporter.DOCUMENT_NUMBER.equals(dg1.documentNumber));
    }
}
