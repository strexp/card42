package card42.test;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.transport.Terminal;
import card42.host.common.util.Args;
import card42.host.emrtd.access.Bac;
import card42.host.emrtd.access.MrzKeySeed;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.Dg1;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.lds.LdsReader;
import card42.host.emrtd.perso.EmrtdPersoExporter;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * End-to-end host-side PACE test: SELECT the LDS1 DF,
 * run PACE (ECDH generic mapping, 3DES and AES-128, MRZ) and read DG1 under the
 * PACE secure messaging.  The self-written P-256 arithmetic is exercised against
 * the card's platform ECC.
 */
public final class EmrtdPaceIntegrationTest {

    private EmrtdPaceIntegrationTest() {
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
            EmrtdTerminal terminal = new EmrtdTerminal(new Terminal(card.getBasicChannel()));
            Checks.check("SELECT LDS1", terminal.selectLds1().getSW(), 0x9000);
            byte[] seed = Pace.keySeed(EmrtdPersoExporter.DOCUMENT_NUMBER,
                    EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY);
            runProfile(terminal, seed, Pace.OID_3DES, "3DES");
            // A plaintext APDU after PACE aborts the session (Doc 9303-11
            // §9.8.3), so a second PACE needs a fresh SELECT.
            terminal.setSecureMessaging(null);
            Checks.check("re-SELECT before AES PACE", terminal.selectLds1().getSW(), 0x9000);
            runProfile(terminal, seed, Pace.OID_AES_128, "AES-128");

            // Regression: repeated PACE must not exhaust the card's persistent
            // heap.  The PACE EC keys are reused across sessions; allocating a
            // fresh KeyPair per session made the card answer 6F00 after ~9 runs.
            for (int i = 0; i < 12; i++) {
                terminal.setSecureMessaging(null);
                Checks.check("re-SELECT before PACE #" + i, terminal.selectLds1().getSW(), 0x9000);
                runProfile(terminal, seed, Pace.OID_3DES, "3DES #" + i);
            }

            // Regression: a prior AES PACE session must not leak into BAC; a
            // fresh SELECT resets the card's secure-messaging state.
            terminal.setSecureMessaging(null);
            Checks.check("re-SELECT LDS1", terminal.selectLds1().getSW(), 0x9000);
            Bac.Session bac = Bac.authenticate(terminal, MrzKeySeed.seed(
                    EmrtdPersoExporter.DOCUMENT_NUMBER,
                    EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY));
            terminal.setSecureMessaging(bac.secureMessaging());
            Dg1 afterBac = Dg1.parse(LdsReader.read(terminal, LdsFileUtil.FID_DG1));
            Checks.check("BAC after PACE reads DG1",
                    EmrtdPersoExporter.DOCUMENT_NUMBER.equals(afterBac.documentNumber));
        } finally {
            card.disconnect(true);
        }
        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " eMRTD PACE check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD PACE CHECKS PASSED");
    }

    private static void runProfile(EmrtdTerminal terminal, byte[] seed, byte[] oid,
                                   String label) throws Exception {
        Pace.Session session = Pace.authenticate(terminal, seed, oid);
        Checks.check("PACE ECDH-GM " + label + " established", true);
        terminal.setSecureMessaging(session.secureMessaging());
        Dg1 parsed = Dg1.parse(LdsReader.read(terminal, LdsFileUtil.FID_DG1));
        Checks.check("DG1 document number under PACE " + label,
                EmrtdPersoExporter.DOCUMENT_NUMBER.equals(parsed.documentNumber));
        Checks.check("DG1 surname under PACE " + label, "ERIKSSON".equals(parsed.surname));

        // A plaintext APDU after PACE aborts the session and is refused with
        // 6982 (BSI TR-03110-3 / Doc 9303-11 §9.8.3).
        ResponseAPDU plain = terminal.base().transmit(
                new CommandAPDU(0x00, 0xB0, 0x00, 0x00, 1));
        Checks.check("plaintext APDU after PACE -> 6982", plain.getSW(), 0x6982);
    }
}
