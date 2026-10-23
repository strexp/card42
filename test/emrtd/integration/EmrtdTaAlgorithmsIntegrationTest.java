package card42.test;

import java.security.SecureRandom;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;

import card42.host.common.cli.Args;
import card42.host.common.transport.Terminal;
import card42.host.emrtd.access.ChipAuth;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.common.LdsFileUtil;
import card42.host.emrtd.tools.EmrtdPersoExporter;
import card42.host.emrtd.ta.TerminalAuth;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Terminal Authentication with both profiles on the LDS1 application (ICAO
 * Doc 9303-11 §7.1): the same card carries an ECDSA-SHA-256 and an RSA-PSS-SHA-256
 * CVCA trust point (DGI FF07 and FF0B), so the terminal can authenticate with
 * either chain.  EF.DG3/DG4 (fingerprints/irises) are CHAT-gated once a trust
 * point is personalized, so they are readable only after a successful TA.
 */
public final class EmrtdTaAlgorithmsIntegrationTest {

    private EmrtdTaAlgorithmsIntegrationTest() {
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
            System.out.println("FAILED: " + Checks.failures() + " TA algorithm check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD TA ALGORITHM CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        Checks.check("SELECT LDS1", terminal.selectLds1().getSW(), 0x9000);
        authenticateWith(terminal, "ECDSA", false);

        // A fresh session for the RSA-PSS profile (TA runs once per session).
        Checks.check("re-SELECT LDS1", terminal.selectLds1().getSW(), 0x9000);
        authenticateWith(terminal, "RSA-PSS", true);
    }

    /** PACE + Chip Authentication + Terminal Authentication with one profile. */
    private static void authenticateWith(EmrtdTerminal terminal, String label, boolean rsa)
            throws Exception {
        Pace.Session pace = Pace.authenticate(terminal,
                EmrtdPersoExporter.DOCUMENT_NUMBER, EmrtdPersoExporter.DATE_OF_BIRTH,
                EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());

        // DG3/DG4 require the ePassport CHAT once a trust point is personalized.
        terminal.selectFile(LdsFileUtil.dgFid(3));
        Checks.check(label + ": DG3 before TA -> 6982",
                terminal.readBinary(0, 0x20).getSW(), 0x6982);

        ChipAuth.Result ca = TaSupport.chipAuthentication(terminal);
        TaSupport.terminalAuthentication(terminal, pace,
                TerminalAuth.chipAuthenticationKeyHash(ca.terminalPublicKeyW),
                new SecureRandom(), rsa);

        terminal.selectFile(LdsFileUtil.dgFid(3));
        Checks.check(label + ": DG3 after TA", terminal.readBinary(0, 0x20).getSW(), 0x9000);
        terminal.selectFile(LdsFileUtil.dgFid(4));
        Checks.check(label + ": DG4 after TA", terminal.readBinary(0, 0x20).getSW(), 0x9000);
        terminal.selectFile(LdsFileUtil.FID_DG1);
        Checks.check(label + ": DG1 after TA", terminal.readBinary(0, 0x20).getSW(), 0x9000);
    }
}
