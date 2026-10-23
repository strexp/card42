package card42.test;

import java.security.SecureRandom;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.cli.Args;
import card42.host.common.transport.Terminal;
import card42.host.emrtd.access.ChipAuth;
import card42.host.emrtd.access.Iso7816SmAes;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.common.CardAccess;
import card42.host.emrtd.lds.common.LdsFileUtil;
import card42.host.emrtd.lds.security.ChipAuthenticationInfo;
import card42.host.emrtd.lds.security.PaceInfo;
import card42.host.emrtd.lds.security.SecurityInfo;
import card42.host.emrtd.tools.EmrtdPersoExporter;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * LDS2 authentication algorithm matrix (ICAO Doc 9303-11 §4.4/§6/§7.1).
 *
 * <p>The existing LDS2 suites use only the default PACE/CA 3DES profile and the
 * ECDSA Terminal Authentication chain, while the AES profile was tested only on
 * LDS1.  This suite drives the same LDS2 applications with:
 *
 * <ul>
 *   <li>PACE ECDH-GM AES-128 and CA ECDH AES-128, then reads a 645-byte
 *       EF.Certificates record so the AES 223-byte short-response window and
 *       the large-record wrap path are both exercised;</li>
 *   <li>PACE-CAN (password reference 0x02) with the MRZ/CAN personalization;</li>
 *   <li>Terminal Authentication with the RSA-PSS CVCA trust point on LDS2,
 *       which was previously only tested on LDS1.</li>
 * </ul>
 */
public final class EmrtdLds2AlgorithmsIntegrationTest {

    private EmrtdLds2AlgorithmsIntegrationTest() {
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
            System.out.println("FAILED: " + Checks.failures() + " LDS2 algorithm check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD LDS2 ALGORITHM CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        paceAesAndCaAes(terminal);
        paceCan(terminal);
        taRsaPss(terminal);
    }

    /** PACE-AES128 → CA-AES128 → TA-ECDSA, then a large AES record read. */
    private static void paceAesAndCaAes(EmrtdTerminal terminal) throws Exception {
        Checks.check("SELECT Travel Records for PACE/CA AES",
                terminal.selectApplication(LdsFileUtil.AID_TRAVEL).getSW(), 0x9000);

        CardAccess cardAccess = CardAccess.parse(
                LdsReader.read(terminal, LdsFileUtil.FID_CARD_ACCESS));
        PaceInfo aesPace = null;
        for (PaceInfo info : cardAccess.paceInfos()) {
            if (SecurityInfo.ID_PACE_ECDH_GM_AES_128.equals(info.oid)) {
                aesPace = info;
            }
        }
        Checks.check("EF.CardAccess advertises PACE ECDH-GM AES-128", aesPace != null);

        Pace.Session pace = Pace.authenticate(terminal,
                Pace.keySeed(EmrtdPersoExporter.DOCUMENT_NUMBER,
                        EmrtdPersoExporter.DATE_OF_BIRTH,
                        EmrtdPersoExporter.DATE_OF_EXPIRY),
                Pace.OID_AES_128);
        terminal.setSecureMessaging(pace.secureMessaging());
        Checks.check("PACE AES-128 uses AES secure messaging",
                pace.secureMessaging() instanceof Iso7816SmAes);

        ChipAuthenticationInfo aesCa = null;
        for (ChipAuthenticationInfo info : cardAccess.chipAuthenticationInfos()) {
            if ("AES".equals(info.cipherAlgorithm())) {
                aesCa = info;
            }
        }
        Checks.check("EF.CardAccess advertises CA ECDH AES-128", aesCa != null);
        if (aesCa == null) {
            throw new IllegalStateException("sample EF.CardAccess has no CA AES-128 profile");
        }
        ChipAuth.Result ca = TaSupport.chipAuthentication(terminal, aesCa);
        Checks.check("Chip Authentication AES-128 re-keyed the LDS2 session",
                ca.secureMessaging instanceof Iso7816SmAes);

        TaSupport.terminalAuthentication(terminal, pace,
                card42.host.emrtd.ta.TerminalAuth.chipAuthenticationKeyHash(
                        ca.terminalPublicKeyW), new SecureRandom());
        Checks.check("Terminal Authentication after CA AES-128", true);

        byte[] entry = LdsReader.readRecord(terminal,
                LdsFileUtil.sfi(LdsFileUtil.FID_RECORDS), 1);
        Checks.check("Entry record readable under PACE/CA AES-128",
                new String(entry, java.nio.charset.StandardCharsets.US_ASCII)
                        .contains("USA"));

        byte[] certificate = LdsReader.readRecord(terminal,
                LdsFileUtil.sfi(LdsFileUtil.FID_CERTIFICATES), 1);
        Checks.check("645 B EF.Certificates read in one AES response ("
                + certificate.length + " B)", certificate.length > 512);
    }

    /** PACE-CAN (password reference 0x02) then CA+TA and a record read. */
    private static void paceCan(EmrtdTerminal terminal) throws Exception {
        terminal.setSecureMessaging(null);
        Checks.check("re-SELECT Travel for PACE-CAN",
                terminal.selectApplication(LdsFileUtil.AID_TRAVEL).getSW(), 0x9000);
        Pace.Session pace = Pace.authenticateCan(terminal,
                EmrtdPersoExporter.CARD_ACCESS_NUMBER);
        terminal.setSecureMessaging(pace.secureMessaging());
        Checks.check("PACE-CAN established on the LDS2 Travel application", true);
        TaSupport.authenticate(terminal, pace, new SecureRandom());
        Checks.check("Chip + Terminal Authentication after PACE-CAN", true);

        byte[] entry = LdsReader.readRecord(terminal,
                LdsFileUtil.sfi(LdsFileUtil.FID_RECORDS), 1);
        Checks.check("Entry record readable after PACE-CAN",
                new String(entry, java.nio.charset.StandardCharsets.US_ASCII)
                        .contains("USA"));
    }

    /** PACE/CA 3DES with the RSA-PSS Terminal Authentication trust point. */
    private static void taRsaPss(EmrtdTerminal terminal) throws Exception {
        terminal.setSecureMessaging(null);
        Checks.check("re-SELECT Travel for TA RSA-PSS",
                terminal.selectApplication(LdsFileUtil.AID_TRAVEL).getSW(), 0x9000);
        Pace.Session pace = Pace.authenticate(terminal, EmrtdPersoExporter.DOCUMENT_NUMBER,
                EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        ChipAuth.Result ca = TaSupport.chipAuthentication(terminal);
        TaSupport.terminalAuthentication(terminal, pace,
                card42.host.emrtd.ta.TerminalAuth.chipAuthenticationKeyHash(
                        ca.terminalPublicKeyW), new SecureRandom(), true);
        Checks.check("Terminal Authentication with RSA-PSS on LDS2", true);

        ResponseAPDU entry = terminal.readRecord(LdsFileUtil.sfi(LdsFileUtil.FID_RECORDS),
                1, false, LdsReader.RECORD_LE);
        Checks.check("Entry record readable after RSA-PSS TA", entry.getSW(), 0x9000);
        Checks.check("Entry record contains the sample state",
                new String(entry.getData(), java.nio.charset.StandardCharsets.US_ASCII)
                        .contains("USA"));
    }
}
