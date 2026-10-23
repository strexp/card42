package card42.test;

import card42.host.emrtd.lds.security.*;

import java.security.SecureRandom;
import java.util.Locale;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.cli.Args;
import card42.host.common.transport.Terminal;
import card42.host.emrtd.access.ChipAuth;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.common.CardAccess;
import card42.host.emrtd.lds.common.CardSecurity;
import card42.host.emrtd.lds.security.ChipAuthenticationInfo;
import card42.host.emrtd.lds.common.LdsFileUtil;
import card42.host.emrtd.tools.EmrtdPersoExporter;
import card42.host.emrtd.ta.TerminalAuth;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Real-card timing harness for the eMRTD algorithm differences.  It measures,
 * on the connected card:
 *
 * <ul>
 *   <li>Active Authentication (the deployed AA variant) — INTERNAL
 *       AUTHENTICATE xN, plain;</li>
 *   <li>PACE 3DES vs AES-128 — full DG2 read after each;</li>
 *   <li>Chip Authentication 3DES vs AES-128 — full DG2 read after each;</li>
 *   <li>Terminal Authentication ECDSA-SHA-256 vs RSA-PSS-SHA-256 — the
 *       MSE:Set DST + PSO:Verify Certificate + MSE:Set AT + EXTERNAL
 *       AUTHENTICATE exchange.</li>
 * </ul>
 *
 * <p>It is report-only: it always passes (after the operations succeed) and
 * prints a table so the same run on the simulator and a real J3R180 can be
 * compared.  Run it once per deformed AA variant to compare SHA-1/SHA-256/ECDSA.
 */
public final class EmrtdPerfTest {

    private static final int AA_ROUNDS = 20;
    private static final int READ_ROUNDS = 3;

    private EmrtdPerfTest() {
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
            System.out.println("FAILED: " + Checks.failures() + " perf check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD PERF CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        System.out.println("== eMRTD algorithm timing (ms) ==");
        aa(terminal);
        paceRead(terminal, "PACE-3DES", Pace.OID_3DES);
        paceRead(terminal, "PACE-AES128", Pace.OID_AES_128);
        caRead(terminal, "CA-3DES", "DESede");
        caRead(terminal, "CA-AES128", "AES");
        ta(terminal, "TA-ECDSA", false);
        ta(terminal, "TA-RSA-PSS", true);
    }

    /** Active Authentication: N INTERNAL AUTHENTICATE round trips. */
    private static void aa(EmrtdTerminal terminal) throws Exception {
        Checks.check("SELECT LDS1", terminal.selectLds1().getSW(), 0x9000);
        byte[] challenge = new byte[8];
        new SecureRandom().nextBytes(challenge);
        long total = 0;
        for (int i = 0; i < AA_ROUNDS; i++) {
            long t0 = System.nanoTime();
            ResponseAPDU r = terminal.internalAuthenticate(challenge);
            total += System.nanoTime() - t0;
            Checks.check("AA round " + i, r.getSW(), 0x9000);
        }
        report("ActiveAuthentication", AA_ROUNDS, total);
    }

    /** Full DG2 read after PACE with the given profile. */
    private static void paceRead(EmrtdTerminal terminal, String label, byte[] oid)
            throws Exception {
        Checks.check("SELECT LDS1 " + label, terminal.selectLds1().getSW(), 0x9000);
        Pace.Session pace = Pace.authenticate(terminal,
                Pace.keySeed(EmrtdPersoExporter.DOCUMENT_NUMBER,
                        EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY),
                oid);
        terminal.setSecureMessaging(pace.secureMessaging());
        long total = 0;
        int bytes = 0;
        for (int i = 0; i < READ_ROUNDS; i++) {
            long t0 = System.nanoTime();
            byte[] dg2 = LdsReader.read(terminal, LdsFileUtil.FID_DG2);
            total += System.nanoTime() - t0;
            bytes = dg2.length;
        }
        report(label + " DG2(" + bytes + "B)", READ_ROUNDS, total);
    }

    /** Full DG2 read after Chip Authentication with the given cipher. */
    private static void caRead(EmrtdTerminal terminal, String label, String cipher)
            throws Exception {
        Checks.check("SELECT LDS1 " + label, terminal.selectLds1().getSW(), 0x9000);
        Pace.Session pace = Pace.authenticate(terminal, EmrtdPersoExporter.DOCUMENT_NUMBER,
                EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        if (!chipAuthentication(terminal, cipher)) {
            System.out.println("  " + label + "                      n/a (not advertised)");
            return;
        }
        long total = 0;
        int bytes = 0;
        for (int i = 0; i < READ_ROUNDS; i++) {
            long t0 = System.nanoTime();
            byte[] dg2 = LdsReader.read(terminal, LdsFileUtil.FID_DG2);
            total += System.nanoTime() - t0;
            bytes = dg2.length;
        }
        report(label + " DG2(" + bytes + "B)", READ_ROUNDS, total);
    }

    /** Full TA exchange with the ECDSA or RSA-PSS profile (n/a when not personalized). */
    private static void ta(EmrtdTerminal terminal, String label, boolean rsa)
            throws Exception {
        Checks.check("SELECT LDS1 " + label, terminal.selectLds1().getSW(), 0x9000);
        Pace.Session pace = Pace.authenticate(terminal, EmrtdPersoExporter.DOCUMENT_NUMBER,
                EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        ChipAuth.Result ca = TaSupport.chipAuthentication(terminal);
        long t0 = System.nanoTime();
        try {
            TaSupport.terminalAuthentication(terminal, pace,
                    TerminalAuth.chipAuthenticationKeyHash(ca.terminalPublicKeyW),
                    new SecureRandom(), rsa);
        } catch (Exception e) {
            System.out.println("  " + label + "                         n/a (no "
                    + (rsa ? "RSA-PSS" : "ECDSA") + " trust point)");
            return;
        }
        report(label, 1, System.nanoTime() - t0);
    }

    /** Runs CA with the given cipher; false when the card does not advertise it. */
    private static boolean chipAuthentication(EmrtdTerminal terminal, String cipher)
            throws Exception {
        CardAccess cardAccess = CardAccess.parse(
                LdsReader.readMf(terminal, LdsFileUtil.FID_CARD_ACCESS));
        ChipAuthenticationInfo info = null;
        for (ChipAuthenticationInfo candidate : cardAccess.chipAuthenticationInfos()) {
            if (cipher.equals(candidate.cipherAlgorithm())) {
                info = candidate;
            }
        }
        if (info == null) {
            return false;
        }
        terminal.selectMf();
        CardSecurity cardSecurity = CardSecurity.parse(
                LdsReader.read(terminal, LdsFileUtil.FID_CARD_SECURITY));
        ChipAuth.authenticate(terminal, cardSecurity.publicKeyInfos().get(0).rawPoint(), info);
        return true;
    }

    private static void report(String label, int rounds, long nanos) {
        double avgMs = nanos / 1e6 / rounds;
        System.out.println(String.format(Locale.ROOT, "  %-26s %8.2f ms  (%d round%s)",
                label, avgMs, rounds, rounds == 1 ? "" : "s"));
    }
}
