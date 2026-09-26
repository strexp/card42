package card42.host.emrtd.cli.command;

import java.io.PrintStream;
import java.security.SecureRandom;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.cli.CliSupport;
import card42.host.common.transport.TerminalSession;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;
import card42.host.emrtd.access.Bac;
import card42.host.emrtd.access.MrzKeySeed;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.aa.ActiveAuthentication;
import card42.host.emrtd.lds.Com;
import card42.host.emrtd.lds.Dg1;
import card42.host.emrtd.lds.Dg15;
import card42.host.emrtd.lds.Dg2;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.lds.LdsReader;
import card42.host.emrtd.lds.LdsSecurityObject;
import card42.host.emrtd.lds.Sod;
import card42.host.emrtd.pa.CscaKeyStore;
import card42.host.emrtd.pa.PassiveAuthentication;
import card42.host.emrtd.report.PassportReport;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * {@code terminal emrtd read|inspect|lds2|apdu}.
 *
 * <ul>
 *   <li>{@code read} - SELECT LDS1, run BAC, read DG1/DG15/COM over SM, verify
 *       AA and print a report;</li>
 *   <li>{@code inspect} - read DG15/COM without BAC (read-only reconnaissance);</li>
 *   <li>{@code apdu} - send one raw APDU.</li>
 * </ul>
 */
public final class EmrtdCommand {

    private EmrtdCommand() {
    }

    public static int run(String subcommand, String[] args) throws Exception {
        switch (subcommand) {
        case "read":
            return read(args, false);
        case "inspect":
            return read(args, true);
        case "lds2":
            return lds2(args);
        case "apdu":
            return apdu(args);
        default:
            usage(System.err);
            return CliSupport.EXIT_USAGE;
        }
    }

    /**
     * {@code terminal emrtd lds2}: SELECT an LDS2 application, read EF.CardAccess
     * and every record of its record EF, and print the SecurityInfos and records.
     */
    private static int lds2(String[] args) throws Exception {
        Args parsed = new Args(args, new String[] { "host", "app", "json" }, new String[0]);
        String host = parsed.get("host", "socket:localhost:9025");
        boolean json = "1".equals(parsed.get("json", "0"));
        String app = parsed.get("app", "travel");
        String aid;
        switch (app) {
        case "travel":
            aid = LdsFileUtil.AID_TRAVEL;
            break;
        case "visa":
            aid = LdsFileUtil.AID_VISA;
            break;
        case "biometrics":
            aid = LdsFileUtil.AID_BIOMETRICS;
            break;
        default:
            return CliSupport.fail("unknown LDS2 app: " + app);
        }
        try (TerminalSession session = TerminalSession.open(host, 0, false, System.out)) {
            EmrtdTerminal terminal = new EmrtdTerminal(session.terminal);
            ResponseAPDU selected = terminal.selectApplication(aid);
            if (selected.getSW() != 0x9000) {
                return CliSupport.fail("SELECT " + aid + " -> " + Checks(selected.getSW()));
            }
            byte[] cardAccessBytes;
            try {
                cardAccessBytes = LdsReader.read(terminal, LdsFileUtil.FID_CARD_ACCESS);
            } catch (RuntimeException e) {
                cardAccessBytes = null;
            }
            card42.host.emrtd.lds.CardAccess cardAccess = cardAccessBytes == null
                    ? null : card42.host.emrtd.lds.CardAccess.parse(cardAccessBytes);
            java.util.List<byte[]> records;
            if ("biometrics".equals(app)) {
                // EF.Biometrics is a transparent EF (Doc 9303-10 §5.3.3), not a
                // record EF: report its bytes as a single entry.
                records = java.util.Collections.singletonList(
                        LdsReader.read(terminal, LdsFileUtil.FID_BIOMETRICS));
            } else {
                int recordFid = "visa".equals(app)
                        ? LdsFileUtil.FID_VISA_RECORDS : LdsFileUtil.FID_RECORDS;
                records = LdsReader.readAllRecords(terminal, LdsFileUtil.sfi(recordFid), 1);
            }
            System.out.print(json ? PassportReport.lds2Json(cardAccess, records)
                    : PassportReport.lds2Text(cardAccess, records));
            return CliSupport.EXIT_OK;
        }
    }

    private static int read(String[] args, boolean inspectOnly) throws Exception {
        Args parsed = new Args(args,
                new String[] { "host", "doc", "dob", "doe", "csca", "json" },
                new String[] { "pace" });
        String host = parsed.get("host", "socket:localhost:9025");
        boolean json = "1".equals(parsed.get("json", "0"));
        try (TerminalSession session = TerminalSession.open(host, 0, false, System.out)) {
            EmrtdTerminal terminal = new EmrtdTerminal(session.terminal);
            ResponseAPDU selected = terminal.selectLds1();
            if (selected.getSW() != 0x9000) {
                return CliSupport.fail("SELECT LDS1 -> " + Checks(selected.getSW()));
            }
            if (inspectOnly) {
                Com com = Com.parse(LdsReader.read(terminal, LdsFileUtil.FID_COM));
                Dg15 dg15 = Dg15.parse(LdsReader.read(terminal, LdsFileUtil.FID_DG15));
                boolean aa = activeAuthentication(terminal, dg15);
                System.out.print(json ? PassportReport.json(null, com, dg15, null)
                        : PassportReport.text(null, com, dg15, null));
                System.out.println("Active Authentication: " + (aa ? "OK" : "not verified"));
                return CliSupport.EXIT_OK;
            }
            String doc = parsed.get("doc", null);
            String dob = parsed.get("dob", null);
            String doe = parsed.get("doe", null);
            if (doc == null || dob == null || doe == null) {
                return CliSupport.fail("read needs -doc, -dob and -doe");
            }
            // Active Authentication needs the DG15 public key and is run in the
            // clear (a 256-byte RSA signature does not fit an SM short APDU).
            // DG15 is read before BAC only when the passport leaves it public;
            // a passport that protects it is read after BAC and AA is skipped.
            byte[] clearDg15Bytes = null;
            Dg15 clearDg15 = null;
            try {
                clearDg15Bytes = LdsReader.read(terminal, LdsFileUtil.FID_DG15);
                clearDg15 = Dg15.parse(clearDg15Bytes);
            } catch (RuntimeException e) {
                clearDg15Bytes = null;
                clearDg15 = null;
            }
            boolean aa = activeAuthentication(terminal, clearDg15);

            if (parsed.has("pace")) {
                // PACE (ECDH generic mapping, 3DES, MRZ) replaces BAC.
                Pace.authenticate(terminal, doc, dob, doe);
            } else {
                byte[] seed = MrzKeySeed.seed(doc, dob, doe);
                Bac.Session bac = Bac.authenticate(terminal, seed);
                terminal.setSecureMessaging(bac.secureMessaging());
            }
            byte[] dg1Bytes = LdsReader.read(terminal, LdsFileUtil.FID_DG1);
            Dg1 dg1 = Dg1.parse(dg1Bytes);
            Com com = Com.parse(LdsReader.read(terminal, LdsFileUtil.FID_COM));
            byte[] dg2Bytes = LdsReader.read(terminal, LdsFileUtil.FID_DG2);
            Dg2 dg2 = Dg2.parse(dg2Bytes);
            System.out.print(json ? PassportReport.json(dg1, com, clearDg15, dg2)
                    : PassportReport.text(dg1, com, clearDg15, dg2));
            System.out.println("Active Authentication: " + (aa ? "OK" : "not verified"));
            String csca = parsed.get("csca", null);
            if (csca == null) {
                System.out.println("Passive Authentication: not verified (no -csca)");
            } else {
                boolean pa = passiveAuthentication(terminal, csca, dg1Bytes, dg2Bytes, clearDg15Bytes);
                System.out.println("Passive Authentication: " + (pa ? "OK" : "FAILED"));
            }
            return CliSupport.EXIT_OK;
        }
    }

    /**
     * Passive Authentication (ICAO Doc 9303-11 §5.1): verify EF.SOD against the
     * CSCA store, then each read data group against its hash in the LDS Security
     * Object.
     */
    private static boolean passiveAuthentication(EmrtdTerminal terminal, String cscaPath,
                                                 byte[] dg1, byte[] dg2, byte[] dg15)
            throws Exception {
        byte[] sodBytes = LdsReader.read(terminal, LdsFileUtil.FID_SOD);
        CscaKeyStore trust = CscaKeyStore.fromFiles(new java.io.File(cscaPath));
        LdsSecurityObject securityObject =
                PassiveAuthentication.verify(Sod.parse(sodBytes), trust);
        boolean ok = PassiveAuthentication.verifyDataGroup(securityObject, 1, dg1)
                && PassiveAuthentication.verifyDataGroup(securityObject, 2, dg2);
        if (dg15 != null) {
            ok = ok && PassiveAuthentication.verifyDataGroup(securityObject, 15, dg15);
        }
        return ok;
    }

    private static boolean activeAuthentication(EmrtdTerminal terminal, Dg15 dg15) throws Exception {
        if (dg15 == null) {
            return false;
        }
        byte[] challenge = new byte[8];
        new SecureRandom().nextBytes(challenge);
        return ActiveAuthentication.verify(terminal, dg15, challenge);
    }

    private static int apdu(String[] args) throws Exception {
        Args parsed = new Args(args, new String[] { "host", "apdu" }, new String[0]);
        String host = parsed.get("host", "socket:localhost:9025");
        String hex = parsed.get("apdu", null);
        if (hex == null) {
            return CliSupport.fail("apdu needs -apdu=<hex>");
        }
        try (TerminalSession session = TerminalSession.open(host, 0, true, System.out)) {
            ResponseAPDU r = session.terminal.transmit(Hex.parse(hex));
            System.out.println("SW=" + String.format("%04X", r.getSW()));
            if (r.getData().length > 0) {
                System.out.println(Hex.format(r.getData()));
            }
            return CliSupport.EXIT_OK;
        }
    }

    private static String Checks(int sw) {
        return String.format("%04X", sw & 0xFFFF);
    }

    public static void usage(PrintStream out) {
        out.println("usage: Main terminal emrtd <read|inspect|lds2|apdu> [options]");
        out.println("  read    -host=... -doc=... -dob=YYMMDD -doe=YYMMDD [-pace] [-csca=<cert>] [-json=1]");
        out.println("  inspect -host=... [-json=1]");
        out.println("  lds2    -host=... [-app=travel|visa|biometrics] [-json=1]");
        out.println("  apdu    -host=... -apdu=<hex>");
    }
}
