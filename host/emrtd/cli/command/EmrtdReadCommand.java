package card42.host.emrtd.cli.command;

import java.security.SecureRandom;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.cli.Args;
import card42.host.common.cli.CliSupport;
import card42.host.common.transport.TerminalSession;
import card42.host.emrtd.access.Bac;
import card42.host.emrtd.access.ChipAuth;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.access.MrzKeySeed;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.aa.ActiveAuthentication;
import card42.host.emrtd.lds.common.CardAccess;
import card42.host.emrtd.lds.common.CardSecurity;
import card42.host.emrtd.lds.lds1.Com;
import card42.host.emrtd.lds.lds1.Dg1;
import card42.host.emrtd.lds.lds1.Dg15;
import card42.host.emrtd.lds.lds1.Dg2;
import card42.host.emrtd.lds.common.LdsFileUtil;
import card42.host.emrtd.lds.common.LdsSecurityObject;
import card42.host.emrtd.lds.common.Sod;
import card42.host.emrtd.lds.security.ChipAuthenticationPublicKeyInfo;
import card42.host.emrtd.pa.CscaKeyStore;
import card42.host.emrtd.pa.PassiveAuthentication;
import card42.host.emrtd.report.PassportReport;
import card42.host.emrtd.ta.CvCertificate;
import card42.host.emrtd.ta.CvCertificateCodec;
import card42.host.emrtd.ta.TerminalAuth;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * {@code terminal emrtd read|inspect}: SELECT LDS1, optionally run BAC/PACE,
 * Chip Authentication and Terminal Authentication, read DG1/DG2/COM/EF.SOD and
 * verify Active/Passive Authentication, then print a report
 * (ICAO Doc 9303-10/-11).
 */
final class EmrtdReadCommand {

    private EmrtdReadCommand() {
    }

    /** {@code read} (full) or {@code inspect} (DG15/COM without BAC). */
    static int run(String[] args, boolean inspectOnly) throws Exception {
        Args parsed = new Args(args,
                new String[] { "host", "wait", "doc", "dob", "doe", "can", "csca",
                        "ta-chain", "ta-key" },
                new String[] { "pace", "ca", "ta", "trace" },
                new String[] { "json" });
        if (parsed.help()) {
            usage(System.out);
            return CliSupport.EXIT_OK;
        }
        parsed.requireNoPositionals();
        String host = parsed.get("host", "socket:localhost:9025");
        int wait = Integer.parseInt(parsed.get("wait", "10"));
        if (wait < 0) {
            throw new IllegalArgumentException("-wait must be >= 0 seconds: " + wait);
        }
        boolean json = CliSupport.json(parsed);
        try (TerminalSession session = TerminalSession.open(
                host, wait, parsed.has("trace"), System.err)) {
            EmrtdTerminal terminal = new EmrtdTerminal(session.terminal);
            ResponseAPDU selected = terminal.selectLds1();
            if (selected.getSW() != 0x9000) {
                return CliSupport.failDeclined("SELECT LDS1 -> " + sw(selected.getSW()));
            }
            if (inspectOnly) {
                Com com = Com.parse(LdsReader.read(terminal, LdsFileUtil.FID_COM));
                Dg15 dg15 = Dg15.parse(LdsReader.read(terminal, LdsFileUtil.FID_DG15));
                boolean aa = activeAuthentication(terminal, dg15);
                System.out.print(json ? PassportReport.json(null, com, dg15, null)
                        : PassportReport.text(null, com, dg15, null));
                status(json, "Active Authentication: " + (aa ? "OK" : "not verified"));
                return CliSupport.EXIT_OK;
            }
            String doc = parsed.get("doc", null);
            String dob = parsed.get("dob", null);
            String doe = parsed.get("doe", null);
            String can = parsed.get("can", null);
            if (can == null && (doc == null || dob == null || doe == null)) {
                return CliSupport.fail("read needs -doc, -dob and -doe (or -can for PACE-CAN)");
            }
            boolean paceRequired = parsed.has("pace") || can != null;
            boolean ca = parsed.has("ca");
            String cscaPath = parsed.get("csca", null);
            CscaKeyStore trust = cscaPath == null ? null
                    : CscaKeyStore.fromPath(new java.io.File(cscaPath));
            if (ca && !paceRequired) {
                // EF.CardSecurity has read access PACE (Doc 9303-10 §3.11.4
                // Table 34), so the LDS1 EF.CardSecurity cannot be read after
                // BAC alone.
                return CliSupport.fail(
                        "read -ca requires -pace (EF.CardSecurity read access is PACE)");
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

            Pace.Session paceSession = null;
            if (can != null) {
                // PACE with the Card Access Number (password reference 0x02)
                // replaces BAC/PACE-MRZ.
                paceSession = Pace.authenticateCan(terminal, can);
                terminal.setSecureMessaging(paceSession.secureMessaging());
            } else if (parsed.has("pace")) {
                // PACE (ECDH generic mapping, 3DES, MRZ) replaces BAC.
                paceSession = Pace.authenticate(terminal, doc, dob, doe);
                terminal.setSecureMessaging(paceSession.secureMessaging());
            } else {
                byte[] seed = MrzKeySeed.seed(doc, dob, doe);
                Bac.Session bac = Bac.authenticate(terminal, seed);
                terminal.setSecureMessaging(bac.secureMessaging());
            }
            // Optional Chip Authentication: re-key the secure messaging with the
            // chip's static key (Doc 9303-11 §6.2).  EF.CardSecurity requires
            // PACE (Doc 9303-10 §3.11.4 Table 34).
            ChipAuth.Result caResult = ca ? chipAuthentication(terminal, trust) : null;
            boolean caOk = caResult != null;
            if (caOk && trust == null) {
                status(json, "EF.CardSecurity signature: not verified (no -csca)");
            }

            // Optional Terminal Authentication (Doc 9303-11 §7.1): on top of CA,
            // send the CV certificate chain and answer the chip challenge.  The
            // signed message is ID_IC || rIC || Comp(PKDH,IFD).
            if (parsed.has("ta")) {
                String chainFile = parsed.get("ta-chain", null);
                String keyHex = parsed.get("ta-key", null);
                if (paceSession == null || caResult == null || chainFile == null || keyHex == null) {
                    return CliSupport.fail("read -ta needs -pace (or -can), -ca, "
                            + "-ta-chain=<file> and -ta-key=<hex>");
                }
                java.util.List<CvCertificate> chain = CvCertificateCodec.parseChain(
                        java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(chainFile)));
                byte[] identifier = TerminalAuth.chipIdentifier(paceSession.piccPublicKey);
                byte[] keyHash =
                        TerminalAuth.chipAuthenticationKeyHash(caResult.terminalPublicKeyW);
                TerminalAuth.authenticate(terminal, chain,
                        new java.math.BigInteger(keyHex, 16), identifier, keyHash,
                        new java.security.SecureRandom());
                status(json, "Terminal Authentication: OK");
            }
            byte[] dg1Bytes = LdsReader.read(terminal, LdsFileUtil.FID_DG1);
            Dg1 dg1 = Dg1.parse(dg1Bytes);
            Com com = Com.parse(LdsReader.read(terminal, LdsFileUtil.FID_COM));
            byte[] dg2Bytes = LdsReader.read(terminal, LdsFileUtil.FID_DG2);
            Dg2 dg2 = Dg2.parse(dg2Bytes);
            System.out.print(json ? PassportReport.json(dg1, com, clearDg15, dg2)
                    : PassportReport.text(dg1, com, clearDg15, dg2));
            status(json, "Active Authentication: " + (aa ? "OK" : "not verified"));
            if (ca) {
                status(json, "Chip Authentication: " + (caOk ? "OK" : "not available"));
            }
            if (trust == null) {
                status(json, "Passive Authentication: not verified (no -csca)");
            } else {
                boolean pa = passiveAuthentication(terminal, trust, dg1Bytes, dg2Bytes,
                        clearDg15Bytes);
                status(json, "Passive Authentication: " + (pa ? "OK" : "FAILED"));
                if (!pa) {
                    return CliSupport.EXIT_DECLINED;
                }
            }
            return CliSupport.EXIT_OK;
        }
    }

    /**
     * Passive Authentication (ICAO Doc 9303-11 §5.1): verify EF.SOD against the
     * CSCA store, then each read data group against its hash in the LDS Security
     * Object.
     */
    private static boolean passiveAuthentication(EmrtdTerminal terminal, CscaKeyStore trust,
                                                 byte[] dg1, byte[] dg2, byte[] dg15)
            throws Exception {
        byte[] sodBytes = LdsReader.read(terminal, LdsFileUtil.FID_SOD);
        PassiveAuthentication.Result result =
                PassiveAuthentication.verifyResult(Sod.parse(sodBytes), trust);
        LdsSecurityObject securityObject = result.securityObject;
        try {
            PassiveAuthentication.verifyDocumentType(result.dsc, Dg1.parse(dg1));
        } catch (IllegalStateException e) {
            System.err.println("DocumentType check: " + e.getMessage());
            return false;
        }
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

    /**
     * Chip Authentication (ICAO Doc 9303-11 §6.2): read EF.CardAccess and the
     * master-file EF.CardSecurity (SELECT MF followed by SELECT 011D;
     * Doc 9303-10 §3.11.4) and re-key the secure messaging with the chip's
     * static public key.  Returns null when the card does not advertise a
     * usable ECDH/3DES Chip Authentication profile.
     *
     * <p>This is only reached for {@code -ca}, which requires PACE.  A BAC-only
     * passport has no PACE and therefore never reads these two optional files.
     */
    static ChipAuth.Result chipAuthentication(EmrtdTerminal terminal) throws Exception {
        return chipAuthentication(terminal, null);
    }

    /**
     * Chip Authentication with an optional CSCA store: when supplied,
     * EF.CardSecurity's CMS signature is verified before its CA key is used
     * (Doc 9303-11 §6.2 / H7.2).  A null store keeps the old behaviour and the
     * caller is expected to warn that authenticity was not checked.
     */
    static ChipAuth.Result chipAuthentication(EmrtdTerminal terminal, CscaKeyStore trust)
            throws Exception {
        CardAccess cardAccess = CardAccess.parse(
                LdsReader.readMf(terminal, LdsFileUtil.FID_CARD_ACCESS));
        if (cardAccess.chipAuthenticationInfos().isEmpty()) {
            return null;
        }
        CardSecurity cardSecurity = CardSecurity.parse(
                LdsReader.readMf(terminal, LdsFileUtil.FID_CARD_SECURITY));
        if (trust != null) {
            PassiveAuthentication.verifyCardSecurity(cardSecurity, trust);
        }
        if (cardSecurity.publicKeyInfos().isEmpty()) {
            return null;
        }
        ChipAuthenticationPublicKeyInfo caKey = cardSecurity.publicKeyInfos().get(0);
        byte[] chipPublicKeyW = caKey.rawPoint();
        if (chipPublicKeyW == null) {
            return null;
        }
        return ChipAuth.authenticateResult(terminal, chipPublicKeyW,
                cardAccess.chipAuthenticationInfos().get(0));
    }

    private static String sw(int sw) {
        return String.format("%04X", sw & 0xFFFF);
    }

    /** Progress/verification lines: stderr in JSON mode so stdout stays a valid document. */
    private static void status(boolean json, String message) {
        (json ? System.err : System.out).println(message);
    }

    static void usage(java.io.PrintStream out) {
        out.println("usage: Main terminal emrtd <read|inspect> [options]");
        out.println("  read     SELECT LDS1, run BAC/PACE + CA/TA, read the DGs, verify PA/AA");
        out.println("  inspect  read COM/DG15 without BAC (public data only)");
        out.println("  transport: -host=pcsc[:i]|socket:host:port -wait=<s> -trace");
        out.println("  read     : -doc=<no> -dob=YYMMDD -doe=YYMMDD  (or -can=<CAN> for PACE-CAN)");
        out.println("             -pace -ca -ta -ta-chain=<file> -ta-key=<hex> -csca=<cert|dir>");
        out.println("  output   : -json=1  structured JSON on stdout, diagnostics on stderr");
        out.println("  note     : -json=0 (default) prints the text report");
    }
}
