package card42.host.emrtd.cli.command;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.cli.Args;
import card42.host.common.cli.CliSupport;
import card42.host.common.transport.TerminalSession;
import card42.host.emrtd.access.ChipAuth;
import card42.host.emrtd.access.Lds2CertificateStore;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.CardAccess;
import card42.host.emrtd.lds.CertificateRecord;
import card42.host.emrtd.lds.Lds2Record;
import card42.host.emrtd.access.Lds2RecordWriter;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.pa.CscaKeyStore;
import card42.host.emrtd.pa.Lds2Verifier;
import card42.host.emrtd.report.PassportReport;
import card42.host.emrtd.ta.CvCertificate;
import card42.host.emrtd.ta.CvCertificateCodec;
import card42.host.emrtd.ta.TerminalAuth;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * {@code terminal emrtd lds2}: SELECT an LDS2 application, read EF.CardAccess,
 * establish PACE (and optionally Chip/Terminal Authentication), then read the
 * selected record EF(s) and print the SecurityInfos and records
 * (ICAO Doc 9303-10 §3.11 / §5, Doc 9303-11 §1.2 Note 2 / §4.2).
 *
 * <p>LDS2 records require PACE and, on a card with a Terminal Authentication
 * trust point, the matching LDS2 authorization bits; the command therefore
 * shares the {@code read} authentication flow instead of touching READ RECORD
 * before the session is authorized.  {@code -append=<json>} builds a structured
 * Travel/Visa/Biometrics/Certificate record (Table 86/90/93/83), validates the
 * signer certificate and key binding, writes it, and verifies the read-back.
 */
final class EmrtdLds2Command {

    private static final String[] RECORD_OPTIONS = {
            "host", "app", "json", "record", "doc", "dob", "doe", "can",
            "ta-chain", "ta-key", "append", "ts-key", "cert-ref", "csca" };
    private static final String[] RECORD_FLAGS = { "pace", "ca", "ta" };

    private EmrtdLds2Command() {
    }

    static int run(String[] args) throws Exception {
        Args parsed = new Args(args, RECORD_OPTIONS, RECORD_FLAGS);
        String host = parsed.get("host", "socket:localhost:9025");
        boolean json = "1".equals(parsed.get("json", "0"));
        String app = parsed.get("app", "travel");
        String doc = parsed.get("doc", null);
        String dob = parsed.get("dob", null);
        String doe = parsed.get("doe", null);
        String can = parsed.get("can", null);
        String record = parsed.get("record", defaultRecord(app));
        String taChain = parsed.get("ta-chain", null);
        String taKey = parsed.get("ta-key", null);
        String append = parsed.get("append", null);
        String tsKey = parsed.get("ts-key", null);
        String csca = parsed.get("csca", null);
        int certRef = parseCertRef(parsed.get("cert-ref", "1"));
        CscaKeyStore trust = csca == null ? null
                : CscaKeyStore.fromPath(new java.io.File(csca));

        Lds2AppendSpec appendSpec = null;
        if (append != null) {
            try {
                appendSpec = Lds2AppendSpec.parse(java.nio.file.Paths.get(append), app,
                        tsKey, certRef, trust);
            } catch (Exception e) {
                return CliSupport.fail(e.getMessage());
            }
            record = parsed.has("record") ? record : null;
        }

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

        String validation = validate(parsed, app, record, doc, dob, doe, can, taChain, taKey,
                appendSpec);
        if (validation != null) {
            return CliSupport.fail(validation);
        }

        try (TerminalSession session = TerminalSession.open(host, 10, false, System.out)) {
            EmrtdTerminal terminal = new EmrtdTerminal(session.terminal);
            ResponseAPDU selected = terminal.selectApplication(aid);
            if (selected.getSW() != 0x9000) {
                return CliSupport.fail("SELECT " + aid + " -> " + sw(selected.getSW()));
            }

            // EF.CardAccess is public and readable before PACE; it carries the
            // PACE / CA / TA SecurityInfos (Doc 9303-10 §3.11.3 Table 32).
            byte[] cardAccessBytes;
            try {
                cardAccessBytes = LdsReader.read(terminal, LdsFileUtil.FID_CARD_ACCESS);
            } catch (RuntimeException e) {
                cardAccessBytes = null;
            }
            CardAccess cardAccess = cardAccessBytes == null
                    ? null : CardAccess.parse(cardAccessBytes);

            // LDS2 records require PACE (Doc 9303-11 §1.2 Note 2 / §4.2 step 3).
            Pace.Session paceSession = can != null
                    ? Pace.authenticateCan(terminal, can)
                    : Pace.authenticate(terminal, doc, dob, doe);
            terminal.setSecureMessaging(paceSession.secureMessaging());
            System.out.println("PACE: OK (" + (can != null ? "CAN" : "MRZ") + ")");

            ChipAuth.Result caResult = null;
            if (parsed.has("ca")) {
                caResult = EmrtdReadCommand.chipAuthentication(terminal, trust);
                System.out.println("Chip Authentication: "
                        + (caResult != null ? "OK" : "not available"));
                if (caResult != null && trust == null) {
                    System.out.println("EF.CardSecurity signature: not verified (no -csca)");
                }
            }

            if (parsed.has("ta")) {
                if (caResult == null) {
                    return CliSupport.fail("ta needs a usable Chip Authentication profile");
                }
                // The TA signature binds the PACE key (ID_IC) to the CA terminal
                // key (Comp(PKDH,IFD)); EF.Certificates read access is b3 for
                // Travel/Visa (Doc 9303-10 §5.4.2 Table 96/97).
                List<CvCertificate> chain = CvCertificateCodec.parseChain(
                        java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(taChain)));
                TerminalAuth.authenticate(terminal, chain, new BigInteger(taKey, 16),
                        TerminalAuth.chipIdentifier(paceSession.piccPublicKey),
                        TerminalAuth.chipAuthenticationKeyHash(caResult.terminalPublicKeyW),
                        new SecureRandom());
                System.out.println("Terminal Authentication: OK");
            }

            if (appendSpec != null) {
                String label = labelForFid(appendSpec.fid);
                if ("certificate".equals(appendSpec.type)) {
                    if (trust == null) {
                        return CliSupport.fail(
                                "certificate append needs -csca=<CSCA certificate>");
                    }
                    int before = LdsReader.readAllRecords(terminal,
                            LdsFileUtil.sfi(LdsFileUtil.FID_CERTIFICATES), 1).size();
                    int reference = Lds2CertificateStore.findOrAppend(
                            terminal, appendSpec.certificate, app, trust);
                    CertificateRecord certificateRecord = Lds2Verifier.loadCertificateRecord(
                            terminal, reference);
                    Lds2Verifier.CertificateCheck check = Lds2Verifier.checkCertificate(
                            Lds2Verifier.x509(certificateRecord.certificate),
                            certificateRecord, app, trust);
                    if (!check.profileValid || !check.trusted) {
                        return CliSupport.fail("written LDS2 certificate is not conformant: "
                                + String.join("; ", check.problems));
                    }
                    System.out.println((reference > before ? "Appended" : "Reused")
                            + " certificate record #" + reference + " ("
                            + certificateRecord.raw().length + " B) in 011A; signer "
                            + check.subject + " (profile OK, trust OK)");
                } else {
                    CertificateRecord signerRecord = Lds2Verifier.loadCertificateRecord(
                            terminal, appendSpec.certificateReference);
                    if (signerRecord == null) {
                        return CliSupport.fail("5F38 references missing EF.Certificates record "
                                + appendSpec.certificateReference);
                    }
                    X509Certificate signer = Lds2Verifier.x509(signerRecord.certificate);
                    Lds2Verifier.CertificateCheck check = Lds2Verifier.checkCertificate(
                            signer, signerRecord, app, trust);
                    if (!check.profileValid || (trust != null && !check.trusted)) {
                        return CliSupport.fail("LDS2 signer certificate rejected: "
                                + String.join("; ", check.problems));
                    }
                    if (!appendSpec.keyMatches(signer)) {
                        return CliSupport.fail("the -ts-key does not match EF.Certificates record "
                                + appendSpec.certificateReference);
                    }
                    System.out.println("Signer certificate: " + check.subject
                            + " (profile OK, trust=" + check.trusted + ")");
                    int before = 0;
                    if ("biometrics".equals(appendSpec.type)) {
                        Lds2RecordWriter.writeBiometrics(terminal, appendSpec.fid,
                                appendSpec.record);
                    } else {
                        before = LdsReader.readAllRecords(terminal,
                                LdsFileUtil.sfi(appendSpec.fid), 1).size();
                        Lds2RecordWriter.append(terminal, appendSpec.fid, appendSpec.record);
                    }
                    byte[] written = "biometrics".equals(appendSpec.type)
                            ? LdsReader.read(terminal, appendSpec.fid)
                            : LdsReader.readRecord(terminal, LdsFileUtil.sfi(appendSpec.fid),
                                    before + 1);
                    Lds2Verifier.Verification verification = Lds2Verifier.verifyRecord(
                            written, label, signer, signerRecord, app, trust);
                    if (!verification.signatureValid || verification.certificate == null
                            || !verification.certificate.profileValid
                            || (trust != null && !verification.certificate.trusted)) {
                        return CliSupport.fail("written record failed LDS2 verification: "
                                + String.join("; ", verification.problems));
                    }
                    System.out.println("Written record signature: valid (signer "
                            + verification.certificate.subject + ", trust="
                            + verification.certificate.trusted + ")");
                    System.out.println("Appended " + appendSpec.type + " record ("
                            + appendSpec.record.length + " B) to "
                            + String.format("%04X", appendSpec.fid));
                }
                if (record == null) {
                    return CliSupport.EXIT_OK;
                }
            }

            Map<String, List<byte[]>> groups = readGroups(terminal, app, record);
            Map<String, List<Lds2Verifier.Verification>> verification =
                    Lds2Verifier.verifyGroups(terminal, groups, app, trust);
            System.out.print(json ? PassportReport.lds2Json(cardAccess, groups, verification)
                    : PassportReport.lds2Text(cardAccess, groups, verification));
            return CliSupport.EXIT_OK;
        }
    }

    /**
     * Validates the option combination before the transport is opened, so a
     * usage error does not require a card and the CLI tests can cover it.
     */
    private static String validate(Args parsed, String app, String record, String doc,
                                   String dob, String doe, String can, String taChain,
                                   String taKey, Lds2AppendSpec appendSpec) {
        boolean biometrics = "biometrics".equals(app);
        if (appendSpec != null) {
            if (!appendTypeMatches(app, appendSpec.type)) {
                return "lds2 -app=" + app + " cannot append a " + appendSpec.type + " record";
            }
            if ("certificate".equals(appendSpec.type) && parsed.get("csca", null) == null) {
                return "certificate append needs -csca=<CSCA certificate>";
            }
        }
        if (biometrics) {
            if (record != null) {
                return "lds2 -app=biometrics has no record EF (-record is only for travel/visa)";
            }
        } else if (record != null && appendSpec == null && !validRecord(app, record)) {
            return "lds2 -app=" + app + " needs -record=entry|exit|visa|cert|all";
        } else if (record != null && appendSpec != null && !validRecord(app, record)) {
            return "lds2 -app=" + app + " needs -record=entry|exit|visa|cert|all";
        }
        if (!parsed.has("pace") && can == null) {
            return "lds2 needs PACE: use -pace with -doc/-dob/-doe, or -can=<CAN>";
        }
        if (!parsed.has("ca") && parsed.has("ta")) {
            return "lds2 -ta needs -ca (Terminal Authentication is bound to Chip Authentication)";
        }
        if (parsed.has("ta") && (taChain == null || taKey == null)) {
            return "lds2 -ta needs -ta-chain=<file> and -ta-key=<hex>";
        }
        if (can == null && parsed.has("pace")
                && (doc == null || dob == null || doe == null)) {
            return "lds2 -pace needs -doc, -dob and -doe";
        }
        return null;
    }

    private static boolean appendTypeMatches(String app, String type) {
        if ("travel".equals(app)) {
            return "entry".equals(type) || "exit".equals(type) || "certificate".equals(type);
        }
        if ("visa".equals(app)) {
            return "visa".equals(type) || "certificate".equals(type);
        }
        return "biometrics".equals(app)
                && ("biometrics".equals(type) || "certificate".equals(type));
    }

    private static int parseCertRef(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("-cert-ref must be a number: " + value);
        }
    }

    private static boolean validRecord(String app, String record) {
        if (record == null) {
            return false;
        }
        if ("travel".equals(app)) {
            return "entry".equals(record) || "exit".equals(record)
                    || "cert".equals(record) || "all".equals(record);
        }
        if ("visa".equals(app)) {
            return "visa".equals(record) || "cert".equals(record) || "all".equals(record);
        }
        return false;
    }

    private static String defaultRecord(String app) {
        if ("travel".equals(app)) {
            return "entry";
        }
        if ("visa".equals(app)) {
            return "visa";
        }
        return null;
    }

    private static Map<String, List<byte[]>> readGroups(EmrtdTerminal terminal, String app,
                                                        String record) throws Exception {
        Map<String, List<byte[]>> groups = new LinkedHashMap<>();
        if ("biometrics".equals(app)) {
            // EF.Biometrics is a transparent EF (Doc 9303-10 §5.3.3), not a
            // record EF: report its bytes as a single entry.
            groups.put("EF.Biometrics1 (0201)", java.util.Collections.singletonList(
                    LdsReader.read(terminal, LdsFileUtil.FID_BIOMETRICS)));
            return groups;
        }
        if ("travel".equals(app)) {
            if ("entry".equals(record) || "all".equals(record)) {
                addRecords(groups, "EF.EntryRecords (0101)", terminal, LdsFileUtil.FID_RECORDS);
            }
            if ("exit".equals(record) || "all".equals(record)) {
                addRecords(groups, "EF.ExitRecords (0102)", terminal,
                        LdsFileUtil.FID_EXIT_RECORDS);
            }
        } else if ("visa".equals(app) && ("visa".equals(record) || "all".equals(record))) {
            addRecords(groups, "EF.VisaRecords (0103)", terminal, LdsFileUtil.FID_VISA_RECORDS);
        }
        if ("cert".equals(record) || "all".equals(record)) {
            addRecords(groups, "EF.Certificates (011A)", terminal,
                    LdsFileUtil.FID_CERTIFICATES);
        }
        return groups;
    }

    private static void addRecords(Map<String, List<byte[]>> groups, String label,
                                   EmrtdTerminal terminal, int fid) throws Exception {
        groups.put(label, LdsReader.readAllRecords(terminal, LdsFileUtil.sfi(fid), 1));
    }

    private static String labelForFid(int fid) {
        switch (fid) {
        case LdsFileUtil.FID_RECORDS:
            return "EF.EntryRecords (0101)";
        case LdsFileUtil.FID_EXIT_RECORDS:
            return "EF.ExitRecords (0102)";
        case LdsFileUtil.FID_VISA_RECORDS:
            return "EF.VisaRecords (0103)";
        case LdsFileUtil.FID_CERTIFICATES:
            return "EF.Certificates (011A)";
        case LdsFileUtil.FID_BIOMETRICS:
            return "EF.Biometrics1 (0201)";
        default:
            return String.format("EF.%04X", fid);
        }
    }

    private static String sw(int sw) {
        return String.format("%04X", sw & 0xFFFF);
    }
}
