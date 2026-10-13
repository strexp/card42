package card42.host.emrtd.cli.command;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.cli.Args;
import card42.host.common.cli.CliSupport;
import card42.host.common.transport.TerminalSession;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.lds.CardAccess;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.report.PassportReport;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * {@code terminal emrtd lds2}: SELECT an LDS2 application, read EF.CardAccess
 * and every record of its record EF, and print the SecurityInfos and records
 * (ICAO Doc 9303-10 §3.11 / §5).
 */
final class EmrtdLds2Command {

    private EmrtdLds2Command() {
    }

    static int run(String[] args) throws Exception {
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
                return CliSupport.fail("SELECT " + aid + " -> " + sw(selected.getSW()));
            }
            byte[] cardAccessBytes;
            try {
                cardAccessBytes = LdsReader.read(terminal, LdsFileUtil.FID_CARD_ACCESS);
            } catch (RuntimeException e) {
                cardAccessBytes = null;
            }
            CardAccess cardAccess = cardAccessBytes == null
                    ? null : CardAccess.parse(cardAccessBytes);
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

    private static String sw(int sw) {
        return String.format("%04X", sw & 0xFFFF);
    }
}
