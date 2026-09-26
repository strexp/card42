package card42.host.emv.cli.command;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.Json;
import card42.host.common.codec.Responses;
import card42.host.emv.lib.TagPolicy;
import card42.host.common.codec.Tags;
import card42.host.common.codec.TlvDump;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.data.TerminalDol;
import card42.host.emv.kernel.data.Tsi;
import card42.host.emv.kernel.data.Tvr;
import card42.host.emv.kernel.entry.ApplicationSelection;
import card42.host.emv.report.TransactionReport;
import card42.host.emv.kernel.entry.EntryPoint;
import card42.host.emv.kernel.oda.OfflineDataAuthentication;
import card42.host.emv.oda.CaKeyProfile;
import card42.host.common.transport.TerminalSession;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;
import card42.host.common.util.Reporter;

/**
 * {@code terminal inspect}: read-only reconnaissance of a card
 * (docs/specs/common/toolchain.md §7.1).
 *
 * <p>It selects the PSE/PPSE directory ({@code -dir}), the application FCI
 * ({@code -fci}), reads the AFL records with a TLV dump ({@code -records}) and
 * decodes the AIP, optionally running ODA ({@code -oda}).  It is the natural
 * pre-flight for {@code terminal pay}.
 */
public final class TerminalInspectCommand {

    private static final String PSE = "315041592E5359532E4444463031";
    private static final String PPSE = "325041592E5359532E4444463031";
    private static final String CONTACT_AID = "43415244420101";
    private static final String CONTACTLESS_AID = "43415244420102";

    private static final String[] VALUE_OPTIONS = {
        "iface", "host", "wait", "aid", "ca-keys",
    };
    private static final String[] FLAG_OPTIONS = {
        "dir", "fci", "records", "oda", "json", "trace",
    };

    private TerminalInspectCommand() {
    }

    /** Runs the command and returns its exit code. */
    public static int run(String[] argv) throws Exception {
        Args args = new Args(argv, VALUE_OPTIONS, FLAG_OPTIONS);
        if (args.help()) {
            usage(System.out);
            return 0;
        }
        String iface = args.get("iface", "contact");
        boolean contact = iface.equals("contact");
        if (!contact && !iface.equals("contactless")) {
            throw new IllegalArgumentException("-iface must be contact or contactless");
        }
        String host = args.get("host", "pcsc:0");
        int wait = Integer.parseInt(args.get("wait", "10"));
        boolean json = args.has("json");
        boolean any = args.has("dir") || args.has("fci") || args.has("records")
                || args.has("oda");
        String[] aids = args.has("aid")
                ? args.get("aid", "").split(",")
                : new String[] { contact ? CONTACT_AID : CONTACTLESS_AID };

        StringBuilder text = new StringBuilder();
        List<String> jsonParts = new ArrayList<>();

        try (TerminalSession session = TerminalSession.open(
                host, wait, args.has("trace"), System.err)) {
            card42.host.emv.lib.Terminal terminal = new card42.host.emv.lib.Terminal(session.terminal);

            // --- Directory ---------------------------------------------------
            byte[] directoryFci = null;
            if (contact) {
                ResponseAPDU pse = terminal.select(PSE);
                if (pse.getSW() == 0x9000) {
                    directoryFci = pse.getData();
                }
            } else {
                ResponseAPDU ppse = terminal.select(PPSE);
                if (ppse.getSW() == 0x9000) {
                    directoryFci = ppse.getData();
                }
            }
            List<DirEntry> entries = directoryEntries(terminal, contact, directoryFci, aids);
            if (!any || args.has("dir")) {
                text.append("Directory (").append(contact ? "PSE" : "PPSE").append(")\n");
                for (DirEntry entry : entries) {
                    text.append(String.format("  %-20s label=%-12s priority=%-2s kernel=%s%n",
                            entry.aid, entry.label, entry.priority, entry.kernel));
                }
                if (entries.isEmpty()) {
                    text.append("  (none)\n");
                }
                jsonParts.add("\"directory\":" + directoryJson(entries));
            }

            // --- Select the application -------------------------------------
            String aid = selectApplication(terminal, contact, entries, aids);
            ResponseAPDU selected = terminal.select(aid);
            if (selected.getSW() != 0x9000) {
                throw new IllegalStateException("SELECT " + aid + " -> "
                        + String.format("%04X", selected.getSW()));
            }
            byte[] fci = selected.getData();
            if (!any || args.has("fci")) {
                text.append("FCI ").append(aid).append(" (").append(label(fci)).append(")\n");
                text.append(indent(TlvDump.format(fci)));
                jsonParts.add("\"fci\":{\"aid\":" + Json.quote(aid)
                        + ",\"tlv\":" + Json.quote(TlvDump.format(fci)) + "}");
            }

            // --- GPO / records / ODA ----------------------------------------
            if (args.has("records") || args.has("oda")) {
                TerminalConfig config = contact
                        ? TerminalConfig.forContact().build() : TerminalConfig.builder().build();
                TransactionRequest data = new TransactionRequest(config);
                TransactionResult.Mutable result = new TransactionResult.Mutable();
                // ODA writes the TVR/TSI through the result; the kernel
                // initializes them in TransactionFlow.beginTransaction.
                result.tvr(Tvr.blank()).tsi(Tsi.blank());
                data.applicationIdentifier = Hex.parse(aid);
                byte[] pdol = TagPolicy.findIcc(fci, 0x9F38);
                byte[] pdolData = TerminalDol.buildDolData(data, result,
                        pdol == null ? new byte[0] : pdol);
                ResponseAPDU gpo = terminal.gpo(pdolData);
                if (gpo.getSW() != 0x9000) {
                    throw new IllegalStateException("GPO -> "
                            + String.format("%04X", gpo.getSW()));
                }
                byte[] aipBytes = Responses.gpoAip(gpo.getData());
                int aip = ((aipBytes[0] & 0xFF) << 8) | (aipBytes[1] & 0xFF);
                byte[] afl = Responses.gpoAfl(gpo.getData());

                if (args.has("records")) {
                    text.append("Records (AIP=").append(String.format("%04X", aip))
                            .append(" AFL=").append(Hex.format(afl)).append(")\n");
                    for (Record record : readAfl(terminal, afl)) {
                        text.append(String.format("  SFI %d record %d%n",
                                record.sfi, record.record));
                        text.append(indent(TlvDump.format(record.data)));
                    }
                }
                if (args.has("oda")) {
                    List<String> names = TransactionReport.aipNames(aip);
                    text.append("AIP ").append(String.format("%04X", aip)).append(" (")
                            .append(names.isEmpty() ? "none" : String.join(", ", names))
                            .append(")\n");
                    if (args.has("ca-keys")) {
                        result.aidHex(aid);
                        result.fci(fci);
                        result.aip(aip);
                        result.afl(afl);
                        OfflineDataAuthentication oda = new OfflineDataAuthentication(
                                Reporter.to(System.err), CaKeyProfile.load(args.get("ca-keys", "")));
                        oda.verify(terminal, data, result);
                        text.append("ODA SDA ").append(outcome(result.sdaPerformed(), result.sdaFailed()))
                                .append(", DDA ").append(outcome(result.ddaPerformed(), result.ddaFailed()))
                                .append(", CDA ").append(outcome(result.cdaPerformed(), result.cdaFailed()))
                                .append('\n');
                        jsonParts.add("\"oda\":{\"sdaPerformed\":" + result.sdaPerformed()
                                + ",\"sdaFailed\":" + result.sdaFailed()
                                + ",\"ddaPerformed\":" + result.ddaPerformed()
                                + ",\"ddaFailed\":" + result.ddaFailed()
                                + ",\"cdaPerformed\":" + result.cdaPerformed()
                                + ",\"cdaFailed\":" + result.cdaFailed() + "}");
                    } else {
                        text.append("ODA not run: no -ca-keys\n");
                    }
                }
            }
        }

        if (json) {
            System.out.println("{" + String.join(",", jsonParts) + "}");
        } else {
            System.out.print(text);
        }
        return 0;
    }

    // --- Directory -----------------------------------------------------------

    /** One directory entry (ADF Name, label, priority, requested kernel). */
    private static final class DirEntry {
        String aid = "";
        String label = "";
        int priority;
        int kernel;
    }

    private static List<DirEntry> directoryEntries(card42.host.emv.lib.Terminal terminal,
            boolean contact, byte[] directoryFci, String[] aids) throws Exception {
        List<DirEntry> entries = new ArrayList<>();
        if (contact) {
            if (directoryFci == null || !ApplicationSelection.isPseFci(directoryFci)) {
                return entries;
            }
            for (byte[] record : readPseDirectory(terminal)) {
                byte[] t70 = Tags.find(record, 0x70);
                if (t70 == null) {
                    continue;
                }
                for (byte[] entry : Tags.findAllDirect(t70, 0x61)) {
                    DirEntry dir = decodeEntry(entry, false);
                    if (!dir.aid.isEmpty()) {
                        entries.add(dir);
                    }
                }
            }
        } else {
            if (directoryFci == null) {
                return entries;
            }
            byte[] discretionary = Tags.find(directoryFci, 0xBF0C);
            if (discretionary == null) {
                return entries;
            }
            for (byte[] entry : Tags.findAllDirect(discretionary, 0x61)) {
                DirEntry dir = decodeEntry(entry, true);
                if (!dir.aid.isEmpty()) {
                    entries.add(dir);
                }
            }
        }
        return entries;
    }

    private static DirEntry decodeEntry(byte[] entry, boolean contactless) {
        DirEntry dir = new DirEntry();
        byte[] adf = Tags.find(entry, 0x4F);
        if (adf != null) {
            dir.aid = Hex.format(adf);
        }
        byte[] label = Tags.find(entry, 0x50);
        if (label != null) {
            dir.label = new String(label, java.nio.charset.StandardCharsets.US_ASCII).trim();
        }
        byte[] priority = Tags.find(entry, 0x87);
        dir.priority = priority == null ? 15 : (priority[0] & 0x0F);
        if (contactless) {
            dir.kernel = EntryPoint.requestedKernelId(entry, dir.aid);
        }
        return dir;
    }

    private static List<byte[]> readPseDirectory(card42.host.emv.lib.Terminal terminal)
            throws Exception {
        List<byte[]> records = new ArrayList<>();
        for (int record = 1; record <= 30; record++) {
            ResponseAPDU r = terminal.readRecord(record, 1);
            if (r.getSW() == 0x6A83) {
                break; // end of the Payment System Directory (Book 1 §12.3.2)
            }
            if (r.getSW() != 0x9000) {
                break;
            }
            records.add(r.getData());
        }
        return records;
    }

    private static String selectApplication(card42.host.emv.lib.Terminal terminal,
            boolean contact, List<DirEntry> entries, String[] aids) throws Exception {
        if (contact) {
            // The directory entries were decoded from the PSE records.
            for (DirEntry entry : entries) {
                for (String supported : aids) {
                    if (entry.aid.equals(supported) || entry.aid.startsWith(supported)) {
                        return entry.aid;
                    }
                }
            }
            return aids[0];
        }
        for (DirEntry entry : entries) {
            for (String supported : aids) {
                if (entry.aid.equals(supported) || entry.aid.startsWith(supported)) {
                    return entry.aid;
                }
            }
        }
        return aids[0];
    }

    // --- Records -------------------------------------------------------------

    private static final class Record {
        int sfi;
        int record;
        byte[] data;
    }

    private static List<Record> readAfl(card42.host.emv.lib.Terminal terminal, byte[] afl)
            throws Exception {
        List<Record> records = new ArrayList<>();
        for (int e = 0; e + 3 < afl.length; e += 4) {
            int sfi = (afl[e] & 0xFF) >> 3;
            int first = afl[e + 1] & 0xFF;
            int last = afl[e + 2] & 0xFF;
            for (int record = first; record <= last; record++) {
                ResponseAPDU r = terminal.readRecord(record, sfi);
                if (r.getSW() != 0x9000) {
                    throw new IllegalStateException("READ RECORD SFI " + sfi + " rec "
                            + record + " -> " + String.format("%04X", r.getSW()));
                }
                Record out = new Record();
                out.sfi = sfi;
                out.record = record;
                out.data = r.getData();
                records.add(out);
            }
        }
        return records;
    }

    // --- Rendering helpers ---------------------------------------------------

    private static String directoryJson(List<DirEntry> entries) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < entries.size(); i++) {
            DirEntry entry = entries.get(i);
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"aid\":").append(Json.quote(entry.aid))
                    .append(",\"label\":").append(Json.quote(entry.label))
                    .append(",\"priority\":").append(entry.priority)
                    .append(",\"kernel\":").append(entry.kernel).append('}');
        }
        return sb.append(']').toString();
    }

    private static String label(byte[] fci) {
        byte[] label = Tags.find(fci, 0x50);
        return label == null ? "" : new String(label,
                java.nio.charset.StandardCharsets.US_ASCII).trim();
    }

    private static String outcome(boolean performed, boolean failed) {
        if (failed) {
            return "failed";
        }
        return performed ? "ok" : "not performed";
    }

    private static String indent(String text) {
        StringBuilder sb = new StringBuilder();
        for (String line : text.split("\n")) {
            sb.append("  ").append(line).append('\n');
        }
        return sb.toString();
    }

    public static void usage(PrintStream out) {
        out.println("usage: Main terminal inspect [options]");
        out.println("  -iface=contact|contactless -host=pcsc[:i]|socket:h:p -wait=<s>");
        out.println("  -aid=<hex>[,<hex>]   supported applications (default the kernel AID)");
        out.println("  -dir                 dump the PSE/PPSE directory");
        out.println("  -fci                 dump the selected application FCI");
        out.println("  -records             read the AFL records and TLV-dump them");
        out.println("  -oda                 decode the AIP, and run ODA with -ca-keys=<path>");
        out.println("  -json                structured output");
    }
}
