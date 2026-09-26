package card42.host.emv.cli.command;

import java.io.PrintStream;

import card42.host.common.codec.Json;
import card42.host.emv.kernel.core.EndApplicationException;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.entry.CombinationTable;
import card42.host.emv.kernel.entry.EntryPointConfiguration;
import card42.host.emv.kernel.entry.KernelActivation;
import card42.host.emv.kernel.entry.PpseSelection;
import card42.host.emv.kernel.entry.PreProcessingIndicators;
import card42.host.common.transport.TerminalSession;
import card42.host.emv.lib.Amounts;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;

/**
 * {@code terminal entrypoint}: the Entry Point diagnostic
 * (EMV Contactless Book A v2.12 §5.8 / Book B v2.12 §3.4).
 *
 * <p>It runs Start A (SELECT PPSE, optional SEND POI INFORMATION, Pre-Processing
 * Indicators), the Final Combination Selection against the reader Combination
 * Table, and prints the {@link KernelActivation} payload; it does not enter the
 * card transaction beyond application selection.  It is the user-visible face of
 * the H1–H3 Entry Point state machine.
 */
public final class TerminalEntryPointCommand {

    private static final String CONTACTLESS_AID = "43415244420102";

    private static final String[] VALUE_OPTIONS = {
        "iface", "host", "wait", "aid", "type", "amount", "decimals",
        "currency", "country", "category",
    };
    private static final String[] FLAG_OPTIONS = { "spi", "json", "trace" };

    private TerminalEntryPointCommand() {
    }

    /** Runs the command and returns its exit code. */
    public static int run(String[] argv) throws Exception {
        Args args = new Args(argv, VALUE_OPTIONS, FLAG_OPTIONS);
        if (args.help()) {
            usage(System.out);
            return 0;
        }
        String iface = args.get("iface", "contactless");
        if (!iface.equals("contactless")) {
            throw new IllegalArgumentException("-iface must be contactless for entrypoint");
        }
        String host = args.get("host", "pcsc:0");
        int wait = Integer.parseInt(args.get("wait", "10"));
        int decimals = Integer.parseInt(args.get("decimals", "2"));
        long amount = Amounts.amount(args.get("amount", "0"), decimals);
        int transactionType = transactionType(args.get("type", "purchase"));
        String[] aids = args.has("aid")
                ? args.get("aid", "").split(",")
                : new String[] { CONTACTLESS_AID };

        // The POI Information ID '0001' Terminal Category is terminal-resident
        // (EMV Contactless Book B v2.12 Table A-2); set it on the terminal data
        // model so SEND POI INFORMATION and SDOL tag '8B' use the same value.
        byte[] terminalCategory = args.has("category")
                ? Hex.parse(args.get("category", "")) : null;
        TerminalConfig.Builder configBuilder = TerminalConfig.builder();
        if (args.has("country")) {
            configBuilder.terminalCountryCode(Hex.parse(args.get("country", "")));
        }
        if (terminalCategory != null) {
            configBuilder.terminalCategory(terminalCategory);
        }
        TerminalConfig terminalConfig = configBuilder.build();
        TransactionRequest data = new TransactionRequest(terminalConfig);
        data.amountAuthorised = Amounts.numeric(Long.toString(amount), 6);
        data.transactionType = transactionType;
        if (args.has("currency")) {
            data.transactionCurrencyCode = Hex.parse(args.get("currency", ""));
        }

        EntryPointConfiguration config = EntryPointConfiguration.from(terminalConfig);
        config.forceSpi = args.has("spi");
        if (terminalCategory != null) {
            config.terminalCategory = terminalCategory;
        }
        CombinationTable table = CombinationTable.defaults(aids);

        try (TerminalSession session = TerminalSession.open(
                host, wait, args.has("trace"), System.err)) {
            PpseSelection selection = new PpseSelection(table, config);
            TransactionResult.Mutable result = new TransactionResult.Mutable();
            try {
                KernelActivation activation = selection.activate(new card42.host.emv.lib.Terminal(session.terminal), data, result);
                if (args.has("json")) {
                    System.out.println(json(activation));
                } else {
                    System.out.print(text(activation));
                }
                return 0;
            } catch (EndApplicationException e) {
                if (args.has("json")) {
                    System.out.println("{\"endApplication\":true,\"uiRequest\":"
                            + e.messageIdentifier() + "}");
                } else {
                    System.out.println("End Application (UI request "
                            + String.format("%02X", e.messageIdentifier()) + "): "
                            + e.getMessage());
                }
                return 1;
            }
        }
    }

    /** Book A Table 5-6 transaction type names. */
    private static int transactionType(String name) {
        switch (name) {
        case "purchase":
            return CombinationTable.PURCHASE;
        case "cashback":
            return CombinationTable.CASHBACK;
        case "cash":
            return CombinationTable.CASH;
        case "refund":
            return CombinationTable.REFUND;
        default:
            throw new IllegalArgumentException(
                    "-type must be purchase, cashback, cash or refund");
        }
    }

    private static String text(KernelActivation activation) {
        PreProcessingIndicators p = activation.indicators;
        StringBuilder sb = new StringBuilder();
        sb.append("Kernel Activation\n");
        sb.append("  ADF Name : ").append(activation.adfName).append('\n');
        sb.append("  AID      : ").append(activation.aid).append('\n');
        sb.append("  Kernel ID: ").append(activation.kernelId).append('\n');
        sb.append("  Indicators: statusCheck=").append(p.statusCheckRequested)
                .append(" appNotAllowed=").append(p.contactlessApplicationNotAllowed)
                .append(" zeroAmount=").append(p.zeroAmount)
                .append(" cvmLimitExceeded=").append(p.readerCvmRequiredLimitExceeded)
                .append(" floorLimitExceeded=").append(p.readerContactlessFloorLimitExceeded)
                .append('\n');
        sb.append("  TTQ      : ").append(Hex.format(p.ttq)).append('\n');
        return sb.toString();
    }

    private static String json(KernelActivation activation) {
        PreProcessingIndicators p = activation.indicators;
        return "{\"adfName\":" + Json.quote(activation.adfName)
                + ",\"aid\":" + Json.quote(activation.aid)
                + ",\"kernelId\":" + activation.kernelId
                + ",\"indicators\":{"
                + "\"statusCheck\":" + p.statusCheckRequested
                + ",\"appNotAllowed\":" + p.contactlessApplicationNotAllowed
                + ",\"zeroAmount\":" + p.zeroAmount
                + ",\"cvmLimitExceeded\":" + p.readerCvmRequiredLimitExceeded
                + ",\"floorLimitExceeded\":" + p.readerContactlessFloorLimitExceeded + "}"
                + ",\"ttq\":" + Json.quote(Hex.format(p.ttq)) + "}";
    }

    public static void usage(PrintStream out) {
        out.println("usage: Main terminal entrypoint [options]");
        out.println("  -iface=contactless -host=pcsc[:i]|socket:h:p -wait=<s>");
        out.println("  -type=purchase|cashback|cash|refund   transaction type (default purchase)");
        out.println("  -amount=<major> -decimals=<n>         amount (default 0)");
        out.println("  -currency=<hex> -country=<hex>        transaction currency / terminal country");
        out.println("  -aid=<hex>[,<hex>]                    supported AIDs (default the kernel AID)");
        out.println("  -category=<hex>                       POI Terminal Category (default 0001)");
        out.println("  -spi                                  force SEND POI INFORMATION");
        out.println("  -json                                 structured output");
    }
}
