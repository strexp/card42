package card42.host.emv.cli.command;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.kernel.ContactKernel;
import card42.host.emv.kernel.ContactlessKernel;
import card42.host.emv.kernel.core.Authorization;
import card42.host.emv.kernel.core.ConfirmationProvider;
import card42.host.emv.kernel.core.Issuer;
import card42.host.emv.kernel.core.OnlinePinProvider;
import card42.host.emv.kernel.core.PinProvider;
import card42.host.emv.kernel.core.SignatureProvider;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.common.util.Bcd;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.entry.CombinationTable;
import card42.host.emv.kernel.entry.EntryPointConfiguration;
import card42.host.emv.app.issuer.AuthFileIssuer;
import card42.host.emv.app.issuer.ClosedLoopIssuer;
import card42.host.emv.app.issuer.SubprocessIssuer;
import card42.host.emv.report.Receipt;
import card42.host.emv.report.ReceiptPrinter;
import card42.host.emv.report.ReceiptRenderer;
import card42.host.emv.report.TransactionReport;
import card42.host.emv.oda.CaKeyProfile;
import card42.host.emv.oda.CaKeyStore;
import card42.host.emv.lib.Terminal;
import card42.host.common.transport.TerminalSession;
import card42.host.emv.lib.Amounts;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;
import card42.host.common.util.KeyValueFile;
import card42.host.common.util.Reporter;

/**
 * {@code terminal pay}: runs one or more complete transactions with the contact
 * or contactless kernel (docs/specs/common/toolchain.md §7.1, docs/specs/emv/contact-kernel.md,
 * docs/specs/emv/contactless.md).
 *
 * <p>The command maps its options onto a {@link TerminalConfig} (terminal-resident)
 * and a {@link TransactionRequest} (per transaction), builds the offline
 * PIN provider and the online {@link Issuer} (closed loop, external host
 * process, static file or a plain approve/decline policy) and prints a
 * {@link TransactionReport}.  Exit codes: 0 approved (TC), 1 declined (AAC),
 * 2 usage or connection error.
 */
public final class TerminalPayCommand {

    private static final String CONTACT_AID = "43415244420101";
    private static final String CONTACTLESS_AID = "43415244420102";

    private static final String[] VALUE_OPTIONS = {
        "iface", "host", "wait", "aid", "profile",
        "amount", "decimals", "currency", "other", "type", "date", "time",
        "country", "un", "seed", "count", "interval",
        "floor", "tac-denial", "tac-online", "tac-default",
        "target", "biased", "max-target", "cvm-limit",
        "ep-transaction-limit", "ep-floor-limit", "ep-9f1b", "ep-cvm-limit",
        "terminal-type", "capabilities", "addl-capabilities", "ttq",
        "app-version", "terminal-id", "ifd", "mcc", "merchant", "acquirer",
        "ca-keys", "icc-key", "csu", "arc", "issuer-cmd", "auth", "online",
        "script", "pin", "pin-file", "referral", "exception",
        "confirm", "receipt",
    };

    private static final String[] FLAG_OPTIONS = {
        "merchant-online", "online-pin", "signature", "no-oda", "csu-reset",
        "ep-status-check", "ep-zero-amount", "ep-zero-offline",
        "ep-extended-selection", "ep-restart-decline",
        "json", "trace", "quiet", "verbose", "no-pin",
    };

    private TerminalPayCommand() {
    }

    /** Runs the command and returns its exit code. */
    public static int run(String[] argv) throws Exception {
        Args args = new Args(argv, VALUE_OPTIONS, FLAG_OPTIONS);
        if (args.help()) {
            usage(System.out);
            return 0;
        }
        Map<String, String> profile = args.has("profile")
                ? KeyValueFile.read(args.get("profile", null))
                : new LinkedHashMap<>();

        String iface = setting(args, profile, "iface", "iface", "contact");
        boolean contact = iface.equals("contact");
        if (!contact && !iface.equals("contactless")) {
            throw new IllegalArgumentException("-iface must be contact or contactless");
        }
        String host = setting(args, profile, "host", "host", "pcsc:0");
        int wait = Integer.parseInt(setting(args, profile, "wait", "wait", "10"));

        String[] aids = parseAids(setting(args, profile, "aid", "aid", null),
                contact ? CONTACT_AID : CONTACTLESS_AID);

        TerminalConfig config = buildConfig(args, profile, contact);
        TransactionRequest request = new TransactionRequest(config);
        applyRequest(request, args, profile, aids);

        Long seed = args.has("seed") ? Long.parseLong(args.get("seed", "0")) : null;
        Random random = seed != null ? new Random(seed) : new Random();
        if (args.has("un")) {
            // A caller-fixed Unpredictable Number overrides the per-activation
            // refresh (EMV Contactless Book A v2.12 §8.1.1.8).
            request.unpredictableNumber = fourBytes(Hex.parse(args.get("un", "")), "un");
            request.unpredictableNumberFixed = true;
        }

        PinProvider pinProvider = pinProvider(args, contact);
        OnlinePinProvider onlinePinProvider = contact ? onlinePinProvider(args, pinProvider) : null;
        SignatureProvider signatureProvider = contact ? signatureProvider(args) : null;
        ConfirmationProvider confirmationProvider = confirmationProvider(args, profile);
        EntryPointConfiguration entryConfig = entryPointConfig(args, profile, config);
        CaKeyStore caStore = caKeyStore(args, profile);
        String online = setting(args, profile, "online", "online", "auto");
        if (!online.equals("auto") && !online.equals("always")
                && !online.equals("never") && !online.equals("decline")) {
            throw new IllegalArgumentException(
                    "-online must be auto, always, never or decline");
        }
        if (online.equals("always")) {
            request.merchantForcedOnline = true;
        }
        Issuer issuer = issuer(args, profile, online);

        int count = Integer.parseInt(setting(args, profile, "count", "count", "1"));
        long interval = Long.parseLong(setting(args, profile, "interval", "interval", "0"));
        boolean json = args.has("json");
        String reportPath = args.get("report", null);
        ReceiptPrinter receiptPrinter = receiptPrinter(args);
        Reporter reporter = args.has("quiet") ? Reporter.noop() : Reporter.to(System.err);

        int exit = 0;
        try (TerminalSession session = TerminalSession.open(
                host, wait, args.has("trace"), System.err)) {
            Terminal terminal = new Terminal(session.terminal);
            for (int i = 0; i < count; i++) {
                long start = System.nanoTime();
                TransactionResult result;
                try {
                    result = contact
                            ? new ContactKernel(reporter, caStore, random, pinProvider,
                                    onlinePinProvider, signatureProvider, confirmationProvider,
                                    aids).run(terminal, request, issuer)
                            : new ContactlessKernel(reporter, caStore, random,
                                    CombinationTable.defaults(aids), entryConfig)
                                    .run(terminal, request, issuer);
                } catch (card42.host.emv.kernel.core.EndApplicationException e) {
                    // Entry Point End Application Outcome (Book B §3.3.2.7):
                    // no supported Combination remains.
                    System.err.println("End Application (UI request "
                            + String.format("%02X", e.messageIdentifier()) + "): "
                            + e.getMessage());
                    exit = 1;
                    continue;
                }
                long elapsed = (System.nanoTime() - start) / 1_000_000;
                String rendered = json
                        ? TransactionReport.json(result, request, iface, host, elapsed)
                        : TransactionReport.text(result, request, iface, host, elapsed);
                write(rendered, reportPath);
                // The receipt is printed when the Outcome requests one
                // (approved transaction) or, for the contact kernel that does
                // not model an Outcome, when the transaction is not declined.
                if (result.outcome() != null ? result.outcome().receipt : !result.declined()) {
                    receiptPrinter.print(Receipt.from(result, request));
                }
                if (result.decision() == TransactionResult.Decision.DECLINE
                        || result.decision() == TransactionResult.Decision.END_APPLICATION) {
                    exit = 1;
                }
                if (i + 1 < count && interval > 0) {
                    Thread.sleep(interval);
                }
            }
        }
        return exit;
    }

    // --- Terminal config and transaction request -----------------------------

    private static TerminalConfig buildConfig(Args args, Map<String, String> profile,
            boolean contact) {
        TerminalConfig.Builder builder = contact
                ? TerminalConfig.forContact() : TerminalConfig.forContactless();

        boolean onlinePinSupported = flag(args, profile, "online-pin", "onlinePin");
        boolean signatureSupported = flag(args, profile, "signature", "signature");
        builder.terminalType(Integer.parseInt(
                setting(args, profile, "terminal-type", "terminal.type",
                        contact ? "22" : "22"), 16));
        byte[] capabilities = bytes(setting(args, profile, "capabilities",
                "terminal.capabilities", null),
                contact ? Hex.parse("E098C8") : Hex.parse("E008C8"));
        // Terminal Capabilities byte 2 must advertise the CVMs the terminal can
        // perform (EMV v4.4 Book 4 §6.3.4 / Annex A2 Table 27): b7 online PIN,
        // b6 signature.  Keep 9F33 in step with the -online-pin / -signature
        // flags the kernel acts on.
        if (capabilities.length >= 2) {
            if (onlinePinSupported) {
                capabilities[1] |= (byte) 0x80;
            }
            if (signatureSupported) {
                capabilities[1] |= (byte) 0x40;
            }
        }
        builder.terminalCapabilities(capabilities);
        builder.additionalTerminalCapabilities(bytes(setting(args, profile,
                "addl-capabilities", "addl.capabilities", null),
                Hex.parse("F000F0A001")));
        builder.ttq(bytes(setting(args, profile, "ttq", "ttq", null), Hex.parse("31008000")));
        builder.applicationVersionNumber(bytes(setting(args, profile, "app-version",
                "app.version", null), Hex.parse("0002")));
        builder.terminalId(bytes(setting(args, profile, "terminal-id",
                "terminal.id", null), Hex.parse("454D5634323030303030303030")));
        builder.ifdSerialNumber(bytes(setting(args, profile, "ifd", "ifd", null),
                Hex.parse("3132333435363738")));
        builder.merchantCategoryCode(bytes(setting(args, profile, "mcc", "mcc", null),
                Hex.parse("5999")));
        String merchant = setting(args, profile, "merchant", "merchant", null);
        builder.merchantName(merchant != null
                ? merchant.getBytes(StandardCharsets.US_ASCII)
                : Hex.parse("454D5634322054455354204D45524348414E54"));
        builder.acquirerIdentifier(bytes(setting(args, profile, "acquirer",
                "acquirer", null), Hex.parse("000000000001")));
        builder.terminalCountryCode(Hex.parse(
                setting(args, profile, "country", "country", "0250")));

        String floor = setting(args, profile, "floor", "floorLimit", "0");
        builder.floorLimit(floor.equals("none") ? Long.MAX_VALUE : Long.parseLong(floor));
        builder.tacDenial(tvr(setting(args, profile, "tac-denial", "tac.denial", null)));
        builder.tacOnline(tvr(setting(args, profile, "tac-online", "tac.online", null)));
        builder.tacDefault(tvr(setting(args, profile, "tac-default", "tac.default", null)));
        builder.targetPercentage(Integer.parseInt(
                setting(args, profile, "target", "target", "0")));
        builder.biasedRandomThreshold(Long.parseLong(
                setting(args, profile, "biased", "biased", "0")));
        builder.maxTargetPercentage(Integer.parseInt(
                setting(args, profile, "max-target", "maxTarget", "0")));
        builder.cvmRequiredLimit(Long.parseLong(
                setting(args, profile, "cvm-limit", "cvm.requiredLimit", "0")));
        builder.onlinePinSupported(onlinePinSupported);
        builder.signatureSupported(signatureSupported);

        // Issuer voice referral policy for attended terminals (Book 4 §6.5.2.2).
        String referral = setting(args, profile, "referral", "referral", null);
        if (referral != null) {
            boolean accept = referral.equals("accept");
            if (!accept && !referral.equals("decline")) {
                throw new IllegalArgumentException("-referral must be accept or decline");
            }
            builder.referralHandler(arc -> accept);
        }

        // Terminal exception file (Book 4 §6.3.5): PAN[:PAN sequence] entries.
        String exception = setting(args, profile, "exception", "exception", null);
        if (exception != null) {
            for (String entry : exception.split(",")) {
                String[] parts = entry.trim().split(":", -1);
                if (parts.length == 0 || parts[0].isEmpty()) {
                    throw new IllegalArgumentException("-exception has an empty PAN");
                }
                byte[] pan = Hex.parse(parts[0]);
                byte[] seq = parts.length > 1 && !parts[1].isEmpty()
                        ? Hex.parse(parts[1]) : null;
                builder.addException(pan, seq);
            }
        }
        return builder.build();
    }

    private static void applyRequest(TransactionRequest request, Args args,
            Map<String, String> profile, String[] aids) {
        int decimals = Integer.parseInt(setting(args, profile, "decimals", "decimals", "2"));
        request.amountAuthorised = Bcd.longToBcd(
                Amounts.amount(setting(args, profile, "amount", "amount", "0.00"), decimals), 6);
        request.amountOther = Bcd.longToBcd(
                Amounts.amount(setting(args, profile, "other", "other", "0.00"), decimals), 6);
        request.transactionCurrencyCode = Amounts.numeric(
                setting(args, profile, "currency", "currency", "978"), 2);
        request.transactionType = transactionType(
                setting(args, profile, "type", "type", "purchase"));

        String date = setting(args, profile, "date", "date", null);
        String time = setting(args, profile, "time", "time", null);
        LocalDate now = LocalDate.now();
        LocalTime clock = LocalTime.now();
        request.transactionDate = Amounts.numeric(date != null ? date
                : String.format("%02d%02d%02d", now.getYear() % 100,
                        now.getMonthValue(), now.getDayOfMonth()), 3);
        request.transactionTime = Amounts.numeric(time != null ? time
                : String.format("%02d%02d%02d", clock.getHour(),
                        clock.getMinute(), clock.getSecond()), 3);

        if (args.has("merchant-online")) {
            request.merchantForcedOnline = true;
        }
        if (aids.length > 0) {
            request.applicationIdentifier = Hex.parse(aids[0]);
        }
    }

    // --- Issuer --------------------------------------------------------------

    private static Issuer issuer(Args args, Map<String, String> profile, String online) {
        if (online.equals("never")) {
            return (arqc, atc, result) -> null;
        }
        if (online.equals("decline")) {
            return (arqc, atc, result) -> new Authorization(Hex.parse("3035"), null);
        }
        int sources = (setting(args, profile, "icc-key", "icc.key", null) != null ? 1 : 0)
                + (args.has("issuer-cmd") ? 1 : 0)
                + (args.has("auth") ? 1 : 0);
        if (sources > 1) {
            throw new IllegalArgumentException(
                    "-icc-key, -issuer-cmd and -auth are mutually exclusive");
        }
        String iccKey = setting(args, profile, "icc-key", "icc.key", null);
        if (iccKey != null) {
            String csuHex = args.has("csu-reset")
                    ? "00820000"
                    : setting(args, profile, "csu", "csu", "00800000");
            byte[] csu = fourBytes(Hex.parse(csuHex), "csu");
            byte[] arc = twoBytes(
                    Hex.parse(setting(args, profile, "arc", "arc", "3030")), "arc");
            List<String> scriptHex = new ArrayList<>(args.all("script"));
            for (int i = 1; profile.containsKey("script." + i); i++) {
                scriptHex.add(profile.get("script." + i));
            }
            byte[][] scripts = new byte[scriptHex.size()][];
            for (int i = 0; i < scriptHex.size(); i++) {
                scripts[i] = Hex.parse(scriptHex.get(i));
            }
            return new ClosedLoopIssuer(Hex.parse(iccKey), csu, arc, scripts);
        }
        if (args.has("issuer-cmd")) {
            return new SubprocessIssuer(args.get("issuer-cmd", ""));
        }
        if (args.has("auth")) {
            return new AuthFileIssuer(args.get("auth", ""));
        }
        // No online host configured: the kernel sees "unable to go online" and
        // takes the Default path.
        return (arqc, atc, result) -> null;
    }

    // --- PIN -----------------------------------------------------------------

    private static PinProvider pinProvider(Args args, boolean contact) throws Exception {
        if (!contact) {
            return null; // the contactless kernel performs no offline CVM
        }
        if (args.has("no-pin")) {
            return () -> null;
        }
        if (args.has("pin")) {
            String pin = args.get("pin", "");
            if (pin.equals("-")) {
                return () -> readPinLine();
            }
            return () -> pin;
        }
        if (args.has("pin-file")) {
            String pin = Files.readAllLines(Path.of(args.get("pin-file", "")))
                    .stream().findFirst().orElse("");
            return () -> pin;
        }
        Console console = System.console();
        if (console == null) {
            return () -> null; // no terminal to prompt on: the CVM fails
        }
        return () -> {
            char[] pin = console.readPassword("PIN: ");
            return pin == null ? null : new String(pin);
        };
    }

    /**
     * The online PIN host callback (EMV v4.4 Book 4 §6.3.4.4): created only when
     * {@code -online-pin} and a 16-byte 3DES {@code -pin-key} are given, since
     * PIN key management is outside this project.  Without it the kernel keeps
     * the 'Online PIN entered, result unknown' path.
     */
    private static OnlinePinProvider onlinePinProvider(Args args, PinProvider pins) {
        if (!args.has("online-pin") || !args.has("pin-key")) {
            return null;
        }
        byte[] key = Hex.parse(args.get("pin-key", ""));
        if (key.length != 16) {
            throw new IllegalArgumentException("-pin-key must be 16 bytes (32 hex digits)");
        }
        return new OnlinePinProvider() {
            @Override
            public String pin() {
                return pins == null ? null : pins.pin();
            }

            @Override
            public byte[] encryptPinBlock(byte[] pinBlock) {
                try {
                    return AcCrypto.des3Ecb(key, pinBlock);
                } catch (java.security.GeneralSecurityException e) {
                    return null;
                }
            }
        };
    }

    /** The signature host callback: an accepted (empty) capture when {@code -signature}. */
    private static SignatureProvider signatureProvider(Args args) {
        if (!args.has("signature")) {
            return null;
        }
        return () -> new byte[0];
    }

    /**
     * The cardholder confirmation callback (EMV v4.4 Book 1 §12.4 step 5):
     * {@code -confirm=always|never}, or null (the terminal does not provide
     * cardholder confirmation) when the option is absent.
     */
    private static ConfirmationProvider confirmationProvider(Args args,
            Map<String, String> profile) {
        String confirm = setting(args, profile, "confirm", "confirm", null);
        if (confirm == null) {
            return null;
        }
        if (confirm.equals("always")) {
            return (adfName, label) -> true;
        }
        if (confirm.equals("never")) {
            return (adfName, label) -> false;
        }
        throw new IllegalArgumentException("-confirm must be always or never");
    }

    /**
     * The receipt printer of the reference CLI: writes the text receipt to the
     * {@code -receipt} path, or a no-op when the option is absent.  The actual
     * presentation is out of scope of this project (docs/specs/emv/contact-kernel.md).
     */
    private static ReceiptPrinter receiptPrinter(Args args) {
        if (!args.has("receipt")) {
            return ReceiptPrinter.NONE;
        }
        String path = args.get("receipt", "");
        return receipt -> {
            try {
                Files.writeString(Path.of(path), ReceiptRenderer.text().render(receipt));
            } catch (Exception e) {
                System.err.println("terminal pay: receipt write failed: " + e.getMessage());
            }
        };
    }

    /**
     * The Entry Point configuration (EMV Contactless Book A v2.12 Table 5-2): derived from the
     * terminal configuration, overridden by the {@code -ep-*} options / profile
     * keys.
     */
    private static EntryPointConfiguration entryPointConfig(Args args,
            Map<String, String> profile, TerminalConfig config) {
        EntryPointConfiguration ep = EntryPointConfiguration.from(config);
        ep.statusCheckSupport = flag(args, profile, "ep-status-check", "ep.statusCheck");
        ep.extendedSelectionSupported = flag(args, profile,
                "ep-extended-selection", "ep.extendedSelection");
        ep.restartOnDecline = flag(args, profile, "ep-restart-decline", "ep.restartOnDecline");
        if (args.has("ep-zero-amount")) {
            ep.zeroAmountAllowed = true;
        } else if (profile.containsKey("ep.zeroAmount")) {
            ep.zeroAmountAllowed = Boolean.parseBoolean(profile.get("ep.zeroAmount"));
        }
        if (args.has("ep-zero-offline")) {
            ep.zeroAmountOfflineAllowed = true;
        } else if (profile.containsKey("ep.zeroOffline")) {
            ep.zeroAmountOfflineAllowed = Boolean.parseBoolean(profile.get("ep.zeroOffline"));
        }
        ep.readerContactlessTransactionLimitPresent = args.has("ep-transaction-limit")
                || profile.containsKey("ep.transactionLimit");
        ep.readerContactlessTransactionLimit = epLong(args, profile,
                "ep-transaction-limit", "ep.transactionLimit",
                ep.readerContactlessTransactionLimit);
        ep.readerContactlessFloorLimitPresent = args.has("ep-floor-limit")
                || profile.containsKey("ep.floorLimit");
        ep.readerContactlessFloorLimit = epLong(args, profile,
                "ep-floor-limit", "ep.floorLimit", ep.readerContactlessFloorLimit);
        ep.terminalFloorLimitPresent = ep.terminalFloorLimitPresent
                || args.has("ep-9f1b") || profile.containsKey("ep.9f1b");
        ep.terminalFloorLimit = epLong(args, profile,
                "ep-9f1b", "ep.9f1b", ep.terminalFloorLimit);
        ep.readerCvmRequiredLimitPresent = ep.readerCvmRequiredLimitPresent
                || args.has("ep-cvm-limit") || profile.containsKey("ep.cvmLimit");
        ep.readerCvmRequiredLimit = epLong(args, profile,
                "ep-cvm-limit", "ep.cvmLimit", ep.readerCvmRequiredLimit);
        return ep;
    }

    /** A long Entry Point option from the CLI or the profile, or the fallback. */
    private static long epLong(Args args, Map<String, String> profile, String option,
            String key, long fallback) {
        String value = setting(args, profile, option, key, null);
        return value == null || value.isEmpty() ? fallback : Long.parseLong(value);
    }

    private static String readPinLine() {
        try {
            Console console = System.console();
            if (console != null) {
                char[] pin = console.readPassword();
                return pin == null ? null : new String(pin);
            }
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(System.in, StandardCharsets.UTF_8));
            return reader.readLine();
        } catch (Exception e) {
            return null;
        }
    }

    // --- CA key ring ---------------------------------------------------------

    private static CaKeyStore caKeyStore(Args args, Map<String, String> profile)
            throws Exception {
        if (args.has("no-oda")) {
            return CaKeyStore.empty();
        }
        String path = setting(args, profile, "ca-keys", "ca.keys", null);
        if (path == null) {
            System.err.println("terminal pay: no -ca-keys, ODA disabled (as -no-oda)");
            return CaKeyStore.empty();
        }
        return CaKeyProfile.load(path);
    }

    // --- Small parsing helpers ----------------------------------------------

    private static String setting(Args args, Map<String, String> profile,
            String name, String profileKey, String defaultValue) {
        if (args.has(name)) {
            return args.get(name, defaultValue);
        }
        String value = profile.get(profileKey);
        return value == null ? defaultValue : value;
    }

    private static boolean flag(Args args, Map<String, String> profile,
            String name, String profileKey) {
        if (args.has(name)) {
            return true;
        }
        String value = profile.get(profileKey);
        return value != null && Boolean.parseBoolean(value);
    }

    private static String[] parseAids(String value, String defaultAid) {
        if (value == null || value.isEmpty()) {
            return new String[] { defaultAid };
        }
        String[] parts = value.split(",");
        String[] aids = new String[parts.length];
        for (int i = 0; i < parts.length; i++) {
            aids[i] = parts[i].trim();
            if (aids[i].isEmpty()) {
                throw new IllegalArgumentException("-aid has an empty entry");
            }
        }
        return aids;
    }

    private static int transactionType(String value) {
        switch (value.toLowerCase()) {
        case "purchase": return 0x00;
        case "cash": return 0x01;
        case "cashback": return 0x09;
        case "refund": return 0x20;
        default: return Integer.parseInt(value, 16);
        }
    }

    private static byte[] tvr(String hex) {
        return hex == null ? new byte[5] : fiveBytes(Hex.parse(hex), "TAC");
    }

    private static byte[] bytes(String hex, byte[] defaultValue) {
        return hex == null ? defaultValue : Hex.parse(hex);
    }

    private static byte[] fourBytes(byte[] value, String name) {
        if (value.length != 4) {
            throw new IllegalArgumentException("-" + name + " must be 4 bytes");
        }
        return value;
    }

    private static byte[] fiveBytes(byte[] value, String name) {
        if (value.length != 5) {
            throw new IllegalArgumentException("-" + name + " must be 5 bytes");
        }
        return value;
    }

    private static byte[] twoBytes(byte[] value, String name) {
        if (value.length != 2) {
            throw new IllegalArgumentException("-" + name + " must be 2 bytes");
        }
        return value;
    }

    private static void write(String text, String path) throws Exception {
        if (path == null) {
            System.out.println(text);
        } else {
            Files.writeString(Path.of(path), text + System.lineSeparator());
        }
    }

    public static void usage(PrintStream out) {
        out.println("usage: Main terminal pay [options]");
        out.println("  transport : -iface=contact|contactless -host=pcsc[:i]|socket:h:p -wait=<s>");
        out.println("              -aid=<hex>[,<hex>] -profile=<path>");
        out.println("  amount    : -amount=<dec> -decimals=<n> -currency=<n> -other=<dec>");
        out.println("              -type=purchase|cash|cashback|refund|<hex> -date=YYMMDD -time=HHMMSS");
        out.println("              -country=<hex> -un=<hex> -seed=<n> -count=<n> -interval=<ms>");
        out.println("  risk/CVM  : -floor=<minor|none> -tac-denial= -tac-online= -tac-default= (5 bytes)");
        out.println("              -merchant-online -target=<0-99> -biased=<minor> -max-target=<0-99>");
        out.println("              -cvm-limit=<minor> -online-pin -signature -pin=<digits>|- -pin-file=<p>");
        out.println("              -pin-key=<32 hex> (3DES online PIN block key, enables online PIN)");
        out.println("              -no-pin -confirm=always|never (cardholder confirmation)");
        out.println("  EntryPoint: -ep-status-check -ep-zero-amount -ep-zero-offline");
        out.println("              -ep-transaction-limit=<minor> -ep-floor-limit=<minor>");
        out.println("              -ep-9f1b=<minor> -ep-cvm-limit=<minor>");
        out.println("              -ep-extended-selection -ep-restart-decline");
        out.println("  terminal  : -terminal-type=<hex> -capabilities=<hex> -addl-capabilities=<hex>");
        out.println("              -ttq=<hex> -app-version= -terminal-id= -ifd= -mcc= -merchant=<ascii>");
        out.println("              -acquirer=<hex>");
        out.println("  ODA       : -ca-keys=<path> -no-oda");
        out.println("  online    : -icc-key=<hex> -csu=<hex> -arc=<hex> -csu-reset -script=<hex>");
        out.println("              -issuer-cmd=<cmd> -auth=<path> -online=auto|always|never|decline");
        out.println("              -referral=accept|decline -exception=<pan[:seq]>[,<pan[:seq]>]");
        out.println("  output    : -json -report=<path> -receipt=<path> -trace -quiet -verbose");
    }
}
