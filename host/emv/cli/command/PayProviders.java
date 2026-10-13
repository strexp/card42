package card42.host.emv.cli.command;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import card42.host.common.cli.Args;
import card42.host.common.util.Hex;
import card42.host.emv.app.issuer.AuthFileIssuer;
import card42.host.emv.app.issuer.ClosedLoopIssuer;
import card42.host.emv.app.issuer.SubprocessIssuer;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.kernel.core.Authorization;
import card42.host.emv.kernel.core.ConfirmationProvider;
import card42.host.emv.kernel.core.Issuer;
import card42.host.emv.kernel.core.OnlinePinProvider;
import card42.host.emv.kernel.core.PinProvider;
import card42.host.emv.kernel.core.SignatureProvider;
import card42.host.emv.oda.CaKeyProfile;
import card42.host.emv.oda.CaKeyStore;
import card42.host.emv.report.ReceiptPrinter;
import card42.host.emv.report.ReceiptRenderer;

/**
 * Builds the host callbacks and online authorisation of {@code terminal pay}
 * from the CLI options / profile (EMV v4.4 Book 4 §6.3.4/§6.5.2): the offline
 * and online PIN providers, the signature/confirmation callbacks, the issuer,
 * the CA key ring and the receipt printer.
 *
 * <p>Split out of {@link TerminalPayCommand} so the command keeps the option
 * parsing, the {@code TerminalConfig}/{@code TransactionRequest} mapping and the
 * run loop.  The shared {@code setting}/{@code flag} option helpers live here
 * too, since every factory needs them.
 */
final class PayProviders {

    private PayProviders() {
    }

    // --- Issuer --------------------------------------------------------------

    static Issuer issuer(Args args, Map<String, String> profile, String online) {
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

    static PinProvider pinProvider(Args args, boolean contact) throws Exception {
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
    static OnlinePinProvider onlinePinProvider(Args args, PinProvider pins) {
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
    static SignatureProvider signatureProvider(Args args) {
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
    static ConfirmationProvider confirmationProvider(Args args,
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
    static ReceiptPrinter receiptPrinter(Args args) {
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

    static String readPinLine() {
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

    static CaKeyStore caKeyStore(Args args, Map<String, String> profile)
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

    // --- Small option helpers (shared) --------------------------------------

    static String setting(Args args, Map<String, String> profile,
            String name, String profileKey, String defaultValue) {
        if (args.has(name)) {
            return args.get(name, defaultValue);
        }
        String value = profile.get(profileKey);
        return value == null ? defaultValue : value;
    }

    static boolean flag(Args args, Map<String, String> profile,
            String name, String profileKey) {
        if (args.has(name)) {
            return true;
        }
        String value = profile.get(profileKey);
        return value != null && Boolean.parseBoolean(value);
    }

    /** A long Entry Point option from the CLI or the profile, or the fallback. */
    static long epLong(Args args, Map<String, String> profile, String option,
            String key, long fallback) {
        String value = setting(args, profile, option, key, null);
        return value == null || value.isEmpty() ? fallback : Long.parseLong(value);
    }

    static byte[] fourBytes(byte[] value, String name) {
        if (value.length != 4) {
            throw new IllegalArgumentException("-" + name + " must be 4 bytes");
        }
        return value;
    }

    static byte[] twoBytes(byte[] value, String name) {
        if (value.length != 2) {
            throw new IllegalArgumentException("-" + name + " must be 2 bytes");
        }
        return value;
    }
}
