package card42.test;

import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import card42.host.emv.lib.Amounts;
import card42.host.common.util.Args;
import card42.host.common.codec.Json;
import card42.host.emv.report.TransactionReport;
import card42.host.common.codec.TlvDump;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.crypto.SmCrypto;
import card42.host.emv.app.issuer.IssuerHost;
import card42.host.emv.oda.CaKey;
import card42.host.emv.oda.CaKeyProfile;
import card42.host.emv.oda.CaKeyStore;
import card42.host.common.util.Hex;

/**
 * Unit suite for the host CLI support classes: the option parser, the amount /
 * numeric encoders, the JSON host-bridge reader, the TLV printer, the CA key
 * ring loader and the report decoders (docs/specs/common/toolchain.md §7.1).
 *
 * <p>CLI support-class coverage (tool), not an EMV/ICAO/BSI/CPS clause.
 */
final class CliTest {

    private CliTest() {
    }

    static void run() throws Exception {
        System.out.println("CliTest");
        argsParser();
        amounts();
        json();
        tlvDump();
        caKeyRing();
        reportDecoders();
        issuerCommands();
    }

    private static void argsParser() {
        Args args = new Args(
                new String[] { "-amount=12.34", "-type", "cash", "-json", "extra" },
                new String[] { "amount", "type" }, new String[] { "json" });
        Asserts.eq("12.34", args.get("amount", null), "-name=value");
        Asserts.eq("cash", args.get("type", null), "-name value");
        Asserts.check(args.has("json"), "flag present");
        Asserts.eq(1, args.positional().size(), "positional kept");
        Asserts.eq("extra", args.positional().get(0), "positional value");

        Args repeated = new Args(new String[] { "-script=AA", "-script", "BB" },
                new String[] { "script" }, new String[] {});
        Asserts.eq(2, repeated.all("script").size(), "repeated option collected");

        Asserts.check(throwsIllegal(() -> new Args(new String[] { "-bogus" },
                new String[] {}, new String[] {})), "unknown option rejected");
        Asserts.check(throwsIllegal(() -> new Args(new String[] { "-amount" },
                new String[] { "amount" }, new String[] {})), "missing value rejected");
        Asserts.check(throwsIllegal(() -> new Args(new String[] { "-json=1" },
                new String[] {}, new String[] { "json" })), "value on flag rejected");
    }

    private static void amounts() {
        Asserts.eq(1234L, Amounts.amount("12.34", 2), "amount 12.34 @2");
        Asserts.eq(5L, Amounts.amount("0.05", 2), "amount 0.05 @2");
        Asserts.eq(5L, Amounts.amount("5", 0), "amount 5 @0");
        Asserts.eq(12345L, Amounts.amount("12.345", 3), "amount 12.345 @3");
        Asserts.bytes(Hex.parse("0978"), Amounts.numeric("978", 2),
                "numeric currency 978 -> 0978");
        Asserts.bytes(Hex.parse("260924"), Amounts.numeric("260924", 3),
                "numeric date left-padded");
    }

    private static void json() {
        Map<String, Object> object = Json.parseObject(
                "{\"arc\":\"3030\",\"auth\":\"0011223344556677\",\"scripts\":[\"AA\",\"BB\"]}");
        Asserts.eq("3030", Json.string(object, "arc"), "json string field");
        Asserts.eq(2, Json.strings(object, "scripts").size(), "json string array");
        Asserts.eq("AA", Json.strings(object, "scripts").get(0), "json array order");
        Asserts.eq("\"a\\\"b\"", Json.quote("a\"b"), "json quote escapes");
    }

    private static void tlvDump() {
        String dump = TlvDump.format(Hex.parse("500A454D5634322054455354"));
        Asserts.check(dump.contains("50 0A"), "tlv dump tag and length");
        Asserts.check(dump.contains("454D5634322054455354"), "tlv dump value");
        Asserts.check(TlvDump.tagName(0x50).equals("Application Label"),
                "tlv dump tag name");
    }

    private static void caKeyRing() throws Exception {
        CaKeyStore store = CaKeyProfile.load("perso/emv/sample.ca.keys");
        CaKey key = store.byIndex(new byte[] { 0x01 });
        Asserts.check(key != null, "CA key index 01 loaded");
        Asserts.check(key.modulus.equals(TestKeys.CA_MODULUS)
                && key.exponent.equals(TestKeys.CA_EXPONENT),
                "perso/emv/sample.ca.keys matches TestKeys (no drift)");
        Asserts.check(store.byIndex(new byte[] { 0x02 }) == null,
                "unknown CA key index returns null");
        Asserts.check(CaKeyStore.empty().byIndex(new byte[] { 0x01 }) == null,
                "empty CA key store trusts nothing");
    }

    private static void reportDecoders() {
        Asserts.check(TransactionReport.aipNames(0x7900).contains("SDA")
                && TransactionReport.aipNames(0x7900).contains("DDA")
                && TransactionReport.aipNames(0x7900).contains("CDA"),
                "AIP decode 0x7900");
        Asserts.eq("ARQC", TransactionReport.cidName((byte) 0x80), "CID name ARQC");
        Asserts.eq("TC", TransactionReport.cidName((byte) 0x40), "CID name TC");
        Asserts.eq("AAC", TransactionReport.cidName((byte) 0x00), "CID name AAC");
        Asserts.check(TransactionReport.cvmText(Hex.parse("010002")).contains("successful"),
                "CVM results decode");
        // '3F0000' is the CVM Results for "No CVM performed" (EMV v4.4 Book 3
        // §10.5), the value the kernel emits when AIP b5=0.
        Asserts.check(TransactionReport.cvmText(Hex.parse("3F0000")).contains("no CVM performed"),
                "CVM results no CVM performed decode");
        Asserts.check(TransactionReport.cvmText(Hex.parse("3F0001")).contains("no CVM performed")
                && TransactionReport.cvmText(Hex.parse("3F0001")).contains("failed"),
                "CVM results no CVM performed (failed) decode");
    }

    /**
     * The issuer command family (docs/specs/common/toolchain.md §7.1): drives {@link
     * card42.host.emv.cli.Main} and checks the KCV / session key / ARPC / JSON
     * authorisation against the crypto helpers (the independent vectors live in
     * {@code AcCryptoTest} / {@code SmCryptoTest}).
     */
    private static void issuerCommands() throws Exception {
        byte[] key = Hex.parse("0F0E0D0C0B0A09080706050403020100");
        byte[] arqc = Hex.parse("0102030405060708");
        byte[] csu = Hex.parse("00800000");
        byte[] arc = Hex.parse("3030");
        byte[] sk = AcCrypto.sessionKey(key, 1);

        // KCV: leftmost 3 bytes of DES3(key)[00 x8], computed here with JCE.
        Cipher des = Cipher.getInstance("DESede/ECB/NoPadding");
        byte[] key24 = new byte[24];
        System.arraycopy(key, 0, key24, 0, 16);
        System.arraycopy(key, 0, key24, 16, 8);
        des.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key24, "DESede"));
        byte[] expectedKcv = java.util.Arrays.copyOf(des.doFinal(new byte[8]), 3);
        String keys = runCli(null, "issuer", "keys", "-key=" + Hex.format(key), "-atc=1");
        Asserts.check(keys.contains(Hex.format(expectedKcv)), "issuer keys KCV");
        Asserts.check(keys.contains(Hex.format(sk)), "issuer keys session key");

        Asserts.eq(Hex.format(AcCrypto.computeArpcMethod2(sk, arqc, csu, new byte[0])),
                runCli(null, "issuer", "arpc", "-key=" + Hex.format(key), "-atc=1",
                        "-arqc=" + Hex.format(arqc)),
                "issuer arpc method 2");
        Asserts.eq(Hex.format(AcCrypto.computeArpcMethod1(sk, arqc, arc)),
                runCli(null, "issuer", "arpc", "-key=" + Hex.format(key), "-atc=1",
                        "-arqc=" + Hex.format(arqc), "-method=1", "-arc=" + Hex.format(arc)),
                "issuer arpc method 1");

        // issuer authorize: the response carries the ARC and the inline issuer
        // authentication data (ARPC || CSU) that IssuerHost also produces.
        String response = runCli("{\"arqc\":\"0102030405060708\",\"atc\":1}",
                "issuer", "authorize", "-icc-key=" + Hex.format(key));
        Map<String, Object> out = Json.parseObject(response);
        Asserts.eq("3030", Json.string(out, "arc"), "issuer authorize arc");
        IssuerHost host = new IssuerHost(key);
        host.setFirstAc(arqc, 1);
        Asserts.bytes(host.inlineIssuerAuthData(IssuerHost.CSU_APPROVE, 0),
                Hex.parse(Json.string(out, "auth")), "issuer authorize inline issuer auth");
        Asserts.eq(0, Json.strings(out, "scripts").size(), "issuer authorize no scripts");

        String withScript = runCli("{\"arqc\":\"0102030405060708\",\"atc\":1}",
                "issuer", "authorize", "-icc-key=" + Hex.format(key),
                "-script=720E9F1804010203048606001E0000");
        Asserts.eq(1, Json.strings(Json.parseObject(withScript), "scripts").size(),
                "issuer authorize script echo");

        // issuer script: raw and Format 1 secure-messaging templates parse back.
        SmCrypto.IssuerScript raw = SmCrypto.parseIssuerScript(Hex.parse(
                runCli(null, "issuer", "script", "-command=001E0000", "-script-id=01020304")));
        Asserts.bytes(Hex.parse("01020304"), raw.scriptId, "issuer script identifier");
        Asserts.bytes(Hex.parse("001E0000"), raw.commands.get(0), "issuer script command");
        SmCrypto.IssuerScript sm = SmCrypto.parseIssuerScript(Hex.parse(
                runCli(null, "issuer", "script", "-command=001E0000",
                        "-mac-key=11111111111111111111111111111111", "-arqc=AABBCCDDEEFF0011")));
        Asserts.eq(1, sm.commands.size(), "issuer script SM command count");
        Asserts.eq(0x8C, sm.commands.get(0)[0] & 0xFF, "issuer script SM CLA 8C");
    }

    /** Runs the CLI with optional stdin and returns the captured stdout. */
    private static String runCli(String stdin, String... args) throws Exception {
        java.io.InputStream oldIn = System.in;
        java.io.PrintStream oldOut = System.out;
        java.io.PrintStream oldErr = System.err;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int code;
        try {
            if (stdin != null) {
                System.setIn(new java.io.ByteArrayInputStream(
                        stdin.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            }
            System.setOut(new java.io.PrintStream(out, true,
                    java.nio.charset.StandardCharsets.UTF_8));
            System.setErr(new java.io.PrintStream(new java.io.ByteArrayOutputStream(), true,
                    java.nio.charset.StandardCharsets.UTF_8));
            code = card42.host.emv.cli.Main.run(args);
        } finally {
            System.setIn(oldIn);
            System.setOut(oldOut);
            System.setErr(oldErr);
        }
        Asserts.eq(0, code, "cli exit " + String.join(" ", args));
        return out.toString(java.nio.charset.StandardCharsets.UTF_8).trim();
    }

    private static boolean throwsIllegal(Runnable action) {
        try {
            action.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }
}
