package card42.test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import javax.smartcardio.CommandAPDU;

import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.crypto.SmCrypto;
import card42.host.common.util.Bytes;
import card42.host.common.util.Hex;
import card42.host.common.codec.TlvWriter;


/** Pure-JVM tests for the issuer script / secure messaging helpers (EMV v4.4 Book 2 §9.2/§9.3). */
final class SmCryptoTest {

    private SmCryptoTest() {
    }

    static void run() throws Exception {
        System.out.println("SmCrypto");

        // --- Issuer Script Results (EMV v4.4 Book 4 Annex A5) ------------------------
        Asserts.bytes(Hex.parse("2001020304"),
                SmCrypto.issuerScriptResults(2, 0, Hex.parse("01020304")),
                "9F5B successful result");
        Asserts.bytes(Hex.parse("1500000000"),
                SmCrypto.issuerScriptResults(1, 5, null),
                "9F5B failed result without identifier");

        // --- TVR script failure bits (EMV v4.4 Book 3 section 10.10) -----------------
        byte[] tvr = new byte[5];
        SmCrypto.setScriptFailure(tvr, false);
        Asserts.bytes(Hex.parse("0000000020"), tvr, "TVR before final AC bit");
        SmCrypto.setScriptFailure(tvr, true);
        Asserts.bytes(Hex.parse("0000000030"), tvr, "TVR after final AC bit");

        // --- 71/72 template parsing -----------------------------------------
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x9F18, Hex.parse("01020304"));
        TlvWriter.writeTlv(body, 0x86, Hex.parse("8C240000"));
        TlvWriter.writeTlv(body, 0x86, Hex.parse("8C1E0000"));
        ByteArrayOutputStream template = new ByteArrayOutputStream();
        TlvWriter.writeTlv(template, 0x71, body.toByteArray());
        SmCrypto.IssuerScript script = SmCrypto.parseIssuerScript(template.toByteArray());
        Asserts.bytes(Hex.parse("01020304"), script.scriptId,
                "issuer script identifier");
        Asserts.eq(2, script.commands.size(), "issuer script command count");
        Asserts.bytes(Hex.parse("8C240000"), script.commands.get(0),
                "issuer script command 0");
        Asserts.bytes(Hex.parse("8C1E0000"), script.commands.get(1),
                "issuer script command 1");

        // --- MAC-chained Format 1 command -----------------------------------
        byte[] macKey = Hex.parse("11111111111111111111111111111111");
        byte[] encKey = Hex.parse("22222222222222222222222222222222");
        byte[] arqc = Hex.parse("AABBCCDDEEFF0011");
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(macKey, encKey);
        session.start(arqc);

        byte[] macSessionKey = AcCrypto.sessionKey(macKey, arqc);
        byte[] header = new byte[] { (byte) 0x8C, 0x24, 0, 0 };
        byte[] headerPad = new byte[] { (byte) 0x80, 0x00, 0x00, 0x00 };

        CommandAPDU first = session.command(0x24, 0x00, 0x00);
        byte[] firstMac = Arrays.copyOfRange(first.getData(), 2, 10);
        Asserts.bytes(AcCrypto.macAlg3Padded(macSessionKey,
                        Bytes.concat(arqc, header, headerPad), 8),
                firstMac, "ScriptSession first command MAC");

        CommandAPDU second = session.command(0x24, 0x00, 0x00);
        byte[] secondMac = Arrays.copyOfRange(second.getData(), 2, 10);
        Asserts.bytes(AcCrypto.macAlg3Padded(macSessionKey,
                        Bytes.concat(firstMac, header, headerPad), 8),
                secondMac, "ScriptSession chained MAC");

        // A Format 1 command with a '81' plaintext object: the MAC input is
        // ICV || padded header || padded data object (EMV v4.4 Book 2 Annex D2.3.1).
        SmCrypto.ScriptSession plain = new SmCrypto.ScriptSession(macKey, encKey);
        plain.start(arqc);
        byte[] plainData = Hex.parse("1234");
        CommandAPDU plainCmd = plain.command(0x24, 0x00, 0x00, plainData, null);
        byte[] plainMac = Arrays.copyOfRange(plainCmd.getData(),
                plainCmd.getData().length - 8, plainCmd.getData().length);
        Asserts.bytes(AcCrypto.macAlg3Padded(macSessionKey, Bytes.concat(arqc,
                        header, headerPad, SmCrypto.padIso7816(
                                Bytes.concat(new byte[] { (byte) 0x81, 0x02 },
                                        plainData))), 8),
                plainMac, "ScriptSession plaintext object MAC");

        // MAC truncation: a 4-byte MAC is transmitted, but the chain advances
        // with the full 8 bytes (EMV v4.4 Book 2 section 9.2.3.1).
        SmCrypto.ScriptSession truncated = new SmCrypto.ScriptSession(macKey, encKey);
        truncated.setMacLength(4);
        truncated.start(arqc);
        CommandAPDU t1 = truncated.command(0x24, 0x00, 0x00);
        Asserts.eq(4, t1.getData()[1] & 0xFF, "truncated MAC length");
        byte[] full1 = AcCrypto.macAlg3Padded(macSessionKey,
                Bytes.concat(arqc, header, headerPad), 8);
        Asserts.bytes(Arrays.copyOf(full1, 4),
                Arrays.copyOfRange(t1.getData(), 2, 6), "truncated MAC value");
        CommandAPDU t2 = truncated.command(0x24, 0x00, 0x00);
        byte[] full2 = AcCrypto.macAlg3Padded(macSessionKey,
                Bytes.concat(full1, header, headerPad), 8);
        Asserts.bytes(Arrays.copyOf(full2, 4),
                Arrays.copyOfRange(t2.getData(), 2, 6),
                "truncated session chains with the full MAC");
    }
}
