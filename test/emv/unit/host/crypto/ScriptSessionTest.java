package card42.test;

import java.util.Arrays;

import javax.smartcardio.CommandAPDU;

import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.crypto.SmCrypto;
import card42.host.emv.crypto.ScriptSession;
import card42.host.common.util.Bytes;
import card42.host.common.util.Hex;


/**
 * Pure-JVM tests for the Format 1 secure-messaging command builder
 * {@link ScriptSession} (EMV v4.4 Book 2 §9.2.3 / Annex D2.3.1).
 */
final class ScriptSessionTest {

    private ScriptSessionTest() {
    }

    static void run() throws Exception {
        System.out.println("ScriptSession");

        // --- MAC-chained Format 1 command -----------------------------------
        byte[] macKey = Hex.parse("11111111111111111111111111111111");
        byte[] encKey = Hex.parse("22222222222222222222222222222222");
        byte[] arqc = Hex.parse("AABBCCDDEEFF0011");
        ScriptSession session = new ScriptSession(macKey, encKey);
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
        ScriptSession plain = new ScriptSession(macKey, encKey);
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
        ScriptSession truncated = new ScriptSession(macKey, encKey);
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
