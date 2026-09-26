package card42.test;

import java.util.Arrays;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Args;
import card42.host.common.util.Hex;
import card42.host.common.codec.Responses;
import card42.host.common.codec.Tags;

/**
 * End-to-end smoke test for the CV '6' (AES) profile (docs/specs/common/toolchain.md §6).
 *
 * It runs the CCD transaction on the AES test instance 43415244420108
 * (personalized by perso/emv/sample-test.perso):
 *
 *   SELECT -> GET PROCESSING OPTIONS -> READ RECORD -> GENERATE AC (ARQC) ->
 *   issuer authentication (ARPC Method 2 with AES-CMAC) -> second AC (TC)
 *
 * Every cryptogram is recomputed off-card with the AES CMAC and the A1.3.1 AES
 * session-key derivation, so a regression in the card's CV '6' crypto is caught
 * here.  The IAD must carry the Format Code 'A' / CV '6' Common Core Identifier
 * ('A6').
 *
 * Exits non-zero if any check fails.
 */
public class AesFlowTest {

    private static final String AID = "43415244420108";

    /** ICC master key of the AES test instance: A1.4.3 Option C of sample-test.perso. */
    private static final byte[] ICC_KEY =
            Hex.parse("F5C0A799FFBED1DB4F9BD2E54BF2CFD9");

    private static final byte[] ARC_APPROVED = { 0x00, 0x00 };
    private static final byte[] CSU_APPROVE = { 0x00, (byte) 0x80, 0x00, 0x00 };

    public static void main(String[] argv) throws Exception {
        Args args = new Args(argv, new String[] { "host" }, new String[0]);
        String host = args.get("host", "socket:localhost:9025");

        CardTerminal terminal = TestTerminals.getTerminal(host.split(":"));
        if (terminal == null || !terminal.waitForCardPresent(10000)) {
            throw new IllegalStateException("Connection to simulator failed on " + host);
        }

        Card card = terminal.connect("*");
        try {
            run(new Terminal(card.getBasicChannel()));
        } finally {
            card.disconnect(true);
        }

        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " check(s)");
            System.exit(1);
        }
        System.out.println("ALL CHECKS PASSED");
    }

    private static void run(Terminal terminal) throws Exception {
        ResponseAPDU r = terminal.select(AID);
        Checks.check("SELECT CV6 instance", r.getSW() == 0x9000, r);
        if (r.getSW() != 0x9000) {
            return;
        }

        r = terminal.gpo();
        Checks.check("GET PROCESSING OPTIONS", r.getSW() == 0x9000, r);
        if (r.getSW() != 0x9000) {
            return;
        }
        byte[] aipBytes = Responses.gpoAip(r.getData());
        int aip = ((aipBytes[0] & 0xFF) << 8) | (aipBytes[1] & 0xFF);
        Checks.check("CV6 AIP", aip == 0x5800);

        r = terminal.readRecord(1, 1);
        Checks.check("READ RECORD 1", r.getSW() == 0x9000, r);
        if (r.getSW() != 0x9000) {
            return;
        }
        byte[] record1 = r.getData();
        byte[] cdol1 = Tags.find(record1, 0x8C);
        byte[] cdol2 = Tags.find(record1, 0x8D);
        if (cdol1 == null || cdol2 == null) {
            Checks.fail("record 1 has no CDOL1/CDOL2");
            return;
        }
        int cdol1Length = AcCrypto.dolDataLength(cdol1);
        int atc = terminal.readAtc();
        System.out.printf("ATC         : %04X%n", atc);

        // First GENERATE AC: request an ARQC.  The AC must be the AES-CMAC over
        // the CDOL1 data, AIP, ATC and IAD (EMV v4.4 Book 2 §8.1.2).
        byte[] cdol1Data = new byte[cdol1Length];
        ResponseAPDU first = terminal.generateAc((byte) 0x80, cdol1Data);
        Checks.check("first GENERATE AC", first.getSW() == 0x9000, first);
        if (first.getSW() != 0x9000) {
            return;
        }
        Responses.AcResponse ac1 = Responses.parseAc(first);
        Checks.check("first AC is an ARQC", ac1.cid == (byte) 0x80);
        Checks.check("CV6 IAD CCI is 'A6'",
                ac1.iad != null && ac1.iad.length > 1 && ac1.iad[1] == (byte) 0xA6);
        byte[] expected1 = AcCrypto.expectedAcAes(ICC_KEY, aip, atc, cdol1Data, ac1.iad);
        System.out.println("  first AC  : " + Hex.format(ac1.ac)
                + " (expected " + Hex.format(expected1) + ")");
        Checks.check("CV6 first AC cryptogram", Arrays.equals(ac1.ac, expected1));

        // Issuer authentication: ARPC Method 2 with AES-CMAC, inline in CDOL2.
        byte[] sk = AcCrypto.sessionKeyAes(ICC_KEY, atc);
        byte[] cdol2Data = cdol2Data(cdol2, ac1.ac, sk);
        ResponseAPDU second = terminal.generateAc((byte) 0x40, cdol2Data);
        Checks.check("second GENERATE AC", second.getSW() == 0x9000, second);
        if (second.getSW() != 0x9000) {
            return;
        }
        Responses.AcResponse ac2 = Responses.parseAc(second);
        Checks.check("CV6 second AC is a TC", ac2.cid == (byte) 0x40);
        byte[] expected2 = AcCrypto.expectedAcAes(ICC_KEY, aip, atc, cdol2Data, ac2.iad);
        System.out.println("  second AC : " + Hex.format(ac2.ac)
                + " (expected " + Hex.format(expected2) + ")");
        Checks.check("CV6 second AC cryptogram", Arrays.equals(ac2.ac, expected2));

        byte[] lastOnline = Tags.find(terminal.getData(0x9F, 0x13).getData(), 0x9F13);
        Checks.check("9F13 records the online ATC",
                lastOnline != null && lastOnline.length == 2
                        && (((lastOnline[0] & 0xFF) << 8) | (lastOnline[1] & 0xFF)) == atc);

        // A wrong ARPC must be rejected (AES-CMAC mismatch) and force an AAC
        // (EMV v4.4 Book 2 §8.2).
        ResponseAPDU wrong = wrongArpc(terminal, cdol1, cdol2);
        if (wrong != null) {
            Checks.check("wrong AES ARPC forces AAC",
                    Responses.parseAc(wrong).cid == 0x00);
        }
    }

    /** Builds a CDOL2 data field with the ARC and an AES-CMAC ARPC. */
    private static byte[] cdol2Data(byte[] cdol2, byte[] arqc, byte[] sk)
            throws Exception {
        byte[] data = new byte[AcCrypto.dolDataLength(cdol2)];
        int arcOff = AcCrypto.dolValueOffset(cdol2, 0x8A);
        if (arcOff >= 0) {
            System.arraycopy(ARC_APPROVED, 0, data, arcOff, 2);
        }
        int authOff = AcCrypto.dolValueOffset(cdol2, 0x91);
        if (authOff >= 0) {
            byte[] arpc = AcCrypto.computeArpcMethod2Aes(sk, arqc, CSU_APPROVE, new byte[0]);
            System.arraycopy(arpc, 0, data, authOff, 4);
            System.arraycopy(CSU_APPROVE, 0, data, authOff + 4, 4);
        }
        return data;
    }

    /** Starts a fresh session, sends a corrupted AES ARPC and returns the second AC response. */
    private static ResponseAPDU wrongArpc(Terminal terminal, byte[] cdol1, byte[] cdol2)
            throws Exception {
        terminal.select(AID);
        ResponseAPDU gpo = terminal.gpo();
        if (gpo.getSW() != 0x9000) {
            Checks.fail("wrong ARPC: GPO -> " + Checks.sw(gpo.getSW()));
            return null;
        }
        int atc = terminal.readAtc();
        ResponseAPDU first = terminal.generateAc((byte) 0x80,
                new byte[AcCrypto.dolDataLength(cdol1)]);
        if (first.getSW() != 0x9000) {
            Checks.fail("wrong ARPC: first AC -> " + Checks.sw(first.getSW()));
            return null;
        }
        byte[] arqc = Responses.parseAc(first).ac;
        byte[] sk = AcCrypto.sessionKeyAes(ICC_KEY, atc);
        byte[] data = cdol2Data(cdol2, arqc, sk);
        int authOff = AcCrypto.dolValueOffset(cdol2, 0x91);
        data[authOff] ^= 0x01; // corrupt the ARPC
        ResponseAPDU r = terminal.generateAc((byte) 0x40, data);
        Checks.check("wrong AES ARPC second AC", r.getSW() == 0x9000, r);
        return r.getSW() == 0x9000 ? r : null;
    }
}
