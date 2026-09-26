package card42.test;

import java.util.Arrays;

import card42.host.emv.crypto.AcCrypto;
import card42.host.common.crypto.AesCmac;
import card42.host.emv.crypto.EmvKeys;
import card42.host.common.util.Hex;

/**
 * Spec vectors for the CV '6' (AES) building blocks (EMV v4.4 Book 2 §A1.2.2,
 * §A1.3.1, §A1.4.3).
 *
 * <p>The AES-CMAC values are the RFC 4493 (equivalently NIST SP 800-38B) test
 * vectors, so the host CMAC used by the CV '6' tests is locked against an
 * external reference.  The A1.3.1 session-key and A1.4.3 master-key derivations
 * are locked against independent OpenSSL computations recorded in the test.
 */
final class AesVectorTest {

    private AesVectorTest() {
    }

    /** RFC 4493 AES-128 key. */
    private static final byte[] CMAC_KEY =
            Hex.parse("2B7E151628AED2A6ABF7158809CF4F3C");

    /** The ICC master key used by the A1.3.1 vectors. */
    private static final byte[] MK = Hex.parse("0F0E0D0C0B0A09080706050403020100");

    static void run() throws Exception {
        System.out.println("AesVector");

        // --- RFC 4493 / NIST SP 800-38B AES-CMAC vectors ---------------------
        checkCmac(new byte[0], "BB1D6929E95937287FA37D129B756746");
        checkCmac(Hex.parse("6BC1BEE22E409F96E93D7E117393172A"),
                "070A16B46B4D4144F79BDD9DD04A287C");
        checkCmac(Hex.parse("6BC1BEE22E409F96E93D7E117393172A"
                + "AE2D8A571E03AC9C9EB76FAC45AF8E51"
                + "30C81C46A35CE411"), "DFA66747DE9AE63030CA32611497C827");
        checkCmac(Hex.parse("6BC1BEE22E409F96E93D7E117393172A"
                + "AE2D8A571E03AC9C9EB76FAC45AF8E51"
                + "30C81C46A35CE411E5FBC1191A0A52EF"
                + "F69F2445DF4F9B17AD2B417BE66C3710"), "51F0BEBF7E3B9D92FC49741779363CFE");

        // The AC truncates the CMAC to its 8 leftmost bytes (EMV v4.4 Book 2 §8.1.2).
        Asserts.bytes(Hex.parse("070A16B46B4D4144"),
                AesCmac.mac(CMAC_KEY, Hex.parse("6BC1BEE22E409F96E93D7E117393172A"), 8),
                "AES-CMAC truncated to s=8");

        // --- A1.3.1 AES session key (R = ATC || 00 x14) ----------------------
        Asserts.bytes(Hex.parse("F06C204C70D2AD0CD1FA3B8CE15958F8"),
                AcCrypto.sessionKeyAes(MK, 0x0001), "A1.3.1 AES session key (R = ATC)");
        // The secure-messaging key uses R = first AC || 00 x8.
        byte[] ac = Hex.parse("AABBCCDDEEFF0011");
        Asserts.bytes(Hex.parse("C1994753F99E6196418C14F7DD5F1AF9"),
                AcCrypto.sessionKeyAesSm(MK, ac), "A1.3.1 AES session key (R = first AC)");

        // --- A1.4.3 Option C master key derivation ---------------------------
        // IMK 0F0E..0100, PAN 1234567890, PAN sequence number 0.
        byte[] imk = Hex.parse("0F0E0D0C0B0A09080706050403020100");
        Asserts.bytes(Hex.parse("00000000000000000000123456789000"),
                EmvKeys.diversificationValue("1234567890", 0), "A1.4.3 diversification value Y");
        Asserts.bytes(Hex.parse("F5C0A799FFBED1DB4F9BD2E54BF2CFD9"),
                EmvKeys.aesMasterKey(imk, "1234567890", 0, 16), "A1.4.3 AES-128 master key");
        // AES-256: MK = AES(IMK)[Y] || AES(IMK)[Y*], Y* = Y xor FF x16.
        Asserts.bytes(Hex.parse("F5C0A799FFBED1DB4F9BD2E54BF2CFD9"
                + "83BC15FBEDDB610DB33F851BAD25B47A"),
                EmvKeys.aesMasterKey(imk, "1234567890", 0, 32), "A1.4.3 AES-256 master key");

        // A different PAN sequence number changes the key.
        Asserts.check(!Arrays.equals(
                        EmvKeys.aesMasterKey(imk, "1234567890", 0, 16),
                        EmvKeys.aesMasterKey(imk, "1234567890", 1, 16)),
                "A1.4.3 key depends on the PAN sequence number");

        // Tag 5F34 is BCD: its nibbles are decimal digits, so 0x12 contributes
        // the digit string "12", not the byte value 18 (EMV v4.4 Book 2 §A1.4.3).
        Asserts.bytes(Hex.parse("00000000000000000000123456789012"),
                EmvKeys.diversificationValue("1234567890", 0x12),
                "A1.4.3 diversification value Y (BCD PSN 0x12)");
        Asserts.bytes(Hex.parse("CBCE431053E9874B1AF0B115D6E04C2A"),
                EmvKeys.aesMasterKey(imk, "1234567890", 0x12, 16),
                "A1.4.3 AES-128 master key (BCD PSN 0x12)");
        // An odd-length BCD value has a 0xF low pad nibble that is dropped:
        // 0x1F is the single digit "1".
        Asserts.bytes(Hex.parse("00000000000000000000012345678901"),
                EmvKeys.diversificationValue("1234567890", 0x1F),
                "A1.4.3 diversification value Y (BCD PSN 0x1F pad nibble)");
    }

    private static void checkCmac(byte[] msg, String expectedHex) throws Exception {
        Asserts.bytes(Hex.parse(expectedHex), AesCmac.mac(CMAC_KEY, msg),
                "RFC 4493 AES-CMAC len=" + msg.length);
    }
}
