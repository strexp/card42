package card42.test;

import java.util.Arrays;

import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.crypto.EmvKeys;
import card42.host.common.util.Hex;

/**
 * Spec vectors for the EMV CV '6' (AES) session-key and master-key derivations
 * (EMV v4.4 Book 2 §A1.3.1, §A1.4.3).
 *
 * <p>The AES-CMAC primitive itself is covered by
 * {@code test/common/unit/host/crypto/AesCmacVectorTest.java}; this suite locks
 * the EMV computations and the raw-AC/BCD PAN-sequence-number rules.
 */
final class AesVectorTest {

    private AesVectorTest() {
    }

    /** The ICC master key used by the A1.3.1 vectors. */
    private static final byte[] MK = Hex.parse("0F0E0D0C0B0A09080706050403020100");

    static void run() throws Exception {
        System.out.println("AesVector");

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
}
