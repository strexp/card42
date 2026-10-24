package card42.test;

import card42.host.common.crypto.AesCmac;
import card42.host.common.util.Hex;

/**
 * External AES-CMAC vectors (RFC 4493, equivalently NIST SP 800-38B) for the
 * host CMAC primitive.
 *
 * <p>The EMV CV '6' session/master-key derivations live in
 * {@code test/emv/unit/host/crypto/AesVectorTest.java}; this suite only covers
 * the shared {@link AesCmac} primitive.
 */
final class AesCmacVectorTest {

    private AesCmacVectorTest() {
    }

    /** RFC 4493 AES-128 key. */
    private static final byte[] CMAC_KEY =
            Hex.parse("2B7E151628AED2A6ABF7158809CF4F3C");

    static void run() throws Exception {
        System.out.println("AesCmacVector");

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
    }

    private static void checkCmac(byte[] msg, String expectedHex) throws Exception {
        Asserts.bytes(Hex.parse(expectedHex), AesCmac.mac(CMAC_KEY, msg),
                "RFC 4493 AES-CMAC len=" + msg.length);
    }
}
