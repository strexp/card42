package card42.test;

import card42.host.common.util.Hex;
import card42.host.common.util.Bcd;

/**
 * Unit tests for the BCD amount helpers (EMV v4.4 Book 3 §4.3).
 */
final class BcdTest {

    private BcdTest() {
    }

    static void run() {
        System.out.println("BcdTest");

        // BCD round trip.
        Asserts.eq(500L, Bcd.bcdToLong(Hex.parse("000000000500")), "bcdToLong 5.00");
        Asserts.bytes(Hex.parse("000000000500"),
                Bcd.longToBcd(500, 6), "longToBcd 5.00");
        Asserts.eq(-1L, Bcd.bcdToLong(Hex.parse("00AB")), "bcdToLong rejects non-BCD");
    }
}
