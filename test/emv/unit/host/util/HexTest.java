package card42.test;

import card42.host.common.util.Hex;

/**
 * Unit tests for the host hex / BCD codecs, in particular the ISO 9564-1
 * format 1 Reference PIN Block used by the CPS '8010' personalization DGI
 * (EMV CPS v2.0 Annex A Table A-4 / §3.2).
 */
final class HexTest {

    private HexTest() {
    }

    static void run() {
        System.out.println("HexTest");

        Asserts.bytes(Hex.parse("00 1A 2b"), new byte[] { 0x00, 0x1A, 0x2B },
                "parse ignores separators and case");
        Asserts.eq("001A2B", Hex.format(Hex.parse("001a2b")), "format is upper case");

        Asserts.bytes(Hex.parse("12 34 5F"), Hex.bcd("12345"),
                "BCD pads an odd digit count with 0xF");

        // Reference PIN Block: control nibble 0, N, BCD digits, 'F' padding.
        Asserts.bytes(Hex.parse("04 12 34 FF FF FF FF FF"), Hex.iso9564Format1("1234"),
                "ISO 9564-1 format 1 block for a 4-digit PIN");
        Asserts.bytes(Hex.parse("0C 12 34 56 78 90 12 FF"), Hex.iso9564Format1("123456789012"),
                "ISO 9564-1 format 1 block for a 12-digit PIN");

        // N must be 4..12 and every character a digit (EMV CPS v2.0 Table A-4);
        // a malformed input is rejected instead of producing a broken block.
        checkRejected(null, "null PIN");
        checkRejected("123", "PIN shorter than 4");
        checkRejected("1234567890123", "PIN longer than 12");
        checkRejected("12a4", "non-numeric PIN");
    }

    private static void checkRejected(String pin, String what) {
        try {
            Hex.iso9564Format1(pin);
            Asserts.check(false, what + " should be rejected");
        } catch (IllegalArgumentException e) {
            Asserts.check(true, what + " is rejected");
        }
    }
}
