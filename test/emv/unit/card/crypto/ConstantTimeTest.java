package card42.test;

import card42.common.ConstantTime;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for the constant-time comparison (docs/specs/common/toolchain.md §6):
 * equality, a difference in the first/last byte, an empty range and a range
 * with a non-zero offset.
 *
 * <p>Internal utility coverage (docs/specs/common/cryptography.md §9); no
 * EMV/ICAO/BSI/CPS clause.
 */
final class ConstantTimeTest {

    private ConstantTimeTest() {
    }

    static void run() {
        System.out.println("ConstantTime");

        byte[] a = Hex.parse("0011223344556677");
        byte[] b = Hex.parse("0011223344556677");
        Asserts.check(ConstantTime.equals(a, (short) 0, b, (short) 0, (short) 8),
                "equal ranges");
        Asserts.check(ConstantTime.equals(a, (short) 0, b, (short) 0, (short) 0),
                "empty range is equal");

        byte[] firstDiff = Hex.parse("FF11223344556677");
        Asserts.check(!ConstantTime.equals(a, (short) 0, firstDiff, (short) 0, (short) 8),
                "difference in the first byte");

        byte[] lastDiff = Hex.parse("00112233445566FF");
        Asserts.check(!ConstantTime.equals(a, (short) 0, lastDiff, (short) 0, (short) 8),
                "difference in the last byte");

        // A range with a non-zero offset on both sides.
        byte[] paddedA = Hex.parse("AA0011223344556677BB");
        byte[] paddedB = Hex.parse("CC0011223344556677DD");
        Asserts.check(ConstantTime.equals(paddedA, (short) 1, paddedB, (short) 1,
                        (short) 8), "equal ranges with offsets");
        Asserts.check(!ConstantTime.equals(paddedA, (short) 1, paddedB, (short) 2,
                        (short) 8), "misaligned ranges differ");

        // A single byte (the shortest comparison the card uses).
        Asserts.check(ConstantTime.equals(new byte[] { 0x5A }, (short) 0,
                        new byte[] { 0x5A }, (short) 0, (short) 1), "single equal byte");
        Asserts.check(!ConstantTime.equals(new byte[] { 0x5A }, (short) 0,
                        new byte[] { 0x5B }, (short) 0, (short) 1), "single differing byte");

        // A 16-byte AES MAC block with the difference in a middle byte: the loop
        // must not short-circuit on the first matching bytes
        // (docs/specs/common/cryptography.md §9).
        byte[] aesA = Hex.parse("000102030405060708090A0B0C0D0E0F");
        byte[] aesB = Hex.parse("000102030405060708FF0A0B0C0D0E0F");
        Asserts.check(!ConstantTime.equals(aesA, (short) 0, aesB, (short) 0, (short) 16),
                "difference in a middle byte of a 16-byte block");
        Asserts.check(ConstantTime.equals(aesA, (short) 0,
                        Hex.parse("000102030405060708090A0B0C0D0E0F"), (short) 0, (short) 16),
                "equal 16-byte block");
    }
}
