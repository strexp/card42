package card42.host.common.util;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * Hex and packed-BCD codecs shared by the host tooling and the tests.
 *
 * The host side has no on-card constraints, so parsing ignores separators and
 * formatting is upper-case Big-Endian.  The hex encode/decode itself is delegated
 * to the JDK {@link HexFormat}; only the separator-tolerant wrapper and the EMV
 * BCD encoders are kept here.  BCD follows the EMV convention: ASCII digits
 * packed two per byte, an odd count padded with 0xF.
 */
public final class Hex {

    /** Upper-case, no-delimiter formatter; {@code withUpperCase} does not affect parsing. */
    private static final HexFormat HEX = HexFormat.of().withUpperCase();

    private Hex() {
    }

    /** Parses a hex string, ignoring separators. */
    public static byte[] parse(String s) {
        String clean = s.replaceAll("[^0-9A-Fa-f]", "");
        if ((clean.length() & 1) != 0) {
            throw new IllegalArgumentException("Odd-length hex string: " + s);
        }
        return HEX.parseHex(clean);
    }

    /** Formats bytes as upper-case hex. */
    public static String format(byte[] b) {
        return HEX.formatHex(b);
    }

    /** Converts ASCII digits to packed BCD, padding an odd count with 0xF. */
    public static byte[] bcd(String digits) {
        int n = digits.length();
        byte[] out = new byte[(n + 1) / 2];
        for (int i = 0; i < n; i += 2) {
            int hi = digits.charAt(i) - '0';
            int lo = (i + 1 < n) ? digits.charAt(i + 1) - '0' : 0x0F;
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /** Builds an 8-byte ISO 9564-1 format 1 Reference PIN Block. */
    public static byte[] iso9564Format1(String digits) {
        return Iso9564.format1(digits);
    }

}
