package card42.host.common.util;

/**
 * Binary-coded-decimal amount helpers for EMV numeric (n) data objects
 * (EMV v4.4 Book 3 §4.3).  These carry no terminal state and are used by the
 * terminal data model and the DOL builder.
 */
public final class Bcd {

    private Bcd() {
    }

    /**
     * Decodes a BCD amount (EMV numeric format, 0-6 bytes) into a long in minor
     * units; a non-BCD nibble fails the comparison by returning -1.
     */
    public static long bcdToLong(byte[] bcd) {
        if (bcd == null) {
            return -1;
        }
        long value = 0;
        for (byte b : bcd) {
            int hi = (b >> 4) & 0x0F;
            int lo = b & 0x0F;
            if (hi > 9 || lo > 9) {
                return -1;
            }
            value = value * 100 + hi * 10 + lo;
        }
        return value;
    }

    /** Encodes a long in minor units as a BCD amount of the given byte length. */
    public static byte[] longToBcd(long value, int length) {
        byte[] out = new byte[length];
        for (int i = length - 1; i >= 0 && value > 0; i--) {
            out[i] = (byte) (((value % 100) / 10 << 4) | (value % 10));
            value /= 100;
        }
        return out;
    }
}
