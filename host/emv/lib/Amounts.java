package card42.host.emv.lib;

import card42.host.common.util.Hex;

/**
 * Amount parsing and EMV numeric (n) encoding helpers used by the terminal
 * commands (EMV v4.4 Book 3 §4.3).
 */
public final class Amounts {

    private Amounts() {
    }

    /** Parses a decimal amount into minor units (e.g. "12.34" with 2 decimals = 1234). */
    public static long amount(String text, int decimals) {
        String[] parts = text.trim().split("\\.", -1);
        if (parts.length > 2) {
            throw new IllegalArgumentException("not an amount: " + text);
        }
        long whole = parts[0].isEmpty() ? 0 : Long.parseLong(parts[0]);
        String fraction = parts.length == 2 ? parts[1] : "";
        if (fraction.length() > decimals) {
            throw new IllegalArgumentException("more than " + decimals + " decimals: " + text);
        }
        while (fraction.length() < decimals) {
            fraction = fraction + "0";
        }
        long value = whole;
        for (int i = 0; i < decimals; i++) {
            value *= 10;
        }
        return value + (fraction.isEmpty() ? 0 : Long.parseLong(fraction));
    }

    /** EMV numeric (n) encoding: left-pad the digits with zeroes to the byte length. */
    public static byte[] numeric(String digits, int bytes) {
        if (digits.length() > bytes * 2) {
            throw new IllegalArgumentException("value too long for " + bytes + " bytes: " + digits);
        }
        StringBuilder padded = new StringBuilder(digits);
        while (padded.length() < bytes * 2) {
            padded.insert(0, '0');
        }
        return Hex.bcd(padded.toString());
    }
}
