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
        if (decimals < 0 || decimals > 6) {
            throw new IllegalArgumentException("decimals must be 0..6: " + decimals);
        }
        String value = text == null ? "" : text.trim();
        if (value.startsWith("-")) {
            throw new IllegalArgumentException("amount must not be negative: " + text);
        }
        String[] parts = value.split("\\.", -1);
        if (parts.length > 2) {
            throw new IllegalArgumentException("not an amount: " + text);
        }
        long whole;
        try {
            whole = parts[0].isEmpty() ? 0 : Long.parseLong(parts[0]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("not an amount: " + text);
        }
        String fraction = parts.length == 2 ? parts[1] : "";
        if (fraction.length() > decimals) {
            throw new IllegalArgumentException("more than " + decimals + " decimals: " + text);
        }
        while (fraction.length() < decimals) {
            fraction = fraction + "0";
        }
        long valueMinor;
        try {
            valueMinor = Math.multiplyExact(whole, pow10(decimals));
            valueMinor = Math.addExact(valueMinor,
                    fraction.isEmpty() ? 0 : Long.parseLong(fraction));
        } catch (ArithmeticException | NumberFormatException e) {
            throw new IllegalArgumentException("amount out of range: " + text);
        }
        if (valueMinor > 999_999_999_999L) {
            throw new IllegalArgumentException("amount exceeds 6-byte BCD: " + text);
        }
        return valueMinor;
    }

    private static long pow10(int decimals) {
        long value = 1;
        for (int i = 0; i < decimals; i++) {
            value *= 10;
        }
        return value;
    }

    /** EMV numeric (n) encoding: left-pad the digits with zeroes to the byte length. */
    public static byte[] numeric(String digits, int bytes) {
        if (digits == null || digits.isEmpty()) {
            throw new IllegalArgumentException("numeric value is empty");
        }
        for (int i = 0; i < digits.length(); i++) {
            char c = digits.charAt(i);
            if (c < '0' || c > '9') {
                throw new IllegalArgumentException("numeric value is not decimal: " + digits);
            }
        }
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
