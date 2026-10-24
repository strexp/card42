package card42.host.emrtd.lds.common;

/**
 * The ICAO 7-3-1 check digit over an MRZ field (ICAO Doc 9303-3 §4.9,
 * Doc 9303-4 §4.9).
 *
 * <p>It lives in the LDS package so the MRZ/DG1 and Visa MRV parsers do not
 * depend on the access-layer BAC helper.  {@code MrzKeySeed.checkDigit} keeps
 * its public signature and delegates here.
 */
public final class MrzCheckDigit {

    private static final int[] WEIGHTS = { 7, 3, 1 };

    private MrzCheckDigit() {
    }

    /** Computes the check digit of {@code field}; '&lt;' and unknown characters count as 0. */
    public static int compute(String field) {
        if (field == null) {
            return 0;
        }
        int sum = 0;
        for (int i = 0; i < field.length(); i++) {
            sum += value(field.charAt(i)) * WEIGHTS[i % 3];
        }
        return sum % 10;
    }

    /** The 7-3-1 weight of one character: digits, then A=10..Z=35, '&lt;'=0. */
    public static int value(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'A' && c <= 'Z') {
            return c - 'A' + 10;
        }
        return 0;
    }

    /** True when {@code expected} is a decimal digit equal to the computed check digit. */
    public static boolean matches(String field, char expected) {
        return expected >= '0' && expected <= '9' && compute(field) == expected - '0';
    }
}
