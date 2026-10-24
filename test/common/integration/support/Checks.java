package card42.test;

import java.util.Arrays;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.util.Hex;

/**
 * Pass/fail bookkeeping for the integration test suites.
 *
 * <p>Every check prints one line and increments a single process-wide failure
 * counter; the entry point exits non-zero when any check failed.  This is test
 * infrastructure: the host library itself reports through
 * {@link card42.host.common.util.Reporter} and returns result objects.
 */
public final class Checks {

    private static int failures = 0;

    private Checks() {
    }

    public static int failures() {
        return failures;
    }

    /** Records a failure with a free-form message. */
    public static void fail(String message) {
        failures++;
        System.out.println("  FAIL " + message);
    }

    /** Compares a status word against the expected one. */
    public static void check(String what, int actual, int expected) {
        if (actual == expected) {
            System.out.println("  OK   " + what + " -> " + sw(actual));
        } else {
            failures++;
            System.out.println("  FAIL " + what + " -> " + sw(actual)
                    + " (expected " + sw(expected) + ")");
        }
    }

    /** Records a boolean check; r supplies the status word for the report. */
    public static void check(String name, boolean ok, ResponseAPDU r) {
        System.out.printf("[%s] %s (SW=%s)%n", ok ? "PASS" : "FAIL", name, sw(r.getSW()));
        if (!ok) {
            failures++;
        }
    }

    /** Records a boolean check without a status word. */
    public static void check(String name, boolean ok) {
        System.out.printf("[%s] %s%n", ok ? "PASS" : "FAIL", name);
        if (!ok) {
            failures++;
        }
    }

    /** Compares two byte arrays and records the result. */
    public static void bytes(byte[] expected, byte[] actual, String what) {
        boolean ok = Arrays.equals(expected, actual);
        System.out.printf("[%s] %s (expected %s, got %s)%n", ok ? "PASS" : "FAIL", what,
                Hex.format(expected), Hex.format(actual));
        if (!ok) {
            failures++;
        }
    }

    public static String sw(int sw) {
        return String.format("%04X", sw & 0xFFFF);
    }
}
