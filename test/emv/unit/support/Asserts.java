package card42.test;

import java.util.Arrays;

import javacard.framework.ISOException;
import card42.host.common.util.Hex;

/**
 * Assertion helpers shared by the pure-JVM unit suites (docs/specs/common/toolchain.md §6).
 * Split out of {@link UnitTests} so the runner stays a thin dispatcher and every
 * suite under tlv/ core/ host/ crypto/ reports through one counter.
 *
 * <p>The class is package-private on purpose: the suites are in package
 * {@code card42.test} (their directories are functional groupings, not packages,
 * matching the convention used by {@code src/}), so no suite needs to import it.
 */
final class Asserts {

    private static int checks;
    private static int failures;

    private Asserts() {
    }

    static int checks() {
        return checks;
    }

    static int failures() {
        return failures;
    }

    static void check(boolean ok, String what) {
        checks++;
        if (ok) {
            System.out.println("  ok   " + what);
        } else {
            failures++;
            System.out.println("  FAIL " + what);
        }
    }

    static void eq(long expected, long actual, String what) {
        check(expected == actual, what + " (expected " + expected + ", got " + actual + ")");
    }

    static void eq(String expected, String actual, String what) {
        check(expected.equals(actual), what + " (expected " + expected + ", got " + actual + ")");
    }

    static void bytes(byte[] expected, byte[] actual, String what) {
        check(Arrays.equals(expected, actual), what
                + " (expected " + Hex.format(expected)
                + ", got " + Hex.format(actual) + ")");
    }

    /** Asserts that action throws ISOException with the given status word. */
    static void sw(short expected, Runnable action, String what) {
        try {
            action.run();
            check(false, what + " did not throw");
        } catch (ISOException e) {
            check(e.getReason() == expected, what
                    + " (expected " + String.format("%04X", expected & 0xFFFF)
                    + ", got " + String.format("%04X", e.getReason() & 0xFFFF) + ")");
        }
    }

    /** Asserts that action completes without throwing. */
    static void noThrow(Runnable action, String what) {
        try {
            action.run();
            check(true, what);
        } catch (Exception e) {
            check(false, what + " threw " + e);
        }
    }

    /** Asserts that action throws (a rejected malformed or invalid input). */
    static void rejects(Runnable action, String what) {
        try {
            action.run();
            check(false, what + " did not throw");
        } catch (RuntimeException e) {
            check(true, what);
        }
    }

    /** Asserts that action throws an IOException. */
    static void throwsIo(IoAction action, String what) {
        try {
            action.run();
            check(false, what + " did not throw");
        } catch (java.io.IOException e) {
            check(true, what);
        }
    }

    /** A Runnable-like action that may throw IOException. */
    interface IoAction {
        void run() throws java.io.IOException;
    }
}
