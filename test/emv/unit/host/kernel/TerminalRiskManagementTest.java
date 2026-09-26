package card42.test;

import java.util.Random;
import card42.host.common.util.Hex;
import card42.host.emv.kernel.analysis.TerminalRiskManagement;
import card42.host.emv.kernel.data.Tvr;

/**
 * Unit tests for {@link TerminalRiskManagement} (EMV v4.4 Book 3 §10.6).
 */
final class TerminalRiskManagementTest {

    private TerminalRiskManagementTest() {
    }

    /** A {@link Random} whose {@code nextInt} always returns a fixed value. */
    private static final class FixedRandom extends Random {
        private final int value;

        FixedRandom(int value) {
            this.value = value;
        }

        @Override
        public int nextInt(int bound) {
            return value;
        }
    }

    static void run() {
        System.out.println("TerminalRiskManagementTest");

        // Floor limit: equal to the limit counts as exceeded (EMV v4.4 Book 3 §10.6.1).
        byte[] tvr = Tvr.blank();
        Asserts.check(TerminalRiskManagement.floorLimit(
                tvr, Hex.parse("000000001000"), 1000),
                "amount equal to the floor limit is exceeded");
        Asserts.check(Tvr.isSet(tvr, 3, Tvr.FLOOR_LIMIT_EXCEEDED),
                "floor limit sets TVR byte 4 b8");

        // Random selection: R in 1..99, selected when R <= target (EMV v4.4 Book 3
        // §10.6.2).  FixedRandom(41) yields R = 42.
        tvr = Tvr.blank();
        Asserts.check(TerminalRiskManagement.randomSelection(tvr, new FixedRandom(41), 500,
                42, 0, 42, 10000), "R = 42 <= target 42 selects");
        Asserts.check(Tvr.isSet(tvr, 3, Tvr.RANDOM_SELECTION),
                "selection sets TVR byte 4 b5");
        tvr = Tvr.blank();
        Asserts.check(!TerminalRiskManagement.randomSelection(tvr, new FixedRandom(41), 500,
                41, 0, 41, 10000), "R = 42 > target 41 does not select");
        Asserts.check(!Tvr.isSet(tvr, 3, Tvr.RANDOM_SELECTION),
                "no selection leaves the TVR bit clear");
        // Target 0 never selects.
        tvr = Tvr.blank();
        Asserts.check(!TerminalRiskManagement.randomSelection(tvr, new FixedRandom(0), 500,
                0, 0, 0, 10000), "target 0 never selects");
        // At or above the floor limit random selection is not performed.
        tvr = Tvr.blank();
        Asserts.check(!TerminalRiskManagement.randomSelection(tvr, new FixedRandom(0), 10000,
                99, 0, 99, 10000), "at the floor limit random selection is skipped");

        // Biased random selection: target 10, max 90, threshold 1000, floor
        // 10000.  Amount 5500 is halfway -> transaction target percent 50.
        Asserts.eq(50L, TerminalRiskManagement.transactionTargetPercent(
                5500, 10, 1000, 90, 10000), "biased target interpolates linearly");
        Asserts.eq(10L, TerminalRiskManagement.transactionTargetPercent(
                500, 10, 1000, 90, 10000), "below the threshold uses the base target");
        tvr = Tvr.blank();
        Asserts.check(TerminalRiskManagement.randomSelection(tvr, new FixedRandom(49), 5500,
                10, 1000, 90, 10000), "biased R = 50 <= target 50 selects");
        tvr = Tvr.blank();
        Asserts.check(!TerminalRiskManagement.randomSelection(tvr, new FixedRandom(50), 5500,
                10, 1000, 90, 10000), "biased R = 51 > target 50 does not select");

        // Merchant forced transaction online (EMV v4.4 Book 3 §10.6).
        tvr = Tvr.blank();
        TerminalRiskManagement.merchantForcedOnline(tvr, true);
        Asserts.check(Tvr.isSet(tvr, 3, Tvr.MERCHANT_FORCED_ONLINE),
                "merchant forces the transaction online");

        // Terminal velocity checking (EMV v4.4 Book 3 §10.6.3): the difference
        // between the ATC and the Last Online ATC Register is compared with the
        // Lower/Upper Consecutive Offline Limits; a difference equal to a limit
        // is not exceeded, and Last Online ATC = 0 sets 'New card'.
        tvr = Tvr.blank();
        Asserts.check(!TerminalRiskManagement.velocityChecking(tvr, true, 15, true, 10, 5, 10),
                "ATC - Last Online ATC equal to LCOL is not exceeded");
        Asserts.check(!Tvr.isSet(tvr, 3, Tvr.LOWER_OFFLINE_LIMIT_EXCEEDED),
                "equal difference leaves the lower bit clear");
        Asserts.check(!Tvr.isSet(tvr, 1, Tvr.NEW_CARD),
                "non-zero Last Online ATC clears New card");

        tvr = Tvr.blank();
        Asserts.check(TerminalRiskManagement.velocityChecking(tvr, true, 16, true, 10, 5, 10),
                "difference over LCOL is exceeded");
        Asserts.check(Tvr.isSet(tvr, 3, Tvr.LOWER_OFFLINE_LIMIT_EXCEEDED),
                "difference over LCOL sets the lower bit");
        Asserts.check(!Tvr.isSet(tvr, 3, Tvr.UPPER_OFFLINE_LIMIT_EXCEEDED),
                "difference under UCOL leaves the upper bit clear");

        tvr = Tvr.blank();
        Asserts.check(TerminalRiskManagement.velocityChecking(tvr, true, 21, true, 10, 5, 10),
                "difference over UCOL is exceeded");
        Asserts.check(Tvr.isSet(tvr, 3, Tvr.UPPER_OFFLINE_LIMIT_EXCEEDED),
                "difference over UCOL sets the upper bit");

        // A zero Last Online ATC Register sets the 'New card' TVR bit.
        tvr = Tvr.blank();
        TerminalRiskManagement.velocityChecking(tvr, true, 1, true, 0, 5, 10);
        Asserts.check(Tvr.isSet(tvr, 1, Tvr.NEW_CARD),
                "zero Last Online ATC sets New card");

        // ATC <= Last Online ATC, or a register not returned by GET DATA, sets
        // both limit bits and ends velocity checking.
        tvr = Tvr.blank();
        Asserts.check(TerminalRiskManagement.velocityChecking(tvr, true, 10, true, 10, 5, 10),
                "ATC equal to Last Online ATC sets both limits");
        Asserts.check(Tvr.isSet(tvr, 3, Tvr.LOWER_OFFLINE_LIMIT_EXCEEDED)
                && Tvr.isSet(tvr, 3, Tvr.UPPER_OFFLINE_LIMIT_EXCEEDED),
                "ATC equal to Last Online ATC sets lower and upper");
        tvr = Tvr.blank();
        Asserts.check(TerminalRiskManagement.velocityChecking(tvr, false, 0, true, 10, 5, 10),
                "missing ATC sets both limits");
        Asserts.check(Tvr.isSet(tvr, 3, Tvr.LOWER_OFFLINE_LIMIT_EXCEEDED)
                && Tvr.isSet(tvr, 3, Tvr.UPPER_OFFLINE_LIMIT_EXCEEDED),
                "missing ATC sets lower and upper");

        // A missing Last Online ATC Register does not set 'New card'.
        tvr = Tvr.blank();
        TerminalRiskManagement.velocityChecking(tvr, true, 10, false, 0, 5, 10);
        Asserts.check(!Tvr.isSet(tvr, 1, Tvr.NEW_CARD),
                "missing Last Online ATC does not set New card");

        // ATC <= Last Online ATC with a zero register still sets 'New card'.
        tvr = Tvr.blank();
        TerminalRiskManagement.velocityChecking(tvr, true, 0, true, 0, 5, 10);
        Asserts.check(Tvr.isSet(tvr, 1, Tvr.NEW_CARD),
                "ATC <= Last Online ATC with a zero register sets New card");
    }
}
