package card42.host.emv.kernel.analysis;

import card42.host.common.util.Bcd;
import card42.host.emv.kernel.data.Tvr;

import java.util.Random;

/**
 * Terminal Risk Management (EMV v4.4 Book 3 §10.6): the terminal-side checks
 * that feed TVR byte 4 before Terminal Action Analysis.
 *
 * <p>The kernel performs floor limit checking, random selection, merchant
 * forced online and velocity checking.  Velocity checking (EMV v4.4 Book 3
 * §10.6.3) is driven by the card's Lower/Upper Consecutive Offline Limits
 * ('9F14'/'9F23') and the ATC / Last Online ATC Register read with GET DATA,
 * not by terminal-side accumulators.
 */
public final class TerminalRiskManagement {

    private TerminalRiskManagement() {
    }

    /**
     * Floor limit check (EMV v4.4 Book 3 §10.6.1): when the Amount, Authorised
     * is equal to or greater than the floor limit, the terminal sets
     * 'Transaction exceeds floor limit' so that Terminal Action Analysis sends
     * the transaction online.
     *
     * @return true when the floor limit was exceeded
     */
    public static boolean floorLimit(byte[] tvr, byte[] amount, long floorLimit) {
        long value = Bcd.bcdToLong(amount);
        boolean exceeded = value >= 0 && value >= floorLimit;
        if (exceeded) {
            Tvr.set(tvr, 3, Tvr.FLOOR_LIMIT_EXCEEDED);
        }
        return exceeded;
    }

    /**
     * Random transaction selection (EMV v4.4 Book 3 §10.6.2).  The terminal
     * generates a random number in the range 1 to 99 and selects the
     * transaction when it is less than or equal to the applicable target
     * percentage.  Below the Threshold Value the Target Percentage applies;
     * between the threshold and the floor limit the target is interpolated
     * linearly up to the Maximum Target Percentage (biased random selection).
     * At or above the floor limit random selection is not performed (the floor
     * limit check handles it).
     *
     * @param tvr              the TVR to update
     * @param random           the random source
     * @param amountMinorUnits the Amount, Authorised in minor units
     * @param targetPercent    Target Percentage for Random Selection (0-99)
     * @param threshold        Threshold Value for Biased Random Selection
     * @param maxTargetPercent Maximum Target Percentage for Biased Random
     *                         Selection (>= targetPercent)
     * @param floorLimit       the terminal floor limit in minor units
     * @return true when the transaction was selected
     */
    public static boolean randomSelection(byte[] tvr, Random random, long amountMinorUnits,
            int targetPercent, long threshold, int maxTargetPercent, long floorLimit) {
        if (amountMinorUnits >= floorLimit) {
            return false; // not applicable at or above the floor limit
        }
        int target = transactionTargetPercent(amountMinorUnits, targetPercent, threshold,
                maxTargetPercent, floorLimit);
        if (target <= 0) {
            return false;
        }
        int r = random.nextInt(99) + 1; // 1..99
        boolean selected = r <= target;
        if (selected) {
            Tvr.set(tvr, 3, Tvr.RANDOM_SELECTION);
        }
        return selected;
    }

    /**
     * The Transaction Target Percent for the biased random selection
     * (EMV v4.4 Book 3 §10.6.2): the Target Percentage for an amount below the
     * Threshold Value, otherwise the linear interpolation between the Target
     * Percentage and the Maximum Target Percentage over the range from the
     * threshold to the floor limit.
     */
    public static int transactionTargetPercent(long amountMinorUnits, int targetPercent, long threshold,
            int maxTargetPercent, long floorLimit) {
        if (floorLimit > threshold && amountMinorUnits >= threshold) {
            long span = floorLimit - threshold;
            long scaled = (long) (maxTargetPercent - targetPercent)
                    * (amountMinorUnits - threshold);
            return targetPercent + (int) (scaled / span);
        }
        return targetPercent;
    }

    /**
     * Merchant forced transaction online (EMV v4.4 Book 3 §10.6): sets
     * 'Merchant forced transaction online'.
     */
    public static void merchantForcedOnline(byte[] tvr, boolean forced) {
        if (forced) {
            Tvr.set(tvr, 3, Tvr.MERCHANT_FORCED_ONLINE);
        }
    }

    /**
     * Terminal velocity checking (EMV v4.4 Book 3 §10.6.3): compares the
     * difference between the ATC and the Last Online ATC Register with the
     * Lower/Upper Consecutive Offline Limits and sets TVR byte 4 b7 (lower) /
     * b6 (upper).  The difference equal to a limit means the limit is not
     * exceeded.  The 'New card' TVR bit is set when the Last Online ATC Register
     * is zero.  When either register is unavailable or ATC &le; Last Online ATC,
     * both limit bits are set and the check ends.
     *
     * @param atcPresent          the ATC ('9F36') was returned by GET DATA
     * @param lastOnlineAtcPresent the Last Online ATC Register ('9F13') was returned
     * @return true when a limit was exceeded
     */
    public static boolean velocityChecking(byte[] tvr, boolean atcPresent, int atc,
            boolean lastOnlineAtcPresent, int lastOnlineAtc, int lowerLimit, int upperLimit) {
        if (!atcPresent || !lastOnlineAtcPresent || atc <= lastOnlineAtc) {
            Tvr.set(tvr, 3, Tvr.LOWER_OFFLINE_LIMIT_EXCEEDED);
            Tvr.set(tvr, 3, Tvr.UPPER_OFFLINE_LIMIT_EXCEEDED);
            if (lastOnlineAtcPresent && lastOnlineAtc == 0) {
                // 'New card' is TVR byte 2 b4 (EMV v4.4 Book 3 Table 46).
                Tvr.set(tvr, 1, Tvr.NEW_CARD);
            }
            return true;
        }
        int difference = atc - lastOnlineAtc;
        boolean lowerExceeded = difference > lowerLimit;
        if (lowerExceeded) {
            Tvr.set(tvr, 3, Tvr.LOWER_OFFLINE_LIMIT_EXCEEDED);
            if (difference > upperLimit) {
                Tvr.set(tvr, 3, Tvr.UPPER_OFFLINE_LIMIT_EXCEEDED);
            }
        }
        if (lastOnlineAtc == 0) {
            // 'New card' is TVR byte 2 b4 (EMV v4.4 Book 3 Table 46).
            Tvr.set(tvr, 1, Tvr.NEW_CARD);
        }
        return lowerExceeded;
    }
}
