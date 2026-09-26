package card42.test;

import card42.emv.OfflineRisk;

/**
 * Pure-JVM tests for the offline velocity-checking accumulators (EMV v4.4
 * EMV v4.4 Book 3 Annex C §C9.3): the consecutive offline transaction count (LCOL/UCOL), the
 * cumulative offline amount (LCOTA/UCOTA), the forced-online / decline
 * behaviour and the CSU 'Update Counters' handling.
 */
final class OfflineRiskTest {

    private OfflineRiskTest() {
    }

    /** A 6-byte BCD amount with value n (n &lt; 10^6). */
    private static byte[] amount(int n) {
        return bcd(n);
    }

    /** A full 6-byte BCD amount (up to 12 digits). */
    private static byte[] bcd(long n) {
        byte[] b = new byte[6];
        for (int i = 5; i >= 0 && n > 0; i--) {
            b[i] = (byte) ((int) (n % 100) / 10 << 4 | (int) (n % 10));
            n /= 100;
        }
        return b;
    }

    static void run() {
        System.out.println("OfflineRisk");

        // Count limits: LCOL=1, UCOL=3.
        OfflineRisk risk = new OfflineRisk();
        Asserts.check(!risk.isEnabled(), "no limits -> disabled");
        risk.setCountLimits((byte) 1, (byte) 3);
        Asserts.check(risk.isEnabled(), "count limits enable velocity checking");
        Asserts.check(!risk.forceOnline(), "fresh counters do not force online");

        risk.recordOffline(new byte[6], (short) 0, (short) 0);
        Asserts.check(risk.forceOnline(), "LCOL reached forces online");
        Asserts.check(!risk.upperExceeded(), "LCOL does not exceed UCOL yet");
        Asserts.eq(0x80, risk.cvrByte3() & 0xFF, "CVR byte 3 lower-count bit");

        risk.recordOffline(new byte[6], (short) 0, (short) 0);
        risk.recordOffline(new byte[6], (short) 0, (short) 0);
        Asserts.check(risk.upperExceeded(), "UCOL reached is an upper limit");
        Asserts.eq(0xC0, risk.cvrByte3() & 0xFF, "CVR byte 3 lower+upper-count bits");

        risk.recordOnline();
        Asserts.check(!risk.forceOnline(), "online transaction resets the counters");
        Asserts.eq(0, risk.cvrByte3() & 0xFF, "CVR byte 3 cleared after online");

        // Amount limits: LCOTA=100, UCOTA=1000.
        OfflineRisk amounts = new OfflineRisk();
        byte[] limits = new byte[12];
        System.arraycopy(amount(100), 0, limits, 0, 6);
        System.arraycopy(amount(1000), 0, limits, 6, 6);
        amounts.setAmountLimits(limits, (short) 0, (short) 12);

        byte[] a50 = amount(50);
        amounts.recordOffline(a50, (short) 0, (short) 6);
        Asserts.check(!amounts.forceOnline(), "50 below LCOTA=100");
        amounts.recordOffline(a50, (short) 0, (short) 6);
        Asserts.check(amounts.forceOnline(), "110 reaches LCOTA=100");
        Asserts.eq(0x20, amounts.cvrByte3() & 0xFF, "CVR byte 3 lower-amount bit");
        amounts.recordOffline(a50, (short) 0, (short) 6); // 160
        Asserts.check(!amounts.upperExceeded(), "160 below UCOTA=1000");
        amounts.recordOffline(amount(900), (short) 0, (short) 6); // 1060
        Asserts.check(amounts.upperExceeded(), "1060 reaches UCOTA=1000");
        Asserts.eq(0x30, amounts.cvrByte3() & 0xFF, "CVR byte 3 lower+upper-amount bits");

        // CSU 'Update Counters' bits.
        amounts.applyUpdateCounters((byte) 0x02, a50, (short) 0, (short) 6); // reset
        Asserts.check(!amounts.forceOnline(), "CSU reset clears the accumulators");
        amounts.applyUpdateCounters((byte) 0x01, a50, (short) 0, (short) 6); // set to upper
        Asserts.check(amounts.upperExceeded(), "CSU set-to-upper reaches UCOTA");
        amounts.applyUpdateCounters((byte) 0x00, a50, (short) 0, (short) 6); // no update
        Asserts.check(amounts.upperExceeded(), "CSU do-not-update keeps the state");
        amounts.applyUpdateCounters((byte) 0x03, a50, (short) 0, (short) 6); // add transaction
        Asserts.check(amounts.upperExceeded(), "CSU add transaction keeps the upper limit");

        // CSU byte 2 b3 'Created by Proxy for the Issuer': a proxy CSU must not
        // drive the offline counters (EMV v4.4 Book 3 §10.11.1.1).
        Asserts.check(OfflineRisk.updateCountersApply((byte) 0x00),
                "Update Counters apply without the proxy bit");
        Asserts.check(OfflineRisk.updateCountersApply((byte) 0x01),
                "Update Counters apply for b3=0 (set-to-upper)");
        Asserts.check(!OfflineRisk.updateCountersApply((byte) 0x04),
                "proxy bit suppresses Update Counters");
        Asserts.check(!OfflineRisk.updateCountersApply((byte) 0x05),
                "proxy bit suppresses Update Counters even with bits set");

        // 'Set Offline Counters to Upper Offline Limits' with UCOL=0 sets the
        // count to that (zero) upper limit (EMV v4.4 Book 3 §10.11.1.1).
        OfflineRisk zeroUcol = new OfflineRisk();
        zeroUcol.setCountLimits((byte) 1, (byte) 0);
        zeroUcol.recordOffline(new byte[6], (short) 0, (short) 0);
        Asserts.check(zeroUcol.forceOnline(), "offline count 1 reaches LCOL=1");
        zeroUcol.applyUpdateCounters((byte) 0x01, new byte[6], (short) 0, (short) 6);
        Asserts.check(!zeroUcol.forceOnline(),
                "CSU set-to-upper with UCOL=0 resets the count to 0");

        // Go-online-on-next-transaction and the ARC 'unable to go online' bits.
        OfflineRisk next = new OfflineRisk();
        Asserts.check(!next.forceOnline(), "no go-online flag");
        next.setGoOnlineNext();
        Asserts.check(next.forceOnline(), "go-online flag forces online");
        next.clearGoOnlineNext();
        Asserts.check(!next.forceOnline(), "go-online flag cleared");

        // 'Update Counters = Reset Offline Counters to Zero' must not clear the
        // independent 'Set Go Online on Next Transaction' flag
        // (EMV v4.4 Book 3 §10.11.1.1).
        OfflineRisk combined = new OfflineRisk();
        combined.setGoOnlineNext();
        combined.applyUpdateCounters((byte) 0x02, new byte[6], (short) 0, (short) 6);
        Asserts.check(combined.forceOnline(),
                "CSU reset does not clear Set Go Online on Next Transaction");
        Asserts.check(OfflineRisk.unableToGoOnline((byte) 0x59, (byte) 0x33),
                "ARC Y3 is unable to go online");
        Asserts.check(OfflineRisk.unableToGoOnline((byte) 0x5A, (byte) 0x33),
                "ARC Z3 is unable to go online");
        Asserts.check(!OfflineRisk.unableToGoOnline((byte) 0x59, (byte) 0x31),
                "ARC Y1 can go online");
        Asserts.check(!OfflineRisk.unableToGoOnline((byte) 0x5A, (byte) 0x31),
                "ARC Z1 can go online");
        Asserts.check(!OfflineRisk.unableToGoOnline((byte) 0x00, (byte) 0x00),
                "ARC 00 can go online");

        // LCOTA/UCOTA are BCD (EMV v4.4 Book 3 Annex C §C9.3): a non-digit
        // nibble is rejected with 6A80.
        OfflineRisk badBcd = new OfflineRisk();
        byte[] badLimits = new byte[12];
        badLimits[0] = (byte) 0x1A; // 'A' is not a decimal digit
        Asserts.sw((short) 0x6A80,
                () -> badBcd.setAmountLimits(badLimits, (short) 0, (short) 12),
                "non-BCD LCOTA -> 6A80");
        badLimits[0] = 0;
        badLimits[11] = (byte) 0xF0;
        Asserts.sw((short) 0x6A80,
                () -> badBcd.setAmountLimits(badLimits, (short) 0, (short) 12),
                "non-BCD UCOTA -> 6A80");

        // --- BCD addition boundaries (docs/specs/common/toolchain.md §6) ------------
        // Carry propagation across a decimal digit: 99 + 1 = 100.
        OfflineRisk carry = new OfflineRisk();
        byte[] carryLimits = new byte[12];
        System.arraycopy(bcd(150), 0, carryLimits, 0, 6); // LCOTA = 150
        carry.setAmountLimits(carryLimits, (short) 0, (short) 12);
        carry.recordOffline(bcd(99), (short) 0, (short) 6);
        Asserts.check(!carry.forceOnline(), "99 below LCOTA=150");
        carry.recordOffline(bcd(1), (short) 0, (short) 6); // 100
        Asserts.check(!carry.forceOnline(), "99+1 carried to 100");
        carry.recordOffline(bcd(50), (short) 0, (short) 6); // 150
        Asserts.check(carry.forceOnline(), "100+50 reaches LCOTA=150");

        // The 12-digit maximum is representable; one more wraps (the final
        // carry out of the most significant digit is dropped).
        OfflineRisk max = new OfflineRisk();
        byte[] maxLimits = new byte[12];
        System.arraycopy(bcd(999999999999L), 0, maxLimits, 0, 6); // LCOTA
        System.arraycopy(bcd(999999999999L), 0, maxLimits, 6, 6); // UCOTA
        max.setAmountLimits(maxLimits, (short) 0, (short) 12);
        max.recordOffline(bcd(999999999999L), (short) 0, (short) 6);
        Asserts.check(max.upperExceeded(), "12-digit maximum reaches UCOTA");
        max.recordOffline(bcd(1), (short) 0, (short) 6);
        Asserts.check(!max.forceOnline(), "overflow wraps the 12-digit amount to 0");
    }
}
