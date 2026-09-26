package card42.test;

import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.entry.Combination;
import card42.host.emv.kernel.entry.CombinationTable;
import card42.host.emv.kernel.entry.EntryPointConfiguration;
import card42.host.emv.kernel.entry.PreProcessingIndicators;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for the Entry Point configuration layer
 * (EMV Contactless Book A v2.12 Table 5-1/5-2/5-3): the Combination Table, the
 * Entry Point Configuration Data derived from the terminal and the Start A/B
 * Pre-Processing Indicators.
 */
final class EntryPointConfigTest {

    private EntryPointConfigTest() {
    }

    static void run() {
        System.out.println("EntryPointConfig");

        // --- Combination Table (Book A Table 5-1/5-6) -----------------------
        CombinationTable defaults = CombinationTable.defaults("A0000000031010", "43415244420102");
        Asserts.eq(2, defaults.forType(CombinationTable.PURCHASE).size(),
                "default table offers both AIDs for a purchase");
        Asserts.eq(2, defaults.forType(CombinationTable.CASH).size(),
                "default table offers both AIDs for cash");
        Asserts.eq(0, defaults.forType(CombinationTable.PURCHASE).get(0).kernelId,
                "Visa combination carries the reader's implemented kernel 0, not the brand default 3");
        Asserts.eq(0, defaults.forType(CombinationTable.PURCHASE).get(1).kernelId,
                "unknown AID combination carries kernel 0");
        Asserts.check(!defaults.isEmpty(), "default table is not empty");

        // A table with a purchase combination only has no cash combination, so
        // the Candidate List for cash is empty (Contactless Application Not
        // Allowed, Book A Table 5-3).
        CombinationTable purchaseOnly = new CombinationTable();
        purchaseOnly.add(CombinationTable.PURCHASE,
                new Combination("A0000000031010", 3));
        Asserts.eq(1, purchaseOnly.forType(CombinationTable.PURCHASE).size(),
                "purchase combination present");
        Asserts.check(purchaseOnly.forType(CombinationTable.CASH).isEmpty(),
                "no cash combination");
        Asserts.check(new CombinationTable().forType(CombinationTable.PURCHASE).isEmpty(),
                "empty table has no combination");
        Asserts.check(new CombinationTable().isEmpty(), "empty table reports empty");

        // --- Entry Point Configuration from the terminal config (Table 5-2) --
        TerminalConfig data = TerminalConfig.forContact()
                .floorLimit(1000)
                .cvmRequiredLimit(500)
                .ttq(Hex.parse("AA40CCDD")) // byte 2 b7 set, to exercise the reset
                .build();
        EntryPointConfiguration config = EntryPointConfiguration.from(data);
        Asserts.eq(1000, config.terminalFloorLimit, "terminal floor limit from the terminal");
        Asserts.check(config.terminalFloorLimitPresent, "terminal floor limit present");
        Asserts.eq(500, config.readerCvmRequiredLimit, "reader CVM required limit from the terminal");
        Asserts.check(config.readerCvmRequiredLimitPresent, "CVM required limit present");
        Asserts.bytes(Hex.parse("AA40CCDD"), config.ttq, "TTQ copied from the terminal");
        Asserts.check(config.zeroAmountAllowed, "zero amount allowed by default");
        Asserts.check(!config.statusCheckSupport, "status check off by default");

        // --- Pre-Processing Indicators Start A (Table 5-3) ------------------
        config.statusCheckSupport = true;
        config.readerContactlessFloorLimitPresent = true;
        config.readerContactlessFloorLimit = 100;
        config.readerCvmRequiredLimit = 50;
        PreProcessingIndicators p = PreProcessingIndicators.startA(config, 0, false);
        // A zero amount is not a single unit of currency, so no Status Check is
        // requested even though Status Check Support is set (Book B §3.1.1.3).
        Asserts.check(!p.statusCheckRequested, "zero amount does not request a status check");
        Asserts.check(!p.contactlessApplicationNotAllowed, "application allowed");
        // 'Zero Amount for Offline Allowed' is set, so 3.1.1.4 skips the Zero
        // Amount indicator (Book B §3.1.1.4).
        Asserts.check(!p.zeroAmount, "zero amount skipped when offline allowed");
        Asserts.check(!p.readerCvmRequiredLimitExceeded, "zero is under the CVM limit");
        Asserts.check(!p.readerContactlessFloorLimitExceeded, "zero is under the floor limit");
        // Copy of TTQ byte 2 b8/b7 reset; no Status Check and no floor/CVM
        // indicator, so both stay clear (Book B §3.1.1.2): 40 -> 00.
        Asserts.bytes(Hex.parse("AA00CCDD"), p.ttq, "TTQ copy reset without a status check");

        // A single unit of currency (100 minor units = EUR 1.00) with Status
        // Check Support set requests the status check (Book B §3.1.1.3); the
        // amount is over the CVM limit but not over the floor limit.
        p = PreProcessingIndicators.startA(config, 100, false);
        Asserts.check(p.statusCheckRequested, "single unit of currency requests a status check");
        Asserts.check(!p.readerContactlessFloorLimitExceeded,
                "single unit is not over the floor limit");
        Asserts.check(p.readerCvmRequiredLimitExceeded, "single unit is over the CVM limit");
        // Status Check sets b8 and the CVM indicator sets b7: 40 -> 00 -> C0.
        Asserts.bytes(Hex.parse("AAC0CCDD"), p.ttq, "status check + CVM set in the TTQ copy");

        // Any other amount is not a single unit of currency, so it does not
        // request a status check by itself.
        p = PreProcessingIndicators.startA(config, 200, false);
        Asserts.check(!p.statusCheckRequested, "non-single-unit amount does not request a status check");

        p = PreProcessingIndicators.startA(config, 1000, true);
        Asserts.check(!p.zeroAmount, "non-zero amount");
        Asserts.check(p.contactlessApplicationNotAllowed, "no combination indicator");
        Asserts.check(p.readerCvmRequiredLimitExceeded, "amount over the CVM limit");
        Asserts.check(p.readerContactlessFloorLimitExceeded, "amount over the floor limit");
        // Floor-limit-exceeded sets b8, CVM sets b7.
        Asserts.bytes(Hex.parse("AAC0CCDD"), p.ttq, "TTQ copy reflects floor/CVM indicators");

        // A disallowed zero amount forbids the application (Book B §3.1.1.4).
        config.zeroAmountOfflineAllowed = false;
        config.zeroAmountAllowed = false;
        p = PreProcessingIndicators.startA(config, 0, false);
        Asserts.check(!p.zeroAmount, "zero amount not set when disallowed");
        Asserts.check(p.contactlessApplicationNotAllowed,
                "disallowed zero amount sets Contactless Application Not Allowed");
        // Allowed zero amount (offline not allowed) sets the Zero Amount indicator.
        config.zeroAmountAllowed = true;
        p = PreProcessingIndicators.startA(config, 0, false);
        Asserts.check(p.zeroAmount, "allowed zero amount sets the Zero Amount indicator");

        // The same allowed zero amount at an offline-only reader (TTQ byte 1
        // b4 set, Book A Table 5-4) cannot be handled offline, so the
        // application is not allowed although the Zero Amount indicator is set
        // (Book B §3.1.1.4).
        byte[] savedTtq = config.ttq;
        config.ttq = Hex.parse("AA48CCDD"); // byte 1 b4 (offline-only reader) set
        p = PreProcessingIndicators.startA(config, 0, false);
        Asserts.check(p.zeroAmount, "offline-only zero amount still sets the indicator");
        Asserts.check(p.contactlessApplicationNotAllowed,
                "offline-only reader forbids a zero amount");
        config.ttq = savedTtq;

        // The Reader CVM Required Limit is inclusive (greater than or equal);
        // the Reader Contactless Floor Limit is exclusive (strictly greater)
        // (Book B §3.1.1.6/§3.1.1.8).
        config.zeroAmountOfflineAllowed = true;
        p = PreProcessingIndicators.startA(config, 50, false);
        Asserts.check(p.readerCvmRequiredLimitExceeded,
                "amount equal to the CVM limit is exceeded");
        p = PreProcessingIndicators.startA(config, 100, false);
        Asserts.check(!p.readerContactlessFloorLimitExceeded,
                "amount equal to the floor limit is not exceeded");

        // The Reader Contactless Transaction Limit is inclusive and forbids the
        // application (Book B §3.1.1.5).
        config.readerContactlessTransactionLimitPresent = true;
        config.readerContactlessTransactionLimit = 2000;
        p = PreProcessingIndicators.startA(config, 2000, false);
        Asserts.check(p.contactlessApplicationNotAllowed,
                "amount equal to the transaction limit is not allowed");

        // The Terminal Floor Limit ('9F1B') is the fallback when the Reader
        // Contactless Floor Limit is not present (Book B §3.1.1.7).
        config.readerContactlessFloorLimitPresent = false;
        config.terminalFloorLimitPresent = true;
        config.terminalFloorLimit = 300;
        p = PreProcessingIndicators.startA(config, 301, false);
        Asserts.check(p.readerContactlessFloorLimitExceeded,
                "amount over the terminal floor limit exceeds");

        // --- Pre-Processing Indicators Start B (fixed values) ---------------
        PreProcessingIndicators b = PreProcessingIndicators.startB(config);
        Asserts.check(!b.statusCheckRequested && !b.contactlessApplicationNotAllowed
                && !b.zeroAmount && !b.readerCvmRequiredLimitExceeded
                && !b.readerContactlessFloorLimitExceeded, "Start B indicators are clear");
        // The Start B Copy of TTQ also resets byte 2 b8/b7.
        Asserts.bytes(Hex.parse("AA00CCDD"), b.ttq, "Start B resets the TTQ copy");

        // --- Per-Combination Entry Point Configuration (C13, Table 5-2) -----
        EntryPointConfiguration comboConfig = new EntryPointConfiguration();
        comboConfig.statusCheckSupport = true;
        Combination withConfig = new Combination("43415244420102", 0, comboConfig);
        Asserts.check(withConfig.config == comboConfig, "Combination carries its config");
        CombinationTable perCombo = new CombinationTable().withDefaultConfig(config);
        Asserts.check(perCombo.configFor(withConfig) == comboConfig,
                "configFor prefers the Combination config");
        Asserts.check(perCombo.configFor(new Combination("43415244420102", 0)) == config,
                "configFor falls back to the table default");
        Asserts.check(new CombinationTable().configFor(new Combination("43415244420102", 0)) == null,
                "configFor is null without a config");

        // Reader parameters reported on the final Outcome (Table 6-2).
        Asserts.check(!config.autorun, "autorun off by default");
        Asserts.check(!config.tryAgainOnDecline, "try again on decline off by default");
        Asserts.eq(0, config.fieldOffRequest, "no field off request by default");
        Asserts.eq(0, config.removalTimeout, "no removal timeout by default");
    }
}
