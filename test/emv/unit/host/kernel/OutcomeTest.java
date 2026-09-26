package card42.test;

import card42.host.emv.kernel.core.Outcome;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for the kernel Outcome model
 * (EMV Contactless Book A v2.12 Table 6-2/6-3): the mapping from the
 * media-neutral transaction result and the Final Outcome factories.
 */
final class OutcomeTest {

    private OutcomeTest() {
    }

    static void run() {
        System.out.println("Outcome");

        TransactionResult.Mutable result = new TransactionResult.Mutable();
        Outcome outcome = Outcome.from(result);
        Asserts.eq(Outcome.APPROVE, outcome.finalOutcome, "approved transaction");
        Asserts.check(!outcome.restart, "approve does not restart");
        Asserts.check(!outcome.uiRequestOnOutcomePresent, "approve has no UI request");

        result.declined(true);
        outcome = Outcome.from(result);
        Asserts.eq(Outcome.DECLINE, outcome.finalOutcome, "declined transaction");

        result.declined(false);
        result.serviceNotAllowed(true);
        outcome = Outcome.from(result);
        Asserts.eq(Outcome.END_APPLICATION, outcome.finalOutcome,
                "service not allowed ends the application");
        Asserts.check(outcome.uiRequestOnOutcomePresent, "end application has a UI request");
        Asserts.eq(0x1C, outcome.messageIdentifier, "end application UI request '1C'");

        // The online response data is carried when the issuer returned '91'.
        result.serviceNotAllowed(false);
        result.issuerAuthData(new byte[] { (byte) 0xAA, (byte) 0xBB });
        outcome = Outcome.from(result);
        Asserts.bytes(new byte[] { (byte) 0xAA, (byte) 0xBB }, outcome.onlineResponseData,
                "online response data carried");

        Outcome end = Outcome.endApplication(0x1C);
        Asserts.eq(Outcome.END_APPLICATION, end.finalOutcome, "endApplication final outcome");
        Asserts.check(end.uiRequestOnOutcomePresent, "endApplication UI request present");
        Outcome next = Outcome.selectNext();
        Asserts.eq(Outcome.SELECT_NEXT, next.finalOutcome, "selectNext final outcome");
        Asserts.check(next.restart, "selectNext requests a restart");

        // --- Table 6-2 fields derived from the transaction (C12) -------------
        TransactionResult.Mutable full = new TransactionResult.Mutable();
        full.aidHex("43415244420102");
        full.putRecord((1 << 8) | 1, Hex.parse("7000"));
        full.fci(Hex.parse("6F 05 A5 03 BF0C 00")); // BF0C present
        outcome = Outcome.from(full);
        Asserts.eq("43415244420102", outcome.adfName, "Final Outcome ADF Name carried");
        Asserts.check(outcome.dataRecordPresent, "data record present");
        Asserts.check(outcome.discretionaryDataPresent, "discretionary data present");
        Asserts.check(outcome.receipt, "approved transaction requests a receipt");
        Asserts.eq(Outcome.START_A, outcome.start, "default Start A");
        Asserts.check(!outcome.alternateInterfacePreference,
                "no alternate interface preference");

        full.declined(true);
        Asserts.check(!Outcome.from(full).receipt, "declined transaction has no receipt");

        // --- Try Again Final Outcome (Table 6-3/6-4, C15) -------------------
        Outcome again = Outcome.tryAgain(0);
        Asserts.eq(Outcome.TRY_AGAIN, again.finalOutcome, "tryAgain final outcome");
        Asserts.check(again.restart, "tryAgain restarts");
        Asserts.check(!again.uiRequestOnRestartPresent, "tryAgain without a UI request");
        Outcome againUi = Outcome.tryAgain(0x1C);
        Asserts.check(againUi.uiRequestOnRestartPresent, "tryAgain UI request on restart");
        Asserts.eq(0x1C, againUi.messageIdentifier, "tryAgain UI request identifier");

        // --- Unified decision (contact Book 4 §6.3.2 / Book A Table 6-1) -----
        TransactionResult.Mutable approve = new TransactionResult.Mutable();
        Asserts.check(TransactionResult.Decision.APPROVE == approve.decision(),
                "contact approval decision");
        approve.declined(true);
        Asserts.check(TransactionResult.Decision.DECLINE == approve.decision(),
                "contact decline decision");
        approve.declined(false).serviceNotAllowed(true);
        Asserts.check(TransactionResult.Decision.END_APPLICATION == approve.decision(),
                "service not allowed ends the application");
        // The contactless Outcome takes precedence when present.
        approve.serviceNotAllowed(false).outcome(Outcome.endApplication(0x1C));
        Asserts.check(TransactionResult.Decision.END_APPLICATION == approve.decision(),
                "outcome end application maps to the end-application decision");
        approve.outcome(Outcome.tryAnotherInterface());
        Asserts.check(TransactionResult.Decision.END_APPLICATION == approve.decision(),
                "try another interface maps to the end-application decision");
        Outcome online = new Outcome();
        online.finalOutcome = Outcome.ONLINE_REQUEST;
        approve.outcome(online);
        Asserts.check(TransactionResult.Decision.ONLINE == approve.decision(),
                "online request maps to the online decision");
    }
}
