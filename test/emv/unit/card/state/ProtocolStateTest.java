package card42.test;

import card42.emv.EMVCodes;
import card42.emv.EMVRoles;
import card42.emv.EMVProtocolState;

/**
 * Pure-JVM tests for the persistent/volatile protocol state, in particular the
 * ATC accounting of EMV v4.4 Book 2 Annex D3: SELECT must not touch
 * the counter, a successful GET PROCESSING OPTIONS advances it once per session,
 * and reaching 0xFFFF invalidates the application without rolling over.
 *
 * The class runs on a plain JVM against the {@code javacard.framework.JCSystem}
 * stub in test/common/stubs.
 */
final class ProtocolStateTest {

    private ProtocolStateTest() {
    }

    static void run() {
        System.out.println("EMVProtocolState / ATC");

        EMVProtocolState s = new EMVProtocolState();
        Asserts.eq(0, s.getATC(), "fresh ATC is 0");
        Asserts.eq(EMVRoles.PERSONALISATION, s.getLifecycle(), "fresh lifecycle");

        // SELECT (startNewSession) must not change the ATC anymore
        // (EMV v4.4 Book 2 Annex D3).
        s.startNewSession();
        s.startNewSession();
        Asserts.eq(0, s.getATC(), "startNewSession does not advance the ATC");
        Asserts.check(!s.isGpoDone(), "fresh session has not done GPO");

        // A successful GPO sets gpoDone and advances the ATC by one.
        s.setGpoDone();
        s.advanceATC();
        Asserts.eq(1, s.getATC(), "advanceATC increments");
        Asserts.check(s.isGpoDone(), "GPO flag set");

        // A new session keeps the persistent ATC but clears the session flag.
        s.startNewSession();
        Asserts.check(!s.isGpoDone(), "startNewSession clears the GPO flag");
        Asserts.eq(1, s.getATC(), "ATC persists across sessions");

        // AC session flags are reset by startNewSession too.
        s.setFirstACGenerated(EMVCodes.ARQC);
        s.setSecondACGenerated(EMVCodes.TC);
        s.setCVMPerformed(EMVCodes.PLAINTEXT_PIN);
        s.startNewSession();
        Asserts.eq(EMVCodes.NONE, s.getFirstACGenerated(), "first AC reset");
        Asserts.eq(EMVCodes.NONE, s.getSecondACGenerated(), "second AC reset");
        Asserts.eq(EMVCodes.NONE, s.getCVMPerformed(), "CVM reset");

        // Reaching 0xFFFF invalidates the application and never rolls over.
        EMVProtocolState limit = new EMVProtocolState();
        for (int i = 0; i < 0xFFFF; i++) {
            limit.advanceATC();
        }
        Asserts.eq(0xFFFF, limit.getATC() & 0xFFFF, "ATC reaches 0xFFFF");
        Asserts.eq(EMVRoles.BLOCKED, limit.getLifecycle(), "0xFFFF invalidates");
        limit.advanceATC();
        Asserts.eq(0xFFFF, limit.getATC() & 0xFFFF, "no roll-over past 0xFFFF");
        Asserts.eq(EMVRoles.BLOCKED, limit.getLifecycle(), "stays invalidated");

        // The invalidated and CARD BLOCK lifecycles are distinct states.
        EMVProtocolState card = new EMVProtocolState();
        card.setLifecycle(EMVRoles.CARD_BLOCKED);
        Asserts.eq(EMVRoles.CARD_BLOCKED, card.getLifecycle(), "card blocked state");
        Asserts.check(EMVRoles.BLOCKED != EMVRoles.CARD_BLOCKED,
                "invalidated and card-blocked differ");

        // The PDOL session buffer is bounded; the GPO handler refuses an
        // over-long expansion with 6985 before copying (docs/specs/emv/transaction.md
        // §2).  The decision is exposed as pdolFits() so it is testable without
        // an APDU.
        EMVProtocolState pdol = new EMVProtocolState();
        Asserts.check(pdol.getPdolData() == null, "no PDOL buffer before GPO data");
        Asserts.check(pdol.pdolFits((short) 64), "a 64-byte PDOL expansion fits");
        Asserts.check(!pdol.pdolFits((short) 65), "a 65-byte PDOL expansion does not fit");
        Asserts.check(!pdol.pdolFits((short) -1), "a negative PDOL length does not fit");
        pdol.setPdolData(new byte[64], (short) 0, (short) 64);
        Asserts.eq(64, pdol.getPdolDataLength(), "setPdolData within the buffer");
        Asserts.eq(64, pdol.getPdolData().length, "PDOL buffer sized to the expansion");

        // A GPO without PDOL data keeps the transient buffer unallocated, so a
        // no-PDOL instance does not spend the shared transient budget
        // (docs/specs/common/risks.md).
        EMVProtocolState noPdol = new EMVProtocolState();
        noPdol.setPdolData(new byte[0], (short) 0, (short) 0);
        Asserts.eq(0, noPdol.getPdolDataLength(), "empty PDOL data accepted");
        Asserts.check(noPdol.getPdolData() == null, "empty PDOL data does not allocate");

        // A GET CHALLENGE challenge is valid only until the next command
        // (EMV v4.4 Book 3 §6.5.6.1): clearChallengeValid invalidates it.
        EMVProtocolState challenge = new EMVProtocolState();
        Asserts.check(!challenge.isChallengeValid(), "no challenge initially");
        challenge.setChallenge(new byte[8], (short) 0);
        Asserts.check(challenge.isChallengeValid(), "challenge valid after GET CHALLENGE");
        challenge.clearChallengeValid();
        Asserts.check(!challenge.isChallengeValid(), "challenge cleared after a command");

        // The persistent CVR flags survive a new session and are cleared only
        // by a successful issuer authentication (EMV v4.4 Book 3 §9.2.3.2).
        EMVProtocolState persistent = new EMVProtocolState();
        persistent.setScriptFailedPersistent(true);
        persistent.setLastOnlineNotCompleted(true);
        persistent.startNewSession();
        Asserts.check(persistent.isScriptFailedPersistent(), "script-failed bit persists");
        Asserts.check(persistent.isLastOnlineNotCompleted(), "last-online bit persists");
        persistent.issuerAuthSucceeded();
        Asserts.check(!persistent.isScriptFailedPersistent(),
                "issuer auth clears the script-failed bit");
        Asserts.check(!persistent.isLastOnlineNotCompleted(),
                "issuer auth clears the last-online bit");
    }
}
