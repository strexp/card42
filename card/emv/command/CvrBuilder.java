package card42.emv;

import card42.common.*;


/* Builds the Card Verification Results of the current transaction and writes
 * them into the IAD (bytes 4-8) before the Application Cryptogram is computed
 * (EMV v4.4 Book 3 Annex C §C9.3).  The AC input, the GENERATE AC response and
 * the transaction log therefore all carry the same 9F10.
 *
 * Extracted from AcProcessor so that the CVR aggregation (protocol state,
 * offline-risk accumulators, offline PIN and secure-messaging state) is
 * independent of the GENERATE AC command handling.
 *
 * @author card42
 */

public class CvrBuilder {

    private final EMVProtocolState protocolState;
    private final EMVStaticData staticData;
    private final OfflineRisk offlineRisk;
    private final SecureMessaging secureMessaging;
    private final OfflinePinState pin;

    /** Card Verification Results scratch. */
    private final byte[] cvr;

    public CvrBuilder(EMVProtocolState protocolState, EMVStaticData staticData,
            OfflineRisk offlineRisk, SecureMessaging secureMessaging, OfflinePinState pin) {
        this.protocolState = protocolState;
        this.staticData = staticData;
        this.offlineRisk = offlineRisk;
        this.secureMessaging = secureMessaging;
        this.pin = pin;
        EmvScratch.init();
        cvr = EmvScratch.cvr;
    }

    /**
     * Aggregates the Card Verification Results of the transaction (EMV v4.4
     * Book 3 Annex C §C9.3) from the protocol state, the offline risk
     * accumulators, the PIN and the secure-messaging state, and writes them
     * into the IAD (bytes 4-8).
     *
     * @param type             the AC type of this GENERATE AC (TC/ARQC/AAC)
     * @param second           true for the second AC of the transaction
     * @param cda              true when this AC carries a CDA signature
     * @param unableToGoOnline true for a second AC whose ARC is Y3/Z3
     */
    public void build(byte type, boolean second, boolean cda, boolean unableToGoOnline) {
        byte firstCode = second ? AcProcessor.acTypeCode(protocolState.getFirstACGenerated())
                : AcProcessor.acTypeCode(type);
        byte secondCode = second ? AcProcessor.acTypeCode(type) : (byte) 2; // 10b = not requested
        // "Issuer Authentication Not Performed": the second AC reports whether
        // this transaction received Issuer Authentication Data; the first AC
        // repeats the value of the most recent second AC (EMV v4.4 Book 3 §9.2.3.2).
        boolean issuerAuthNotPerformed = second
                ? !protocolState.isIssuerAuthPerformed()
                : protocolState.isIssuerAuthNotPerformedPrevious();
        byte b1 = Iad.cvrByte1(firstCode, secondCode,
                cda || protocolState.isCdaPerformed(),
                protocolState.isDdaPerformed(), issuerAuthNotPerformed,
                protocolState.isIssuerAuthFailedPersistent());

        short ptc = pin.getTriesRemaining();
        byte b2 = (byte) ((ptc << 4) & 0xF0);
        if (protocolState.getCVMPerformed() != EMVCodes.NONE) {
            b2 |= Iad.CVR2_PIN_PERFORMED;
            if (!pin.isValidated()) {
                // Offline PIN verification was performed and did not succeed
                // (EMV v4.4 Book 3 §9.2.3.2).
                b2 |= Iad.CVR2_PIN_FAILED;
            }
        }
        if (ptc == 0) {
            b2 |= Iad.CVR2_PIN_TRY_LIMIT_EXCEEDED;
        }
        if (!second && protocolState.isLastOnlineNotCompleted()) {
            // The previous transaction requested online and its second AC was
            // never received (EMV v4.4 Book 3 §9.2.3.2).
            b2 |= Iad.CVR2_LAST_ONLINE_NOT_COMPLETED;
        }

        byte b3 = offlineRisk.cvrByte3();

        // 'Issuer Script Processing Failed' is persistent (EMV v4.4 Book 3
        // §9.2.3.2): a failure detected by SecureMessaging is copied into the
        // persistent protocol state and reported until the reset conditions
        // clear it (see AcProcessor.completeTransaction).  This works for tag
        // '72' scripts too, which fail after the final AC of the current
        // transaction.
        if (secureMessaging.isScriptFailedPersistent()) {
            protocolState.setScriptFailedPersistent(true);
        }
        byte b4 = (byte) ((secureMessaging.getScriptCommandsProcessed() << 4) & 0xF0);
        if (protocolState.isScriptFailedPersistent()) {
            b4 |= Iad.CVR4_SCRIPT_FAILED;
        }
        if (protocolState.isOdaFailedPrevious()) {
            b4 |= Iad.CVR4_ODA_FAILED_PREVIOUS;
        }
        if (offlineRisk.isGoOnlineNext()) {
            b4 |= Iad.CVR4_GO_ONLINE_NEXT;
        }
        if (unableToGoOnline) {
            b4 |= Iad.CVR4_UNABLE_TO_GO_ONLINE;
        }

        cvr[0] = b1;
        cvr[1] = b2;
        cvr[2] = b3;
        cvr[3] = b4;
        cvr[4] = 0;
        staticData.setCvr(cvr, (short) 0);
    }
}
