package card42.emv;

import card42.common.*;

/* Finalizes a GENERATE AC transaction: the Last Online ATC register, the
 * offline-risk accumulators and the persistent CVR carry-over bits, and the
 * single transaction-log record written once the transaction is final
 * (EMV v4.4 Book 3 §9.2.3.2, Annex C §C9.3, Annex D4).
 *
 * Extracted from AcProcessor so that the end-of-transaction bookkeeping is
 * independent of the AC command handling.  The first-AC CDOL1 copy (kept by
 * AcProcessor for the CDA signature and the CSU amount update) is passed in by
 * the caller.
 *
 * @author card42
 */

public class TransactionFinalizer {

    private final EMVProtocolState protocolState;
    private final EMVStaticData staticData;
    private final OfflineRisk offlineRisk;
    private final TransactionLog transactionLog;
    private final SecureMessaging secureMessaging;

    public TransactionFinalizer(EMVProtocolState protocolState, EMVStaticData staticData,
            OfflineRisk offlineRisk, TransactionLog transactionLog,
            SecureMessaging secureMessaging) {
        this.protocolState = protocolState;
        this.staticData = staticData;
        this.offlineRisk = offlineRisk;
        this.transactionLog = transactionLog;
        this.secureMessaging = secureMessaging;
    }

    /**
     * Marks the transaction as completed online (EMV v4.4 Book 2 §8.2): the
     * Last Online ATC Register (9F13) is written only when the transaction
     * actually went online (the ARC does not indicate Y3/Z3) and the first AC
     * was an ARQC.
     */
    public void completeOnlineSession(boolean wentOnline) {
        if (wentOnline && protocolState.getFirstACGenerated() == EMVCodes.ARQC) {
            protocolState.setLastOnlineATC(protocolState.getATC());
        }
    }

    /**
     * Finalizes the transaction (EMV v4.4 Book 3 Annex D4, Annex C §C9.3): the
     * offline accumulators are updated and, once the transaction is final,
     * exactly one transaction-log record is written.  A first AC that returns
     * an ARQC is not final - if the terminal never sends a second AC there is
     * no log and no counter update, so a half-completed online transaction
     * leaves no stale entry (EMV v4.4 Book 3 §9.2.3.2).
     */
    public void complete(byte cid, boolean second, boolean wentOnline, byte requestedCid,
            byte[] firstCdol, short firstCdolLength) {
        byte type = AcProcessor.acType(cid);
        if (second) {
            // Remember the "Issuer Authentication Not Performed" bit for the
            // first AC of the next transaction (EMV v4.4 Book 3 §9.2.3.2).
            protocolState.setIssuerAuthNotPerformedPrevious(
                    !protocolState.isIssuerAuthPerformed());
            // The accumulators are reset only after a transaction that actually
            // went online (ARC not Y3/Z3) and, when issuer authentication was
            // not performed, only when the *terminal requested* a TC (not the
            // card's downgraded decision); with issuer authentication the CSU
            // 'Update Counters' bits already decided the update
            // (EMV v4.4 Book 3 §10.11.1.2, Annex C §C10).
            if (wentOnline && AcProcessor.acType(requestedCid) == EMVCodes.TC
                    && !protocolState.isIssuerAuthPerformed()) {
                offlineRisk.recordOnline();
            }
            if (wentOnline) {
                // A successful online transaction clears the persistent "Issuer
                // Script Processing Failed" bit (EMV v4.4 Book 3 §9.2.3.2).
                protocolState.setScriptFailedPersistent(false);
                secureMessaging.clearScriptFailedPersistent();
            }
            if (!wentOnline && type == EMVCodes.TC
                    && protocolState.getFirstACGenerated() == EMVCodes.ARQC) {
                // The terminal could not go online and the second AC approved the
                // transaction offline (ARC 'Y3').  Like any other offline-approved
                // transaction it must be added to the offline accumulators
                // (EMV v4.4 Book 3 CCD §9.2.3.2).  Only when the first AC was an
                // ARQC: a first AC that already approved offline (TC) was counted
                // then, and must not be counted twice.
                recordOfflineRisk(firstCdol, firstCdolLength);
            }
            // The second AC of a terminal that could not go online approves the
            // transaction offline when it is a TC ('Y3'), which also resets the
            // "ODA failed on previous transaction" bit; an AAC ('Z3') does not
            // (EMV v4.4 Book 3 §9.2.3.2).
            updateOdaFailedPrevious(firstCdol, firstCdolLength,
                    wentOnline, !wentOnline && type == EMVCodes.TC);
            writeLog(cid, firstCdol, firstCdolLength);
            return;
        }
        if (type == EMVCodes.ARQC) {
            return; // not final yet
        }
        updateOdaFailedPrevious(firstCdol, firstCdolLength, false, type == EMVCodes.TC);
        if (type == EMVCodes.TC) {
            recordOfflineRisk(firstCdol, firstCdolLength);
        }
        writeLog(cid, firstCdol, firstCdolLength);
    }

    /**
     * Maintains the CVR "Offline Data Authentication Failed on Previous
     * Transaction" bit (EMV v4.4 Book 3 §9.2.3.2): the TVR of this transaction
     * (SDA/DDA/CDA failed) is reported in the next transaction's first AC.  A
     * transaction that went online or was approved offline resets an older bit;
     * per the spec the reset wins when both apply in the same transaction.
     */
    private void updateOdaFailedPrevious(byte[] firstCdol, short firstCdolLength,
            boolean wentOnline, boolean approvedOffline) {
        boolean failedNow = false;
        short off = staticData.getCDOL1ValueOffset(TlvTags.TAG_TVR);
        short len = staticData.getCDOL1ValueLength(TlvTags.TAG_TVR);
        if (off >= 0 && len >= 1 && (short) (off + 1) <= firstCdolLength) {
            byte tvr = firstCdol[off];
            // TVR byte 1: SDA failed (b7), DDA failed (b4), CDA failed (b3).
            failedNow = (tvr & 0x40) != 0 || (tvr & 0x10) != 0 || (tvr & 0x08) != 0;
        }
        if (wentOnline || approvedOffline) {
            protocolState.setOdaFailedPrevious(false);
        } else if (failedNow) {
            protocolState.setOdaFailedPrevious(true);
        }
    }

    /** Records an offline-approved transaction in the accumulators. */
    private void recordOfflineRisk(byte[] firstCdol, short firstCdolLength) {
        short off = staticData.getCDOL1ValueOffset(TlvTags.TAG_AMOUNT_AUTHORISED);
        short len = staticData.getCDOL1ValueLength(TlvTags.TAG_AMOUNT_AUTHORISED);
        if (off < 0 || len <= 0 || (short) (off + len) > firstCdolLength) {
            offlineRisk.recordOffline(firstCdol, (short) 0, (short) 0);
        } else {
            offlineRisk.recordOffline(firstCdol, off, len);
        }
    }

    /** Writes one transaction-log record (EMV v4.4 Book 3 Annex D4). */
    private void writeLog(byte cid, byte[] firstCdol, short firstCdolLength) {
        transactionLog.write(cid, protocolState, staticData, firstCdol, firstCdolLength);
    }
}
