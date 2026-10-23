package card42.host.emv.kernel.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import card42.host.emv.lib.IssuerKey;
import card42.host.emv.lib.Responses;
import card42.host.emv.lib.TagPolicy;

final class MutableTransactionResult implements TransactionResultWriter {

    private String aidHex;
    private byte[] fci;
    private int aip;
    private byte[] afl;
    private byte[] pdolData;
    private byte[] record1;
    private byte[] cdol1Data;
    private byte[] cdol2Data;
    private final Map<Integer, byte[]> records = new LinkedHashMap<Integer, byte[]>();

    private byte[] tvr;
    private byte[] tsi;
    private byte[] cvmResults;

    private byte[] onlinePinBlock;
    private byte[] signature;

    private boolean sdaPerformed;
    private boolean sdaFailed;
    private boolean ddaPerformed;
    private boolean ddaFailed;
    private boolean cdaPerformed;
    private boolean cdaFailed;
    private boolean cdaSelected;
    private boolean odaAttempted;

    private IssuerKey issuerKey;
    private IssuerKey iccKey;
    private byte[] dataAuthenticationCode;
    private byte[] iccDynamicNumber;

    private byte requestedFirstAc;
    private byte firstCid;
    private byte secondCid;
    private Responses.AcResponse firstAc;
    private Responses.AcResponse secondAc;
    private byte[] firstResponse;
    private byte[] secondResponse;

    private boolean wentOnline;
    private boolean issuerAuthPerformed;
    private byte[] issuerAuthData;
    private byte[] arc;
    private boolean declined;

    private boolean adviceRequired;
    private boolean serviceNotAllowed;
    private boolean cardCaptureRequested;
    private boolean referralRequested;
    private boolean attendantForcedAcceptance;
    private boolean reversalRequired;

    private byte[] issuerScriptResults;
    private boolean issuerScriptFailedBeforeFinalAc;
    private boolean issuerScriptFailedAfterFinalAc;

    private Outcome outcome;

    public TransactionResultWriter aidHex(String v) { this.aidHex = v; return this; }
    public TransactionResultWriter fci(byte[] v) { this.fci = v; return this; }
    public TransactionResultWriter aip(int v) { this.aip = v; return this; }
    public TransactionResultWriter afl(byte[] v) { this.afl = v; return this; }
    public TransactionResultWriter pdolData(byte[] v) { this.pdolData = v; return this; }
    public TransactionResultWriter record1(byte[] v) { this.record1 = v; return this; }
    public TransactionResultWriter cdol1Data(byte[] v) { this.cdol1Data = v; return this; }
    public TransactionResultWriter cdol2Data(byte[] v) { this.cdol2Data = v; return this; }

    public TransactionResultWriter tvr(byte[] v) { this.tvr = v; return this; }
    public TransactionResultWriter tsi(byte[] v) { this.tsi = v; return this; }
    public TransactionResultWriter cvmResults(byte[] v) { this.cvmResults = v; return this; }

    public TransactionResultWriter onlinePinBlock(byte[] v) { this.onlinePinBlock = v; return this; }
    public TransactionResultWriter signature(byte[] v) { this.signature = v; return this; }

    public TransactionResultWriter sdaPerformed(boolean v) { this.sdaPerformed = v; return this; }
    public TransactionResultWriter sdaFailed(boolean v) { this.sdaFailed = v; return this; }
    public TransactionResultWriter ddaPerformed(boolean v) { this.ddaPerformed = v; return this; }
    public TransactionResultWriter ddaFailed(boolean v) { this.ddaFailed = v; return this; }
    public TransactionResultWriter cdaPerformed(boolean v) { this.cdaPerformed = v; return this; }
    public TransactionResultWriter cdaFailed(boolean v) { this.cdaFailed = v; return this; }
    public TransactionResultWriter cdaSelected(boolean v) { this.cdaSelected = v; return this; }
    public TransactionResultWriter odaAttempted(boolean v) { this.odaAttempted = v; return this; }

    public TransactionResultWriter issuerKey(IssuerKey v) { this.issuerKey = v; return this; }
    public TransactionResultWriter iccKey(IssuerKey v) { this.iccKey = v; return this; }
    public TransactionResultWriter dataAuthenticationCode(byte[] v) { this.dataAuthenticationCode = v; return this; }
    public TransactionResultWriter iccDynamicNumber(byte[] v) { this.iccDynamicNumber = v; return this; }

    public TransactionResultWriter requestedFirstAc(byte v) { this.requestedFirstAc = v; return this; }
    public TransactionResultWriter firstCid(byte v) { this.firstCid = v; return this; }
    public TransactionResultWriter secondCid(byte v) { this.secondCid = v; return this; }
    public TransactionResultWriter firstAc(Responses.AcResponse v) { this.firstAc = v; return this; }
    public TransactionResultWriter secondAc(Responses.AcResponse v) { this.secondAc = v; return this; }
    public TransactionResultWriter firstResponse(byte[] v) { this.firstResponse = v; return this; }
    public TransactionResultWriter secondResponse(byte[] v) { this.secondResponse = v; return this; }

    public TransactionResultWriter wentOnline(boolean v) { this.wentOnline = v; return this; }
    public TransactionResultWriter issuerAuthPerformed(boolean v) { this.issuerAuthPerformed = v; return this; }
    public TransactionResultWriter issuerAuthData(byte[] v) { this.issuerAuthData = v; return this; }
    public TransactionResultWriter arc(byte[] v) { this.arc = v; return this; }
    public TransactionResultWriter declined(boolean v) { this.declined = v; return this; }

    public TransactionResultWriter adviceRequired(boolean v) { this.adviceRequired = v; return this; }
    public TransactionResultWriter serviceNotAllowed(boolean v) { this.serviceNotAllowed = v; return this; }
    public TransactionResultWriter cardCaptureRequested(boolean v) { this.cardCaptureRequested = v; return this; }
    public TransactionResultWriter referralRequested(boolean v) { this.referralRequested = v; return this; }
    public TransactionResultWriter attendantForcedAcceptance(boolean v) { this.attendantForcedAcceptance = v; return this; }
    public TransactionResultWriter reversalRequired(boolean v) { this.reversalRequired = v; return this; }

    public TransactionResultWriter issuerScriptResults(byte[] v) { this.issuerScriptResults = v; return this; }
    public TransactionResultWriter issuerScriptFailedBeforeFinalAc(boolean v) { this.issuerScriptFailedBeforeFinalAc = v; return this; }
    public TransactionResultWriter issuerScriptFailedAfterFinalAc(boolean v) { this.issuerScriptFailedAfterFinalAc = v; return this; }

    public TransactionResultWriter outcome(Outcome v) { this.outcome = v; return this; }

    /** Puts a record read from the card under {@code (sfi << 8) | record}. */
    public TransactionResultWriter putRecord(int key, byte[] value) {
        this.records.put(key, value);
        return this;
    }

    // --- Read contract ---------------------------------------------------

    @Override public String aidHex() { return aidHex; }
    @Override public byte[] fci() { return fci; }
    @Override public int aip() { return aip; }
    @Override public byte[] afl() { return afl; }
    @Override public byte[] pdolData() { return pdolData; }
    @Override public byte[] record1() { return record1; }
    @Override public byte[] cdol1Data() { return cdol1Data; }
    @Override public byte[] cdol2Data() { return cdol2Data; }

    @Override public byte[] tvr() { return tvr; }
    @Override public byte[] tsi() { return tsi; }
    @Override public byte[] cvmResults() { return cvmResults; }

    @Override public byte[] onlinePinBlock() { return onlinePinBlock; }
    @Override public byte[] signature() { return signature; }

    @Override public boolean sdaPerformed() { return sdaPerformed; }
    @Override public boolean sdaFailed() { return sdaFailed; }
    @Override public boolean ddaPerformed() { return ddaPerformed; }
    @Override public boolean ddaFailed() { return ddaFailed; }
    @Override public boolean cdaPerformed() { return cdaPerformed; }
    @Override public boolean cdaFailed() { return cdaFailed; }
    @Override public boolean cdaSelected() { return cdaSelected; }
    @Override public boolean odaAttempted() { return odaAttempted; }

    @Override public IssuerKey issuerKey() { return issuerKey; }
    @Override public IssuerKey iccKey() { return iccKey; }
    @Override public byte[] dataAuthenticationCode() { return dataAuthenticationCode; }
    @Override public byte[] iccDynamicNumber() { return iccDynamicNumber; }

    @Override public byte requestedFirstAc() { return requestedFirstAc; }
    @Override public byte firstCid() { return firstCid; }
    @Override public byte secondCid() { return secondCid; }
    @Override public Responses.AcResponse firstAc() { return firstAc; }
    @Override public Responses.AcResponse secondAc() { return secondAc; }
    @Override public byte[] firstResponse() { return firstResponse; }
    @Override public byte[] secondResponse() { return secondResponse; }

    @Override public boolean wentOnline() { return wentOnline; }
    @Override public boolean issuerAuthPerformed() { return issuerAuthPerformed; }
    @Override public byte[] issuerAuthData() { return issuerAuthData; }
    @Override public byte[] arc() { return arc; }
    @Override public boolean declined() { return declined; }

    @Override public boolean adviceRequired() { return adviceRequired; }
    @Override public boolean serviceNotAllowed() { return serviceNotAllowed; }
    @Override public boolean cardCaptureRequested() { return cardCaptureRequested; }
    @Override public boolean referralRequested() { return referralRequested; }
    @Override public boolean attendantForcedAcceptance() { return attendantForcedAcceptance; }
    @Override public boolean reversalRequired() { return reversalRequired; }

    @Override public byte[] issuerScriptResults() { return issuerScriptResults; }
    @Override public boolean issuerScriptFailedBeforeFinalAc() { return issuerScriptFailedBeforeFinalAc; }
    @Override public boolean issuerScriptFailedAfterFinalAc() { return issuerScriptFailedAfterFinalAc; }

    @Override public Outcome outcome() { return outcome; }

    @Override public Map<Integer, byte[]> records() {
        return Collections.unmodifiableMap(records);
    }

    @Override public byte[] record(int sfi, int record) {
        return records.get((sfi << 8) | record);
    }

    @Override public byte[] firstValue(int tag) {
        for (byte[] record : records.values()) {
            byte[] value = TagPolicy.findIcc(record, tag);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    @Override public Decision decision() {
        if (outcome != null) {
            switch (outcome.finalOutcome) {
            case Outcome.APPROVE:
                return Decision.APPROVE;
            case Outcome.DECLINE:
                return Decision.DECLINE;
            case Outcome.ONLINE_REQUEST:
            case Outcome.REQUEST_ONLINE_PIN:
                return Decision.ONLINE;
            case Outcome.END_APPLICATION:
            case Outcome.TRY_ANOTHER_INTERFACE:
                return Decision.END_APPLICATION;
            default:
                break; // Select Next / Try Again restart; use the terminal decision
            }
        }
        if (serviceNotAllowed) {
            return Decision.END_APPLICATION;
        }
        return declined ? Decision.DECLINE : Decision.APPROVE;
    }
}
