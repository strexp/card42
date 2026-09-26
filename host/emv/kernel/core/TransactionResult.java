package card42.host.emv.kernel.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import card42.host.emv.lib.IssuerKey;
import card42.host.emv.lib.TagPolicy;
import card42.host.common.codec.Responses;

/**
 * Everything a terminal kernel observed during one transaction (EMV v4.4
 * Book 3/4).
 *
 * <p>This is the media-neutral result shared by the contact and the contactless
 * kernel: the application selection differs (PSE/ADF vs PPSE/Entry Point) and
 * the CVM execution differs (offline PIN vs no offline CVM), but the transaction
 * data, the ODA outcome, the cryptograms and the online decision are the same.
 * Both kernels return this type directly.
 *
 * <p>The fields are read-only to callers; the kernel writes them through the
 * package-internal {@link Mutable} subclass.  A caller that needs a media-neutral
 * decision uses {@link #decision()}.
 */
public class TransactionResult {

    /**
     * The media-neutral transaction decision.  It unifies the terminal decision
     * of EMV v4.4 Book 4 §6.3.2 (approve / decline / online) with the Final
     * Outcome of EMV Contactless Book A v2.12 Table 6-1, so a caller can branch
     * without knowing which kernel ran.
     */
    public enum Decision {
        /** The transaction is approved (offline or after an online approval). */
        APPROVE,
        /** The transaction is declined. */
        DECLINE,
        /** The transaction requires an online authorisation. */
        ONLINE,
        /** No application can complete the transaction (Book A Table 6-1). */
        END_APPLICATION
    }

    protected String aidHex;
    protected byte[] fci;
    protected int aip;
    protected byte[] afl;
    protected byte[] pdolData;
    protected byte[] record1;
    protected byte[] cdol1Data;
    protected byte[] cdol2Data;
    protected final Map<Integer, byte[]> records = new LinkedHashMap<Integer, byte[]>();

    protected byte[] tvr;
    protected byte[] tsi;
    protected byte[] cvmResults;

    protected byte[] onlinePinBlock;
    protected byte[] signature;

    protected boolean sdaPerformed;
    protected boolean sdaFailed;
    protected boolean ddaPerformed;
    protected boolean ddaFailed;
    protected boolean cdaPerformed;
    protected boolean cdaFailed;
    protected boolean cdaSelected;
    protected boolean odaAttempted;

    protected IssuerKey issuerKey;
    protected IssuerKey iccKey;
    protected byte[] dataAuthenticationCode;
    protected byte[] iccDynamicNumber;

    protected byte requestedFirstAc;
    protected byte firstCid;
    protected byte secondCid;
    protected Responses.AcResponse firstAc;
    protected Responses.AcResponse secondAc;
    protected byte[] firstResponse;
    protected byte[] secondResponse;

    protected boolean wentOnline;
    protected boolean issuerAuthPerformed;
    protected byte[] issuerAuthData;
    protected byte[] arc;
    protected boolean declined;

    protected boolean adviceRequired;
    protected boolean serviceNotAllowed;
    protected boolean cardCaptureRequested;
    protected boolean referralRequested;
    protected boolean attendantForcedAcceptance;
    protected boolean reversalRequired;

    protected byte[] issuerScriptResults;
    protected boolean issuerScriptFailedBeforeFinalAc;
    protected boolean issuerScriptFailedAfterFinalAc;

    protected Outcome outcome;

    // --- Accessors -----------------------------------------------------------

    public String aidHex() { return aidHex; }
    public byte[] fci() { return fci; }
    public int aip() { return aip; }
    public byte[] afl() { return afl; }
    public byte[] pdolData() { return pdolData; }
    public byte[] record1() { return record1; }
    public byte[] cdol1Data() { return cdol1Data; }
    public byte[] cdol2Data() { return cdol2Data; }

    public byte[] tvr() { return tvr; }
    public byte[] tsi() { return tsi; }
    public byte[] cvmResults() { return cvmResults; }

    public byte[] onlinePinBlock() { return onlinePinBlock; }
    public byte[] signature() { return signature; }

    public boolean sdaPerformed() { return sdaPerformed; }
    public boolean sdaFailed() { return sdaFailed; }
    public boolean ddaPerformed() { return ddaPerformed; }
    public boolean ddaFailed() { return ddaFailed; }
    public boolean cdaPerformed() { return cdaPerformed; }
    public boolean cdaFailed() { return cdaFailed; }
    public boolean cdaSelected() { return cdaSelected; }
    public boolean odaAttempted() { return odaAttempted; }

    public IssuerKey issuerKey() { return issuerKey; }
    public IssuerKey iccKey() { return iccKey; }
    public byte[] dataAuthenticationCode() { return dataAuthenticationCode; }
    public byte[] iccDynamicNumber() { return iccDynamicNumber; }

    public byte requestedFirstAc() { return requestedFirstAc; }
    public byte firstCid() { return firstCid; }
    public byte secondCid() { return secondCid; }
    public Responses.AcResponse firstAc() { return firstAc; }
    public Responses.AcResponse secondAc() { return secondAc; }
    public byte[] firstResponse() { return firstResponse; }
    public byte[] secondResponse() { return secondResponse; }

    public boolean wentOnline() { return wentOnline; }
    public boolean issuerAuthPerformed() { return issuerAuthPerformed; }
    public byte[] issuerAuthData() { return issuerAuthData; }
    /** Authorisation Response Code ('8A', two bytes), or null. */
    public byte[] arc() { return arc; }
    public boolean declined() { return declined; }

    public boolean adviceRequired() { return adviceRequired; }
    public boolean serviceNotAllowed() { return serviceNotAllowed; }
    public boolean cardCaptureRequested() { return cardCaptureRequested; }
    public boolean referralRequested() { return referralRequested; }
    public boolean attendantForcedAcceptance() { return attendantForcedAcceptance; }
    public boolean reversalRequired() { return reversalRequired; }

    public byte[] issuerScriptResults() { return issuerScriptResults; }
    public boolean issuerScriptFailedBeforeFinalAc() { return issuerScriptFailedBeforeFinalAc; }
    public boolean issuerScriptFailedAfterFinalAc() { return issuerScriptFailedAfterFinalAc; }

    /** The kernel Outcome (EMV Contactless Book A v2.12 Table 6-2), or null for the contact kernel. */
    public Outcome outcome() { return outcome; }

    /** The read-only records keyed by {@code (sfi << 8) | record}. */
    public Map<Integer, byte[]> records() {
        return Collections.unmodifiableMap(records);
    }

    /** The record at (sfi, record), or null. */
    public byte[] record(int sfi, int record) {
        return records.get((sfi << 8) | record);
    }

    /**
     * The first ICC-sourced value of a tag across all read records, or null.
     * Terminal- and issuer-sourced data objects sent by the card are ignored,
     * and Table 34 format errors are treated as absent (EMV v4.4 Book 3 §7.5).
     */
    public byte[] firstValue(int tag) {
        for (byte[] record : records.values()) {
            byte[] value = TagPolicy.findIcc(record, tag);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    /**
     * The media-neutral decision of the transaction.  The contactless Outcome
     * (EMV Contactless Book A v2.12 Table 6-1) takes precedence when present;
     * otherwise the terminal decision of EMV v4.4 Book 4 §6.3.2 is derived from
     * {@link #serviceNotAllowed()} and {@link #declined()}.
     */
    public Decision decision() {
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

    /**
     * The mutable view the kernel writes through.  It is public only so the
     * kernel (a different package) can populate it; callers hold the read-only
     * {@link TransactionResult} returned by {@code TerminalKernel.run}.
     */
    public static final class Mutable extends TransactionResult {

        public Mutable aidHex(String v) { this.aidHex = v; return this; }
        public Mutable fci(byte[] v) { this.fci = v; return this; }
        public Mutable aip(int v) { this.aip = v; return this; }
        public Mutable afl(byte[] v) { this.afl = v; return this; }
        public Mutable pdolData(byte[] v) { this.pdolData = v; return this; }
        public Mutable record1(byte[] v) { this.record1 = v; return this; }
        public Mutable cdol1Data(byte[] v) { this.cdol1Data = v; return this; }
        public Mutable cdol2Data(byte[] v) { this.cdol2Data = v; return this; }

        public Mutable tvr(byte[] v) { this.tvr = v; return this; }
        public Mutable tsi(byte[] v) { this.tsi = v; return this; }
        public Mutable cvmResults(byte[] v) { this.cvmResults = v; return this; }

        public Mutable onlinePinBlock(byte[] v) { this.onlinePinBlock = v; return this; }
        public Mutable signature(byte[] v) { this.signature = v; return this; }

        public Mutable sdaPerformed(boolean v) { this.sdaPerformed = v; return this; }
        public Mutable sdaFailed(boolean v) { this.sdaFailed = v; return this; }
        public Mutable ddaPerformed(boolean v) { this.ddaPerformed = v; return this; }
        public Mutable ddaFailed(boolean v) { this.ddaFailed = v; return this; }
        public Mutable cdaPerformed(boolean v) { this.cdaPerformed = v; return this; }
        public Mutable cdaFailed(boolean v) { this.cdaFailed = v; return this; }
        public Mutable cdaSelected(boolean v) { this.cdaSelected = v; return this; }
        public Mutable odaAttempted(boolean v) { this.odaAttempted = v; return this; }

        public Mutable issuerKey(IssuerKey v) { this.issuerKey = v; return this; }
        public Mutable iccKey(IssuerKey v) { this.iccKey = v; return this; }
        public Mutable dataAuthenticationCode(byte[] v) { this.dataAuthenticationCode = v; return this; }
        public Mutable iccDynamicNumber(byte[] v) { this.iccDynamicNumber = v; return this; }

        public Mutable requestedFirstAc(byte v) { this.requestedFirstAc = v; return this; }
        public Mutable firstCid(byte v) { this.firstCid = v; return this; }
        public Mutable secondCid(byte v) { this.secondCid = v; return this; }
        public Mutable firstAc(Responses.AcResponse v) { this.firstAc = v; return this; }
        public Mutable secondAc(Responses.AcResponse v) { this.secondAc = v; return this; }
        public Mutable firstResponse(byte[] v) { this.firstResponse = v; return this; }
        public Mutable secondResponse(byte[] v) { this.secondResponse = v; return this; }

        public Mutable wentOnline(boolean v) { this.wentOnline = v; return this; }
        public Mutable issuerAuthPerformed(boolean v) { this.issuerAuthPerformed = v; return this; }
        public Mutable issuerAuthData(byte[] v) { this.issuerAuthData = v; return this; }
        public Mutable arc(byte[] v) { this.arc = v; return this; }
        public Mutable declined(boolean v) { this.declined = v; return this; }

        public Mutable adviceRequired(boolean v) { this.adviceRequired = v; return this; }
        public Mutable serviceNotAllowed(boolean v) { this.serviceNotAllowed = v; return this; }
        public Mutable cardCaptureRequested(boolean v) { this.cardCaptureRequested = v; return this; }
        public Mutable referralRequested(boolean v) { this.referralRequested = v; return this; }
        public Mutable attendantForcedAcceptance(boolean v) { this.attendantForcedAcceptance = v; return this; }
        public Mutable reversalRequired(boolean v) { this.reversalRequired = v; return this; }

        public Mutable issuerScriptResults(byte[] v) { this.issuerScriptResults = v; return this; }
        public Mutable issuerScriptFailedBeforeFinalAc(boolean v) { this.issuerScriptFailedBeforeFinalAc = v; return this; }
        public Mutable issuerScriptFailedAfterFinalAc(boolean v) { this.issuerScriptFailedAfterFinalAc = v; return this; }

        public Mutable outcome(Outcome v) { this.outcome = v; return this; }

        /** Puts a record read from the card under {@code (sfi << 8) | record}. */
        public Mutable putRecord(int key, byte[] value) {
            this.records.put(key, value);
            return this;
        }
    }
}
