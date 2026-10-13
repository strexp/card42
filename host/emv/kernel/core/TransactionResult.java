package card42.host.emv.kernel.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import card42.host.emv.lib.IssuerKey;
import card42.host.emv.lib.Responses;
import card42.host.emv.lib.TagPolicy;

/**
 * Everything a terminal kernel observed during one transaction (EMV v4.4
 * Book 3/4), as a read-only contract.
 *
 * <p>This is the media-neutral result shared by the contact and the contactless
 * kernel: the application selection differs (PSE/ADF vs PPSE/Entry Point) and
 * the CVM execution differs (offline PIN vs no offline CVM), but the transaction
 * data, the ODA outcome, the cryptograms and the online decision are the same.
 * Both kernels return this type directly.
 *
 * <p>This is an interface, so a caller depends on the read contract only; the
 * kernel writes through the package-internal {@link Mutable}, which implements
 * it.  A caller that needs a media-neutral decision uses {@link #decision()}.
 */
public interface TransactionResult {

    /**
     * The media-neutral transaction decision.  It unifies the terminal decision
     * of EMV v4.4 Book 4 §6.3.2 (approve / decline / online) with the Final
     * Outcome of EMV Contactless Book A v2.12 Table 6-1, so a caller can branch
     * without knowing which kernel ran.
     */
    enum Decision {
        /** The transaction is approved (offline or after an online approval). */
        APPROVE,
        /** The transaction is declined. */
        DECLINE,
        /** The transaction requires an online authorisation. */
        ONLINE,
        /** No application can complete the transaction (Book A Table 6-1). */
        END_APPLICATION
    }

    // --- Accessors -----------------------------------------------------------

    String aidHex();
    byte[] fci();
    int aip();
    byte[] afl();
    byte[] pdolData();
    byte[] record1();
    byte[] cdol1Data();
    byte[] cdol2Data();

    byte[] tvr();
    byte[] tsi();
    byte[] cvmResults();

    byte[] onlinePinBlock();
    byte[] signature();

    boolean sdaPerformed();
    boolean sdaFailed();
    boolean ddaPerformed();
    boolean ddaFailed();
    boolean cdaPerformed();
    boolean cdaFailed();
    boolean cdaSelected();
    boolean odaAttempted();

    IssuerKey issuerKey();
    IssuerKey iccKey();
    byte[] dataAuthenticationCode();
    byte[] iccDynamicNumber();

    byte requestedFirstAc();
    byte firstCid();
    byte secondCid();
    Responses.AcResponse firstAc();
    Responses.AcResponse secondAc();
    byte[] firstResponse();
    byte[] secondResponse();

    boolean wentOnline();
    boolean issuerAuthPerformed();
    byte[] issuerAuthData();
    /** Authorisation Response Code ('8A', two bytes), or null. */
    byte[] arc();
    boolean declined();

    boolean adviceRequired();
    boolean serviceNotAllowed();
    boolean cardCaptureRequested();
    boolean referralRequested();
    boolean attendantForcedAcceptance();
    boolean reversalRequired();

    byte[] issuerScriptResults();
    boolean issuerScriptFailedBeforeFinalAc();
    boolean issuerScriptFailedAfterFinalAc();

    /** The kernel Outcome (EMV Contactless Book A v2.12 Table 6-2), or null for the contact kernel. */
    Outcome outcome();

    /** The read-only records keyed by {@code (sfi << 8) | record}. */
    Map<Integer, byte[]> records();

    /** The record at (sfi, record), or null. */
    byte[] record(int sfi, int record);

    /**
     * The first ICC-sourced value of a tag across all read records, or null.
     * Terminal- and issuer-sourced data objects sent by the card are ignored,
     * and Table 34 format errors are treated as absent (EMV v4.4 Book 3 §7.5).
     */
    byte[] firstValue(int tag);

    /**
     * The media-neutral decision of the transaction.  The contactless Outcome
     * (EMV Contactless Book A v2.12 Table 6-1) takes precedence when present;
     * otherwise the terminal decision of EMV v4.4 Book 4 §6.3.2 is derived from
     * {@link #serviceNotAllowed()} and {@link #declined()}.
     */
    Decision decision();

    /**
     * The mutable implementation the kernel writes through.  It composes the
     * read contract (implements {@link TransactionResult}) rather than extending
     * a concrete result class, so a caller never sees a writable subtype.
     */
    final class Mutable implements TransactionResult {

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
}
