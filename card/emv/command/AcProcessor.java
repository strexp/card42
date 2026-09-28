package card42.emv;

import card42.common.*;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* The Application Cryptogram path of a payment instance: GENERATE AC, the Card
 * Action Analysis, the CVR-bearing IAD, and the transaction finalization that
 * updates the offline risk accumulators and writes one log record
 * (EMV v4.4 Book 3 §9.3, §10.8, Annex C §C9.3, Annex D4).
 *
 * The first AC's CDOL1 data is kept here for the CDA signature of the second AC
 * and for the CSU amount update (IssuerAuth reads it back).  The card may only
 * downgrade the cryptogram the terminal requested (EMV v4.4 Book 3 §9.3).
 *
 * @author card42
 */

public class AcProcessor implements ISO7816 {

    /** P1 b5-b4 selects the offline data authentication type (EMV v4.4 Book 3 Table 12). */
    private static final byte ODA_MASK = (byte) 0x18;
    private static final byte ODA_CDA = (byte) 0x10;
    private static final byte ODA_XDA = (byte) 0x08;

    private final EMVProtocolState protocolState;
    private final EMVStaticData staticData;
    private final EMVCrypto theCrypto;
    private final DdaCrypto ddaCrypto;
    private final OfflineRisk offlineRisk;
    private final DynamicAuth dynamicAuth;
    private final IssuerAuth issuerAuth;

    /** CVR/IAD aggregation and end-of-transaction bookkeeping (focused helpers). */
    private final CvrBuilder cvrBuilder;
    private final TransactionFinalizer finalizer;

    /** Upper bound of the CDOL1-related data accepted for a CDA/CDOL1 copy. */
    private static final short MAX_CDOL1_DATA = (short) 128;

    /* Transient copy of the first GENERATE AC CDOL1 data, needed by the CDA
     * signature of the second GENERATE AC and the CSU amount update.  It is the
     * package-shared {@link EmvScratch#firstCdol} buffer (128 bytes, the
     * on-card bound), so no allocation happens on a GENERATE AC
     * (docs/specs/common/risks.md). */
    private final byte[] firstCdol;
    private short firstCdolLength;

    public AcProcessor(EMVProtocolState protocolState, EMVStaticData staticData,
            EMVCrypto theCrypto, DdaCrypto ddaCrypto, OfflineRisk offlineRisk,
            TransactionLog transactionLog, SecureMessaging secureMessaging,
            OfflinePinState pin, DynamicAuth dynamicAuth, IssuerAuth issuerAuth) {
        this.protocolState = protocolState;
        this.staticData = staticData;
        this.theCrypto = theCrypto;
        this.ddaCrypto = ddaCrypto;
        this.offlineRisk = offlineRisk;
        this.dynamicAuth = dynamicAuth;
        this.issuerAuth = issuerAuth;

        cvrBuilder = new CvrBuilder(protocolState, staticData, offlineRisk,
                secureMessaging, pin);
        finalizer = new TransactionFinalizer(protocolState, staticData, offlineRisk,
                transactionLog, secureMessaging);

        firstCdol = EmvScratch.firstCdol;
    }

    /**
     * Validates the first-AC CDOL1 data length against the shared buffer.  The
     * CDOL1-related data must fit MAX_CDOL1_DATA (the on-card bound, EMV v4.4
     * Book 2 §6.6.1); a longer one is refused rather than truncated into a wrong
     * CDA signature.  The shared buffer is fixed, so no allocation happens here
     * (docs/specs/common/risks.md).
     */
    private void ensureFirstCdol(short length) {
        if (length > MAX_CDOL1_DATA || length > firstCdol.length) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
    }

    /**
     * The first-AC CDOL1 copy, exposed to {@code IssuerAuth} so a Method 2
     * EXTERNAL AUTHENTICATE can apply its CSU 'Update Counters' against the
     * transaction amount (EMV v4.4 Book 3 Annex C §C10).  Null before the
     * first AC.
     */
    byte[] getFirstCdol() {
        return firstCdol;
    }

    /** Length of {@link #getFirstCdol()}. */
    short getFirstCdolLength() {
        return firstCdolLength;
    }

    public void generateFirstAC(APDU apdu, byte[] apduBuffer, byte[] response) {
        // First 2 bits of P1 specify the type
        // These bits also have to be returned, as the Cryptogram Information Data (CID);
        // See EMV v4.4 Book 3 §6.5.5.4
        byte requested = (byte) (apduBuffer[OFFSET_P1] & 0xC0);
        // P1 b5-b4 selects the offline data authentication type: 10 = CDA,
        // 01 = XDA (not implemented), 11 = RFU (EMV v4.4 Book 3 Table 12).
        // The RFU value must not be verified (EMV v4.4 Book 3 §6.3.6): it is
        // treated as "no CDA/XDA signature requested", like 00.
        byte odaBits = (byte) (apduBuffer[OFFSET_P1] & ODA_MASK);
        if (odaBits == ODA_XDA) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }
        boolean invalidated = protocolState.getLifecycle() == EMVRoles.BLOCKED;
        byte cid = EMVCodes.AAC_CODE;
        if (invalidated) {
            // An invalidated application only returns an AAC, whatever the
            // terminal requested (EMV v4.4 Book 3 §6.5.1).
            cid = EMVCodes.AAC_CODE;
        } else {
            // Card Action Analysis (EMV v4.4 Book 3 §10.8): the TVR is a CDOL1
            // data element; the IACs are card data.  The card may only
            // downgrade the cryptogram the terminal requested (EMV v4.4 Book 3 §9.3).
            byte decided = cardDecision(apduBuffer);
            // P1 b8-b7 = 11 is RFU and shall not be verified (EMV v4.4 Book 3
            // §6.3.6): with no valid requested type to cap to, the card returns
            // its own decision.
            cid = requested == EMVCodes.RFU_CODE ? decided
                    : CardRiskManagement.capToRequest(requested, decided);
        }
        short cdol1Length = staticData.getCDOL1DataLength();
        // Keep the first AC's CDOL1 data for the CDA signature of the second
        // AC (EMV v4.4 Book 2 section 6.6.1, second GENERATE AC).  The buffer is sized
        // to the actual CDOL1 data; a longer one than MAX_CDOL1_DATA is refused
        // rather than truncated into a wrong signature (EMV v4.4 Book 2 §6.6.1).
        ensureFirstCdol(cdol1Length);
        firstCdolLength = cdol1Length;
        Util.arrayCopyNonAtomic(apduBuffer, OFFSET_CDATA, firstCdol,
                (short) 0, firstCdolLength);

        // CDA is only performed for a TC or ARQC response (EMV v4.4 Book 2 §6.6.1); a CDA
        // request without an ICC key is refused (EMV v4.4 Book 2 §6.6).
        boolean cdaRequested = !invalidated && cid != EMVCodes.AAC_CODE
                && odaBits == ODA_CDA;
        if (cdaRequested && !ddaCrypto.isAvailable()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        if (cdaRequested) {
            // The CVR "CDA Performed" bit is set in the first AC when SDAD is
            // returned and inherited by the second AC (EMV v4.4 Book 3 §9.2.3.2).
            protocolState.setCdaPerformed();
        }
        // Build the CVR-bearing IAD before the AC is computed (EMV v4.4 Book 3 Annex C §C9).
        cvrBuilder.build(acType(cid), false, cdaRequested, false);
        // The CVR "Last Online Transaction Not Completed" bit of the next first
        // AC reports this transaction's first AC (EMV v4.4 Book 3 §9.2.3.2): it is set
        // when this first AC requests online and cleared by the second AC.
        protocolState.setLastOnlineNotCompleted(acType(cid) == EMVCodes.ARQC);

        if (cdaRequested) {
            dynamicAuth.copyUn(staticData.getCDOL1UnOffset(), cdol1Length, apduBuffer);
            // The AC is left in EMVCrypto.lastAc; reusing it avoids a separate
            // 8-byte scratch per instance (docs/specs/common/risks.md).
            theCrypto.computeFirstAC(apduBuffer, cdol1Length, theCrypto.getLastAc(), (short) 0);
            protocolState.setArqc(theCrypto.getLastAc(), (short) 0);
            protocolState.setFirstACGenerated(acType(cid));
            finalizer.complete(cid, false, false, cid, firstCdol, firstCdolLength);
            dynamicAuth.generateCda(apdu, cid, protocolState.getATC(), theCrypto.getLastAc(),
                    firstCdol, (short) 0, firstCdolLength, null, (short) 0, (short) 0,
                    response);
            return;
        }

        // Format 2 is used for a contactless instance and for a CCD application;
        // a generic contact application returns Format 1 (EMV v4.4 Book 3
        // §6.5.5.4, CCD §6.5.5.4).  The CCD data format, not the AIP EXTERNAL
        // AUTHENTICATE capability bit, decides it.
        boolean format2 = protocolState.getRole() == EMVRoles.ROLE_CONTACTLESS
                || staticData.isCcdFormat();
        theCrypto.generateFirstACReponse(cid, apduBuffer, cdol1Length,
                response, (short) 0, format2);
        protocolState.setArqc(theCrypto.getLastAc(), (short) 0);
        protocolState.setFirstACGenerated(acType(cid));
        finalizer.complete(cid, false, false, cid, firstCdol, firstCdolLength);

        short length = Tlv.totalLength(response, (short) 0);
        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        apdu.sendBytesLong(response, (short) 0, length);
    }

    /**
     * Card Action Analysis for the first GENERATE AC: extracts the TVR (tag
     * '95') from the CDOL1 data and applies the personalised Issuer Action
     * Codes (EMV v4.4 Book 3 §10.8).
     */
    private byte cardDecision(byte[] apduBuffer) {
        short tvrOffset = staticData.getCDOL1ValueOffset(TlvTags.TAG_TVR);
        short tvrLength = staticData.getCDOL1ValueLength(TlvTags.TAG_TVR);
        if (tvrOffset < 0 || tvrLength <= 0) {
            // No TVR in the CDOL: treat it as all zeroes.
            tvrOffset = 0;
            tvrLength = 0;
        }
        byte decided = CardRiskManagement.decide(apduBuffer, (short) (OFFSET_CDATA + tvrOffset),
                tvrLength,
                staticData.getIacDenial(), staticData.getIacDenialLength(),
                staticData.getIacOnline(), staticData.getIacOnlineLength(),
                staticData.getIacDefault(), staticData.getIacDefaultLength());
        // Offline velocity checking (EMV v4.4 Book 3 Annex C §C9.3): an exceeded lower
        // (or upper) limit forces the transaction online; the second AC then
        // declines it if the terminal could not go online.  The CVR "Last Online
        // Transaction Not Completed" bit likewise forces an online-capable
        // terminal's transaction online (EMV v4.4 Book 3 §9.2.3.2).  Neither may
        // override an IAC-Denial decision, which is absolute (EMV v4.4 Book 3 §10.7).
        if (decided != EMVCodes.AAC_CODE
                && (offlineRisk.forceOnline() || protocolState.isLastOnlineNotCompleted())) {
            decided = EMVCodes.ARQC_CODE;
        }
        return decided;
    }

    public void generateSecondAC(APDU apdu, byte[] apduBuffer, byte[] response) {
        // First 2 bits of P1 specify the type
        // These bits also have to be returned, as the Cryptogram Information Data (CID);
        // See EMV v4.4 Book 3 §6.5.5.4 (CCD).
        byte requestedCid = (byte) (apduBuffer[OFFSET_P1] & 0xC0);
        byte cid = requestedCid;
        // P1 b5-b4: 10 = CDA, 01 = XDA (not implemented), 11 = RFU (EMV v4.4 Book 3 Table 12).
        // The RFU value must not be verified (EMV v4.4 Book 3 §6.3.6) and is
        // treated as "no CDA/XDA signature requested".
        byte odaBits = (byte) (apduBuffer[OFFSET_P1] & ODA_MASK);
        if (odaBits == ODA_XDA) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED); // 6A81
        }
        boolean invalidated = protocolState.getLifecycle() == EMVRoles.BLOCKED;
        if (invalidated) {
            // Only AAC for an invalidated application (EMV v4.4 Book 2 Annex D3).
            cid = EMVCodes.AAC_CODE;
        } else if (cid == EMVCodes.RFU_CODE || cid == EMVCodes.ARQC_CODE) {
            // A second GENERATE AC shall return only a TC or an AAC
            // (EMV v4.4 Book 3 §9.3/§9.3.2).  An ARQC or RFU request is therefore
            // treated as a TC request that the card may still downgrade below.
            cid = EMVCodes.TC_CODE;
        }
        if (protocolState.getFirstACGenerated() == EMVCodes.AAC) {
            // EMV v4.4 Book 3 §9.3: the cryptogram types are hierarchical
            // (TC highest, ARQC, AAC lowest) and the second GENERATE AC may
            // only return a TC or an AAC.  A first AC that was an AAC must not
            // be upgraded by the second AC, so it caps the response at AAC.
            cid = EMVCodes.AAC_CODE;
        }
        short cdol2Length = staticData.getCDOL2DataLength();

        // Read the Authorisation Response Code first.  When the terminal could
        // not go online (ARC 'Y3'/'Z3') the second AC decides offline and no
        // issuer authentication is expected, so an all-zero inline tag '91'
        // must not be treated as a failed issuer authentication
        // (EMV v4.4 Book 3 §10.11.1.2 / Book 4 Annex A6 Table 35).
        boolean unableToGoOnline = false;
        short arcOffset = staticData.getCDOL2ValueOffset(
                TlvTags.TAG_AUTHORISATION_RESPONSE_CODE);
        if (arcOffset >= 0 && (short) (arcOffset + 2) <= cdol2Length) {
            unableToGoOnline = OfflineRisk.unableToGoOnline(
                    apduBuffer[(short) (OFFSET_CDATA + arcOffset)],
                    apduBuffer[(short) (OFFSET_CDATA + arcOffset + 1)]);
        }

        // Issuer authentication (EMV v4.4 Book 2 §8.2).  The CCD default carries
        // the Issuer Authentication Data (tag 91) inline in CDOL2 and completes
        // issuer authentication here; the generic profile (AIP byte 1 bit 3
        // set) uses EXTERNAL AUTHENTICATE instead, handled by IssuerAuth.  An
        // unable-to-go-online second AC skips it: there is no issuer response
        // to authenticate against and CVR1 reports "Not Performed".
        if (!invalidated && !unableToGoOnline
                && !staticData.externalAuthenticateSupported(protocolState.getRole())) {
            issuerAuth.performInlineIssuerAuth(apduBuffer, cdol2Length,
                    firstCdol, firstCdolLength);
        }
        if (!invalidated && protocolState.isIssuerAuthFailed()) {
            // Issuer authentication was performed and failed: decline the
            // transaction (EMV v4.4 Book 3 §10.11.1.2).
            cid = EMVCodes.AAC_CODE;
        }
        if (!invalidated && cid != EMVCodes.AAC_CODE && protocolState.isCsuApplied()
                && !protocolState.isIssuerApprovedOnline()) {
            // CCD CSU byte 2 b8 "Issuer Approves Online Transaction" is not
            // set: decline even though the ARPC verified and the terminal
            // requested a TC (EMV v4.4 Book 3 §10.11.1.1 / Annex C §C10).
            cid = EMVCodes.AAC_CODE;
        }

        // Offline velocity checking (EMV v4.4 Book 3 Annex C §C9.3): an upper limit that
        // is exceeded at a terminal that could not go online (ARC Y3/Z3)
        // declines the transaction even though the terminal requested a TC.
        // The ARC was read above, before inline issuer authentication.
        if (!invalidated && cid != EMVCodes.AAC_CODE && unableToGoOnline
                && offlineRisk.upperExceeded()) {
            cid = EMVCodes.AAC_CODE;
        }

        boolean cdaRequested = !invalidated && cid != EMVCodes.AAC_CODE
                && odaBits == ODA_CDA;
        if (cdaRequested && !ddaCrypto.isAvailable()) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        if (cdaRequested) {
            protocolState.setCdaPerformed();
        }
        // Build the CVR-bearing IAD before the AC is computed (EMV v4.4 Book 3 Annex C §C9).
        cvrBuilder.build(acType(cid), true, cdaRequested, unableToGoOnline);
        // The "Last Online Transaction Not Completed" bit stays set until the
        // transaction successfully went online (ARC not Y3/Z3) or issuer
        // authentication succeeded; an unable-to-go-online second AC must not
        // clear it (EMV v4.4 Book 3 §9.2.3.2).
        if (!unableToGoOnline) {
            protocolState.setLastOnlineNotCompleted(false);
        }

        if (cdaRequested) {
            dynamicAuth.copyUn(staticData.getCDOL2UnOffset(), cdol2Length, apduBuffer);
            theCrypto.computeSecondAC(apduBuffer, cdol2Length, theCrypto.getLastAc(), (short) 0);
            protocolState.setSecondACGenerated(acType(cid));
            finalizer.completeOnlineSession(!unableToGoOnline);
            finalizer.complete(cid, true, !unableToGoOnline, requestedCid,
                    firstCdol, firstCdolLength);
            dynamicAuth.generateCda(apdu, cid, protocolState.getATC(), theCrypto.getLastAc(),
                    firstCdol, (short) 0, firstCdolLength,
                    apduBuffer, OFFSET_CDATA, cdol2Length, response);
            return;
        }

        boolean format2 = protocolState.getRole() == EMVRoles.ROLE_CONTACTLESS
                || staticData.isCcdFormat();
        theCrypto.generateSecondACReponse(cid, apduBuffer, cdol2Length,
                response, (short) 0, format2);
        protocolState.setSecondACGenerated(acType(cid));
        finalizer.completeOnlineSession(!unableToGoOnline);
        finalizer.complete(cid, true, !unableToGoOnline, requestedCid,
                firstCdol, firstCdolLength);

        short length = Tlv.totalLength(response, (short) 0);
        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        apdu.sendBytesLong(response, (short) 0, length);
    }

    /** Maps a Cryptogram Information Data code to the AC type constant. */
    static byte acType(byte cid) {
        if (cid == EMVCodes.ARQC_CODE) {
            return EMVCodes.ARQC;
        }
        if (cid == EMVCodes.TC_CODE) {
            return EMVCodes.TC;
        }
        return EMVCodes.AAC;
    }

    /** Maps an AC type constant to the 2-bit CVR code (EMV v4.4 Book 3 Annex C §C9.3). */
    static byte acTypeCode(byte type) {
        if (type == EMVCodes.TC) {
            return (byte) 1;
        }
        if (type == EMVCodes.ARQC) {
            return (byte) 2;
        }
        return (byte) 0; // AAC (and NONE, which never reaches the CVR)
    }
}
