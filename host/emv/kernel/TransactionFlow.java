package card42.host.emv.kernel;

import java.util.Arrays;
import java.util.Random;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.Responses;
import card42.host.emv.lib.TagPolicy;
import card42.host.common.codec.Tags;
import card42.host.emv.crypto.SmCrypto;
import card42.host.emv.kernel.analysis.CvmList;
import card42.host.emv.kernel.analysis.CvmPerformer;
import card42.host.emv.kernel.analysis.ProcessingRestrictions;
import card42.host.emv.kernel.analysis.TerminalActionAnalysis;
import card42.host.emv.kernel.analysis.TerminalRiskManagement;
import card42.host.emv.kernel.core.Authorization;
import card42.host.emv.kernel.core.OdaVerifier;
import card42.host.emv.kernel.core.EndApplicationException;
import card42.host.emv.kernel.core.Issuer;
import card42.host.emv.kernel.core.KernelListener;
import card42.host.emv.kernel.core.Selection;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.common.util.Bcd;
import card42.host.emv.kernel.data.TerminalDol;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.data.Tsi;
import card42.host.emv.kernel.data.Tvr;
import card42.host.emv.kernel.script.IssuerScriptProcessor;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Hex;
import card42.host.common.util.Reporter;

/**
 * The media-neutral transaction flow shared by the contact and the contactless
 * kernel (EMV v4.4 Book 3/4):
 *
 * <pre>
 *   application selection (supplied by the caller)
 *     -&gt; GET PROCESSING OPTIONS (PDOL)
 *     -&gt; READ RECORD (AFL)
 *     -&gt; Offline Data Authentication (SDA / DDA / CDA, RSA)
 *     -&gt; Processing Restrictions
 *     -&gt; Cardholder Verification (CVM List)
 *     -&gt; Terminal Risk Management (floor limit / random selection)
 *     -&gt; Terminal Action Analysis (TAC/IAC)
 *     -&gt; first GENERATE AC -&gt; online -&gt; second GENERATE AC
 * </pre>
 *
 * <p>The two kernels differ only in the {@link Selection} (PPSE Entry Point vs
 * PSE / direct ADF) and in the {@link CvmPerformer} (the contact kernel can
 * perform offline PIN, the contactless kernel cannot); everything from GPO on is
 * identical and lives here.  Each step is a private method so {@link #run} reads
 * as the sequence above.
 *
 * <p>It deliberately implements only the RSA profile: no ECC/XDA, no Book E
 * secure channel, no data exchange / data storage and no relay resistance.
 * An {@link Issuer} supplies the online authorisation (ARC and Issuer
 * Authentication Data) so the flow never needs the ICC master key; ODA is
 * verified from the certificates the card returns.
 */
final class TransactionFlow {

    private final Reporter reporter;
    private final OdaVerifier oda;
    private final Random random;
    private final KernelListener listener;

    TransactionFlow(Reporter reporter, Random random, OdaVerifier oda,
            KernelListener listener) {
        this.reporter = reporter == null ? Reporter.noop() : reporter;
        this.oda = oda;
        this.random = random;
        this.listener = listener == null ? KernelListener.NONE : listener;
    }

    /**
     * Runs one transaction into {@code result}: selects the application through
     * {@code selection}, then drives GPO through the second GENERATE AC.
     *
     * @return the same {@code result} instance
     */
    TransactionResult run(Terminal terminal, TransactionRequest data, Issuer issuer,
            Selection selection, CvmPerformer cvmPerformer, TransactionResult.Mutable result)
            throws Exception {
        beginTransaction(data, result);

        // --- Application selection (kernel-specific). ------------------------
        String aidHex = selection.select(terminal, data, result);
        result.aidHex(aidHex);
        reporter.info("  kernel SELECT  : " + aidHex);
        listener.onStep(KernelListener.Step.APPLICATION_SELECTION, result);
        return runActivated(terminal, data, issuer, selection, cvmPerformer, result);
    }

    /**
     * Resets the transaction and draws a fresh Unpredictable Number unless the
     * caller fixed one (EMV Contactless Book A v2.12 §8.1.1.8).  Called by the
     * Entry Point state machine before it activates the kernel.
     */
    void beginTransaction(TransactionRequest data, TransactionResult.Mutable result) {
        // The Transaction Sequence Counter is drawn for this transaction and
        // advanced for the next (EMV v4.4 Book 4 §6.5.5).
        data.transactionSequenceCounter = data.config.state.nextTransactionSequenceCounter();
        newUnpredictableNumber(data);
        // Expose the live TVR/TSI: ODA runs before the end-of-transaction
        // assignment and writes the TVR through the result.
        result.tvr(Tvr.blank()).tsi(Tsi.blank());
    }

    /**
     * Runs the transaction from GET PROCESSING OPTIONS to the second GENERATE
     * AC for an already selected application (EMV Contactless Book B v2.12 §3.4
     * kernel activation).  {@code selection} is used only for the GET PROCESSING
     * OPTIONS '6985' candidate reselection and may be null.
     */
    TransactionResult runActivated(Terminal terminal, TransactionRequest data, Issuer issuer,
            Selection selection, CvmPerformer cvmPerformer, TransactionResult.Mutable result)
            throws Exception {
        // --- GET PROCESSING OPTIONS (EMV v4.4 Book 3 §6.5.8). ----------------
        // Only ICC-sourced data objects are read from the card (Book 3 §7.5).
        // A '6985' response means the application cannot be used for this
        // transaction: the terminal removes it from the candidate list and
        // returns to application selection (EMV v4.4 Book 4 §6.3.1).
        byte[] gpoData;
        while (true) {
            byte[] pdol = TagPolicy.findIcc(result.fci(), 0x9F38);
            result.pdolData(TerminalDol.buildDolData(data, result,
                    pdol == null ? new byte[0] : pdol));
            ResponseAPDU gpo = terminal.gpo(result.pdolData());
            if (gpo.getSW() == 0x6985) {
                String next = selection == null ? null
                        : selection.reselect(terminal, data, result);
                if (next == null) {
                    throw new EndApplicationException("GPO 6985 and no further candidate");
                }
                result.aidHex(next);
                reporter.info("  kernel SELECT  : " + next + " (after GPO 6985)");
                continue;
            }
            if (gpo.getSW() != 0x9000) {
                throw new IllegalStateException("GPO -> " + sw(gpo.getSW()));
            }
            gpoData = gpo.getData();
            break;
        }
        byte[] aipBytes = Responses.gpoAip(gpoData);
        result.aip(((aipBytes[0] & 0xFF) << 8) | (aipBytes[1] & 0xFF));
        result.afl(Responses.gpoAfl(gpoData));
        reporter.info("  kernel GPO     : AIP=" + String.format("%04X", result.aip())
                + " AFL=" + Hex.format(result.afl()));
        listener.onStep(KernelListener.Step.INITIATE_APPLICATION_PROCESSING, result);

        // --- READ RECORD for every AFL entry. -------------------------------
        readAfl(terminal, result);
        listener.onStep(KernelListener.Step.READ_APPLICATION_DATA, result);

        // --- Offline Data Authentication (EMV v4.4 Book 2 §5/§6.5/§6.6). ------------
        oda.verify(terminal, data, result);
        if (result.odaAttempted() && !result.cdaSelected()) {
            // SDA/DDA: the 'ODA performed' bit is set upon completion of ODA
            // (EMV v4.4 Book 3 §10.3).  CDA is set after the first GENERATE AC.
            Tsi.set(result.tsi(), Tsi.ODA_PERFORMED);
        }
        listener.onStep(KernelListener.Step.OFFLINE_DATA_AUTHENTICATION, result);

        processingRestrictions(data, result);
        listener.onStep(KernelListener.Step.PROCESSING_RESTRICTIONS, result);

        cardholderVerification(data, result, cvmPerformer);
        listener.onStep(KernelListener.Step.CARDHOLDER_VERIFICATION, result);

        terminalRiskManagement(terminal, data, result);
        listener.onStep(KernelListener.Step.TERMINAL_RISK_MANAGEMENT, result);

        byte requestedFirstAc = terminalActionAnalysis(data, result);
        listener.onStep(KernelListener.Step.TERMINAL_ACTION_ANALYSIS, result);

        // --- GENERATE AC (CDA when the terminal selected CDA and recovered the ICC key). --
        boolean performCda = result.cdaSelected() && result.iccKey() != null;
        boolean firstCdaFailed = firstGenerateAc(terminal, data, result,
                requestedFirstAc, performCda);
        if (result.cdaSelected()) {
            // CDA Mode 1/2: 'ODA performed' is set immediately after the first
            // GENERATE AC (EMV v4.4 Book 3 §10.3).
            Tsi.set(result.tsi(), Tsi.ODA_PERFORMED);
        }
        listener.onStep(KernelListener.Step.CARD_ACTION_ANALYSIS, result);
        // CID advice bit b4 (EMV v4.4 Book 3 Table 15 / Book 4 §6.3.7).  A
        // 'Service not allowed' reason terminates the transaction immediately.
        noteAdvice(result, result.firstCid());
        if (result.serviceNotAllowed()) {
            result.secondCid(TerminalActionAnalysis.AAC).declined(true);
            if (result.arc() == null) {
                result.arc(new byte[] { 0x5A, 0x31 }); // 'Z1' offline declined
            }
        } else if (result.firstCid() == TerminalActionAnalysis.ARQC) {
            onlineOrOffline(terminal, data, issuer, result, performCda, firstCdaFailed);
        } else {
            finishOffline(result, firstCdaFailed);
        }

        listener.onStep(KernelListener.Step.COMPLETION, result);
        return result;
    }

    /** Processing Restrictions (EMV v4.4 Book 3 §10.4): -&gt; TVR byte 2. */
    private void processingRestrictions(TransactionRequest data, TransactionResult result) {
        byte[] cardVersion = result.firstValue(0x9F08);
        byte[] expiry = result.firstValue(0x5F24);
        byte[] effective = result.firstValue(0x5F25);
        byte[] auc = result.firstValue(0x9F07);
        // Domestic when the Issuer Country Code ('5F28') matches the Terminal
        // Country Code ('9F1A') (EMV v4.4 Book 3 §10.4.2 Table 36).  The AUC
        // checks require both the AUC and the Issuer Country Code, so a card
        // without '5F28' is not geographically restricted (§10.4.2).
        byte[] issuerCountry = result.firstValue(0x5F28);
        boolean domestic = issuerCountry != null
                && Arrays.equals(issuerCountry, data.config.terminalCountryCode);
        ProcessingRestrictions.Result restrictions = ProcessingRestrictions.check(
                result.tvr(), cardVersion, data.config.applicationVersionNumber, expiry, effective,
                data.transactionDate, auc, issuerCountry != null, data.transactionType,
                domestic, data.config.isAtm(), data.hasCashback());
        reporter.info("  kernel restrict: version=" + restrictions.versionMismatch
                + " expired=" + restrictions.expired + " auc=" + restrictions.serviceNotAllowed);
    }

    /**
     * Cardholder Verification (EMV v4.4 Book 3 §10.5, Book 4 §6.3.4.5 Table 2).
     *
     * <p>CVM processing only runs when the AIP says the ICC supports at least
     * one CVM; otherwise the CVM Results report 'No CVM performed' and the TSI
     * CVM bit stays clear.  Offline PIN is executed through {@code cvmPerformer}
     * when the kernel supplies one.
     */
    private void cardholderVerification(TransactionRequest data, TransactionResult.Mutable result,
            CvmPerformer cvmPerformer) {
        long amount = Bcd.bcdToLong(data.amountAuthorised);
        long amountOther = Bcd.bcdToLong(data.amountOther);
        byte[] applicationCurrency = result.firstValue(0x9F42);
        // Conditions 06-09 of EMV v4.4 Book 3 Table 44 require the transaction to be in
        // the application currency, i.e. Transaction Currency Code = Application
        // Currency Code ('5F2A' = '9F42').
        boolean transactionInApplicationCurrency = applicationCurrency != null
                && Arrays.equals(applicationCurrency, data.transactionCurrencyCode);
        if ((result.aip() & 0x1000) != 0) {
            byte[] cvmList = result.firstValue(0x8E);
            if (cvmList == null) {
                // AIP bit 5 says the ICC supports a CVM but the CVM List is
                // absent: 'ICC data missing' (EMV v4.4 Book 3 §7.5 Table 35).
                Tvr.set(result.tvr(), 0, Tvr.ICC_DATA_MISSING);
            }
            CvmList.Result cvm = CvmList.process(cvmList, amount, amountOther,
                    data.config.onlinePinSupported, data.config.signatureSupported,
                    data.config.cvmRequiredLimit,
                    transactionInApplicationCurrency, data.transactionType,
                    cvmPerformer, data.config.isUnattended(), result.tvr());
            if (cvm.formatError) {
                throw new IllegalStateException(
                        "CVM List formatting error -> terminate transaction");
            }
            result.cvmResults(cvm.toBytes());
            if (cvm.performed) {
                Tsi.set(result.tsi(), Tsi.CVM_PERFORMED);
            }
        } else {
            result.cvmResults(CvmList.none().toBytes());
        }
        reporter.info("  kernel CVM     : " + Hex.format(result.cvmResults()));
    }

    /** Terminal Risk Management (EMV v4.4 Book 3 §10.6): -&gt; TVR byte 4. */
    private void terminalRiskManagement(Terminal terminal, TransactionRequest data,
            TransactionResult.Mutable result) throws Exception {
        // Exception file (EMV v4.4 Book 4 §6.3.5): a matching card sets the TVR
        // 'Card appears in exception file' bit regardless of the AIP.
        byte[] pan = result.firstValue(0x5A);
        byte[] panSequence = result.firstValue(0x5F34);
        if (data.config.inExceptionFile(pan, panSequence)) {
            Tvr.set(result.tvr(), 0, Tvr.CARD_ON_EXCEPTION_FILE);
            reporter.info("  kernel exception file: card matches");
        }
        long amount = Bcd.bcdToLong(data.amountAuthorised);
        TerminalRiskManagement.floorLimit(result.tvr(), data.amountAuthorised, data.config.floorLimit);
        TerminalRiskManagement.randomSelection(result.tvr(), random, amount,
                data.config.targetPercentage, data.config.biasedRandomThreshold,
                data.config.maxTargetPercentage, data.config.floorLimit);
        TerminalRiskManagement.merchantForcedOnline(result.tvr(), data.merchantForcedOnline);
        // Velocity checking is performed only when both the Lower ('9F14') and
        // Upper ('9F23') Consecutive Offline Limits are present in the ICC
        // (EMV v4.4 Book 3 §10.6.3).
        byte[] lowerLimit = result.firstValue(0x9F14);
        byte[] upperLimit = result.firstValue(0x9F23);
        if (lowerLimit != null && upperLimit != null
                && lowerLimit.length >= 1 && upperLimit.length >= 1) {
            int atc = getDataValue(terminal, 0x9F, 0x36, 0x9F36);
            int lastOnlineAtc = getDataValue(terminal, 0x9F, 0x13, 0x9F13);
            TerminalRiskManagement.velocityChecking(result.tvr(), atc >= 0, atc,
                    lastOnlineAtc >= 0, lastOnlineAtc,
                    lowerLimit[0] & 0xFF, upperLimit[0] & 0xFF);
        }
        Tsi.set(result.tsi(), Tsi.TERMINAL_RISK_MANAGEMENT_PERFORMED);
    }

    /**
     * Terminal Action Analysis (EMV v4.4 Book 3 §10.7): the cryptogram to
     * request in the first GENERATE AC.
     */
    private byte terminalActionAnalysis(TransactionRequest data, TransactionResult.Mutable result) {
        byte[] iacDenial = result.firstValue(0x9F0E);
        byte[] iacOnline = result.firstValue(0x9F0F);
        byte requestedFirstAc;
        if (data.config.isOfflineOnly()) {
            // An offline-only terminal uses the Denial pair then the Default
            // pair, skipping the Online pair (EMV v4.4 Book 3 §10.7 option 2).
            byte[] iacDefault = result.firstValue(0x9F0D);
            requestedFirstAc = TerminalActionAnalysis.firstAcOfflineOnly(
                    result.tvr(), data.config.tacDenial, iacDenial,
                    data.config.tacDefault, iacDefault);
        } else {
            requestedFirstAc = TerminalActionAnalysis.firstAcOnlineCapable(
                    result.tvr(), data.config.tacDenial, data.config.tacOnline,
                    iacDenial, iacOnline);
            if (requestedFirstAc == TerminalActionAnalysis.TC && data.config.isOnlineOnly()) {
                // An online-only terminal never approves offline; it requests an
                // ARQC unless the Denial pair already forced an AAC
                // (EMV v4.4 Book 4 §12.2.1 / Book 3 §10.7).
                requestedFirstAc = TerminalActionAnalysis.ARQC;
            }
        }
        result.requestedFirstAc(requestedFirstAc);
        reporter.info("  kernel TVR     : " + Hex.format(result.tvr())
                + " -> request " + cidName(requestedFirstAc));
        return requestedFirstAc;
    }

    /**
     * First GENERATE AC and the CDA verification when the terminal recovered
     * the ICC key (EMV v4.4 Book 2 §6.6).
     *
     * @return true when a CDA verification failed
     */
    private boolean firstGenerateAc(Terminal terminal, TransactionRequest data,
            TransactionResult.Mutable result, byte requestedFirstAc, boolean performCda)
            throws Exception {
        byte[] cdol1 = result.firstValue(0x8C);
        if (cdol1 == null) {
            throw new IllegalStateException("record 1 has no CDOL1 (8C)");
        }
        byte[] cdol1Data = TerminalDol.buildDolData(data, result, cdol1);
        result.cdol1Data(cdol1Data);
        // When requesting an AAC the terminal must not request a CDA signature
        // (EMV v4.4 Book 2 §6.6).
        byte firstP1 = (byte) (requestedFirstAc
                | ((performCda && requestedFirstAc != TerminalActionAnalysis.AAC) ? 0x10 : 0x00));
        ResponseAPDU first = terminal.generateAc(firstP1, cdol1Data);
        if (first.getSW() != 0x9000) {
            throw new IllegalStateException("first GENERATE AC -> " + sw(first.getSW()));
        }
        result.firstResponse(first.getData());
        result.firstAc(Responses.parseAc(first));
        result.firstCid(result.firstAc().cid);
        Tsi.set(result.tsi(), Tsi.CARD_RISK_MANAGEMENT_PERFORMED);
        boolean firstCdaFailed = false;
        if (performCda && (result.firstCid() == TerminalActionAnalysis.TC
                || result.firstCid() == TerminalActionAnalysis.ARQC)) {
            byte[] recovered = oda.verifyCda(result.firstResponse(), cdol1Data, null,
                    result.pdolData(), data.unpredictableNumber, result.iccKey(),
                    result.firstCid() & 0xFF, result);
            if (recovered != null) {
                result.cdaPerformed(true);
                if (result.firstAc().ac == null) {
                    // A CDA response carries the AC inside the SDAD (EMV v4.4 Book 2 §6.6),
                    // so it is not returned as 9F26; use the recovered one.
                    result.firstAc().ac = recovered;
                }
            } else {
                result.cdaFailed(true);
                firstCdaFailed = true;
            }
        }
        reporter.info("  kernel first AC: " + cidName(result.firstCid())
                + (result.cdaPerformed() ? " (CDA)" : ""));
        return firstCdaFailed;
    }

    /**
     * Online processing and the second GENERATE AC (EMV v4.4 Book 3 §9.3/§10.7,
     * Book 4 §6.3.8/Annex A6), including the terminal-side issuer scripts
     * (Book 3 §10.10).
     */
    private void onlineOrOffline(Terminal terminal, TransactionRequest data, Issuer issuer,
            TransactionResult.Mutable result, boolean performCda, boolean firstCdaFailed)
            throws Exception {
        Authorization auth = null;
        boolean approved = false;
        boolean secondCdaFailed = false;
        byte secondP1;
        if (firstCdaFailed) {
            // CDA failed after an ARQC: the terminal immediately requests an
            // AAC at the second GENERATE AC without going online
            // (EMV v4.4 Book 4 §6.3.2.1).  The ARC is an offline decline.
            result.issuerAuthData(null);
            result.arc(new byte[] { 0x5A, 0x31 }); // 'Z1'
            secondP1 = TerminalActionAnalysis.AAC;
        } else {
            result.wentOnline(true);
            listener.onStep(KernelListener.Step.ONLINE_PROCESSING, result);
            auth = issuer.authorize(result.firstAc().ac, result.firstAc().atc, result);
            if (auth != null) {
                // TSI 'Issuer authentication was performed' only when the issuer
                // supplied Issuer Authentication Data ('91') for the card to
                // verify (EMV v4.4 Book 3 §10.9); a null '91' means no issuer
                // authentication was performed.
                if (auth.issuerAuthData != null) {
                    result.issuerAuthPerformed(true);
                    Tsi.set(result.tsi(), Tsi.ISSUER_AUTH_PERFORMED);
                }
                result.arc(auth.arc);
                result.issuerAuthData(auth.issuerAuthData);
                approved = issuerApproved(data, result, auth.arc);
                // An issuer decline makes the terminal request an AAC
                // (EMV v4.4 Book 4 §6.3.8).
                secondP1 = (byte) (approved
                        ? TerminalActionAnalysis.TC : TerminalActionAnalysis.AAC);
                if ((secondP1 & 0xC0) != TerminalActionAnalysis.AAC && performCda) {
                    secondP1 |= 0x10;
                }
            } else {
                // Unable to go online: the Default pair decides TC vs AAC
                // (EMV v4.4 Book 3 §10.7).  The ARC reflects the decision:
                // 'Y3' for offline approved and 'Z3' for offline declined
                // (EMV v4.4 Book 4 A6 Table 35).
                result.issuerAuthData(null);
                byte[] iacDefault = result.firstValue(0x9F0D);
                secondP1 = TerminalActionAnalysis.unableToGoOnline(
                        result.tvr(), data.config.tacDefault, iacDefault);
                if ((secondP1 & 0xC0) != TerminalActionAnalysis.AAC && performCda) {
                    secondP1 |= 0x10;
                }
                boolean declined = (secondP1 & 0xC0) == TerminalActionAnalysis.AAC;
                result.arc(declined
                        ? new byte[] { 0x5A, 0x33 } // 'Z3'
                        : new byte[] { 0x59, 0x33 }); // 'Y3'
            }
        }

        byte[] cdol2 = result.firstValue(0x8D);
        if (cdol2 == null) {
            throw new IllegalStateException("record 1 has no CDOL2 (8D)");
        }
        data.unpredictableNumber = nextUn();
        byte[] cdol2Data = TerminalDol.buildDolData(data, result, cdol2);
        result.cdol2Data(cdol2Data);

        // Issuer scripts tagged '71' are processed before the final GENERATE AC
        // (EMV v4.4 Book 3 §10.10), so a card-side state change they cause (for
        // example unblocking the offline PIN) can influence the second AC.
        IssuerScriptProcessor.Result scriptsBefore = processScripts(
                terminal, auth, 0x71, false);
        if (scriptsBefore != null) {
            Tsi.set(result.tsi(), Tsi.SCRIPT_PROCESSING_PERFORMED);
        }

        ResponseAPDU second = terminal.generateAc(secondP1, cdol2Data);
        if (second.getSW() != 0x9000) {
            throw new IllegalStateException("second GENERATE AC -> " + sw(second.getSW()));
        }
        result.secondResponse(second.getData());
        result.secondAc(Responses.parseAc(second));
        result.secondCid(result.secondAc().cid);
        if (performCda && result.secondCid() != TerminalActionAnalysis.AAC) {
            byte[] recovered = oda.verifyCda(result.secondResponse(), result.cdol1Data(),
                    cdol2Data, result.pdolData(), data.unpredictableNumber, result.iccKey(),
                    result.secondCid() & 0xFF, result);
            if (recovered != null) {
                result.cdaPerformed(true);
                if (result.secondAc().ac == null) {
                    result.secondAc().ac = recovered;
                }
            } else {
                result.cdaFailed(true);
                secondCdaFailed = true;
            }
        }
        reporter.info("  kernel second AC: " + cidName(result.secondCid()));

        // A CDA failure in conjunction with a GENERATE AC, an issuer decline,
        // or a second AC that is an AAC means the terminal does not approve the
        // transaction (EMV v4.4 Book 4 §6.3.2.1/§6.3.8).  A CDA failure detected
        // before the final TAA (e.g. key recovery) only sets the TVR bit and
        // lets Terminal Action Analysis decide (EMV v4.4 Book 4 §6.3.2.1), so
        // result.cdaFailed() alone does not decline here.
        noteAdvice(result, result.secondCid());
        result.declined(firstCdaFailed || secondCdaFailed
                || (auth != null && !approved)
                || result.secondCid() == TerminalActionAnalysis.AAC
                || result.serviceNotAllowed());
        // The card's final decision declined a transaction the issuer had
        // approved: the terminal must send a reversal when it supports online
        // data capture (EMV v4.4 Book 4 §6.3.8/§12.1.8).
        result.reversalRequired(auth != null && approved && result.declined());

        // Issuer scripts tagged '72' are processed after the final GENERATE AC
        // (EMV v4.4 Book 3 §10.10).
        IssuerScriptProcessor.Result scriptsAfter = processScripts(
                terminal, auth, 0x72, true);
        if (scriptsAfter != null) {
            Tsi.set(result.tsi(), Tsi.SCRIPT_PROCESSING_PERFORMED);
        }
        if (scriptsBefore != null || scriptsAfter != null) {
            mergeScripts(result, scriptsBefore, scriptsAfter);
            listener.onStep(KernelListener.Step.ISSUER_SCRIPT_PROCESSING, result);
        }
    }

    /**
     * Processes the online response's Issuer Script templates carrying the
     * given tag, or returns null when there is none.  EMV v4.4 Book 3 §10.10.
     */
    private static IssuerScriptProcessor.Result processScripts(Terminal terminal,
            Authorization auth, int tag, boolean afterFinalAc) throws Exception {
        if (auth == null || auth.issuerScripts == null) {
            return null;
        }
        java.util.List<byte[]> selected = new java.util.ArrayList<>();
        for (byte[] template : auth.issuerScripts) {
            if (SmCrypto.tagOf(template) == tag) {
                selected.add(template);
            }
        }
        if (selected.isEmpty()) {
            return null;
        }
        return IssuerScriptProcessor.process(terminal, afterFinalAc,
                selected.toArray(new byte[0][]));
    }

    /**
     * Aggregates the '71' (before) and '72' (after) script outcomes into the
     * transaction result and the TVR/TSI (EMV v4.4 Book 3 §10.10).
     */
    private void mergeScripts(TransactionResult.Mutable result,
            IssuerScriptProcessor.Result before, IssuerScriptProcessor.Result after) {
        byte[] results = new byte[(before == null ? 0 : before.results.length)
                + (after == null ? 0 : after.results.length)];
        int p = 0;
        if (before != null) {
            System.arraycopy(before.results, 0, results, p, before.results.length);
            p += before.results.length;
        }
        if (after != null) {
            System.arraycopy(after.results, 0, results, p, after.results.length);
        }
        result.issuerScriptResults(results);
        result.issuerScriptFailedBeforeFinalAc(before != null && before.failedBeforeFinalAc);
        result.issuerScriptFailedAfterFinalAc(after != null && after.failedAfterFinalAc);
        if (before != null) {
            IssuerScriptProcessor.applyToTvr(before, result.tvr());
        }
        if (after != null) {
            IssuerScriptProcessor.applyToTvr(after, result.tvr());
        }
        int sent = (before == null ? 0 : before.commandsSent)
                + (after == null ? 0 : after.commandsSent);
        boolean anyFailed = (before != null && before.anyFailed)
                || (after != null && after.anyFailed);
        reporter.info("  kernel issuer scripts: " + sent
                + " command(s), " + (anyFailed ? "failed" : "successful"));
    }

    /**
     * Offline first AC: TC or AAC.  Book 4 §6.3.6 sets the ARC to 'Y1' (offline
     * approved) or 'Z1' (offline declined).  A CDA failure after a TC means the
     * terminal declines and does not send a second GENERATE AC
     * (EMV v4.4 Book 4 §6.3.2.1).
     */
    private static void finishOffline(TransactionResult.Mutable result, boolean firstCdaFailed) {
        if (result.firstCid() == TerminalActionAnalysis.TC && firstCdaFailed) {
            result.secondCid(TerminalActionAnalysis.AAC).declined(true);
            result.arc(new byte[] { 0x5A, 0x31 }); // 'Z1'
        } else {
            result.secondCid(result.firstCid());
            result.declined(result.firstCid() == TerminalActionAnalysis.AAC);
            result.arc(result.declined()
                    ? new byte[] { 0x5A, 0x31 } // 'Z1'
                    : new byte[] { 0x59, 0x31 }); // 'Y1'
        }
    }

    // --- Records -------------------------------------------------------------

    /**
     * ICC-sourced data objects that shall appear at most once across the
     * transaction records (EMV v4.4 Book 3 §7.5: multiple occurrences of a
     * data object that should only appear once terminate the transaction).
     */
    private static final int[] SINGLE_OCCURRENCE = {
        0x5A,   // Application PAN
        0x5F24, // Application Expiration Date
        0x5F25, // Application Effective Date
        0x5F28, // Issuer Country Code
        0x5F34, // Application PAN Sequence Number
        0x56,   // Track 1 Equivalent Data
        0x57,   // Track 2 Equivalent Data
        0x8C,   // CDOL1
        0x8D,   // CDOL2
        0x8E,   // CVM List
        0x8F,   // Certification Authority Public Key Index
        0x90,   // Issuer Public Key Certificate
        0x92,   // Issuer Public Key Remainder
        0x93,   // Signed Static Application Data
        0x9F07, // Application Usage Control
        0x9F08, // Application Version Number (ICC)
        0x9F0D, // Issuer Action Code - Default
        0x9F0E, // Issuer Action Code - Denial
        0x9F0F, // Issuer Action Code - Online
        0x9F13, // Last Online ATC Register
        0x9F17, // PIN Try Counter
        0x9F32, // Issuer Public Key Exponent
        0x9F42, // Application Currency Code
        0x9F46, // ICC Public Key Certificate
        0x9F47, // ICC Public Key Exponent
        0x9F48, // ICC Public Key Remainder
        0x9F49, // Dynamic Data Authentication Data Object List (DDOL)
        0x9F4A, // Static Data Authentication Tag List
    };

    private void readAfl(Terminal terminal, TransactionResult.Mutable result) throws Exception {
        // AFL syntax (EMV v4.4 Book 3 §7.5): an AFL with no entries, a
        // non-multiple-of-4 length, an SFI of 0 or 31, a starting record of 0,
        // an ending record before the starting record, or more ODA records
        // than the entry covers terminates the transaction.
        byte[] afl = result.afl();
        if (afl == null || afl.length == 0 || (afl.length % 4) != 0) {
            throw new IllegalStateException("AFL syntax: empty or truncated AFL");
        }
        for (int e = 0; e + 3 < afl.length; e += 4) {
            int sfi = (afl[e] & 0xFF) >> 3;
            int first = afl[e + 1] & 0xFF;
            int last = afl[e + 2] & 0xFF;
            int odaRecords = afl[e + 3] & 0xFF;
            if (sfi == 0 || sfi == 31 || first == 0 || last < first
                    || odaRecords > (last - first + 1)) {
                throw new IllegalStateException("AFL syntax: SFI " + sfi
                        + " records " + first + ".." + last + " ODA " + odaRecords);
            }
        }
        for (int e = 0; e + 3 < afl.length; e += 4) {
            int sfi = (afl[e] & 0xFF) >> 3;
            int first = afl[e + 1] & 0xFF;
            int last = afl[e + 2] & 0xFF;
            for (int record = first; record <= last; record++) {
                ResponseAPDU r = terminal.readRecord(record, sfi);
                if (r.getSW() != 0x9000) {
                    throw new IllegalStateException("READ RECORD SFI " + sfi + " rec " + record
                            + " -> " + sw(r.getSW()));
                }
                result.putRecord((sfi << 8) | record, r.getData());
            }
        }
        result.record1(result.record(1, 1));
        checkSingleOccurrence(result);
        checkMandatoryObjects(result);
    }

    /**
     * Mandatory ICC data objects (EMV v4.4 Book 3 Table 28): the transaction
     * terminates when any of them is absent (EMV v4.4 Book 3 §7.5/§10.2).
     */
    private static final int[] MANDATORY_ICC_OBJECTS = {
        0x5F24, // Application Expiration Date
        0x5A,   // Application PAN
        0x8C,   // CDOL1
        0x8D,   // CDOL2
    };

    private static void checkMandatoryObjects(TransactionResult result) {
        for (int tag : MANDATORY_ICC_OBJECTS) {
            if (result.firstValue(tag) == null) {
                throw new IllegalStateException(String.format(
                        "mandatory data object %04X missing (EMV v4.4 Book 3 Table 28)", tag));
            }
        }
    }

    /**
     * Terminates the transaction when a single-occurrence data object is present
     * more than once (EMV v4.4 Book 3 §7.5).
     */
    private static void checkSingleOccurrence(TransactionResult result) {
        for (int tag : SINGLE_OCCURRENCE) {
            int count = 0;
            for (byte[] record : result.records().values()) {
                count += Tags.findAll(record, tag).size();
                if (count > 1) {
                    throw new IllegalStateException(String.format(
                            "duplicate data object %04X (Book 3 §7.5)", tag));
                }
            }
        }
    }

    /**
     * Draws a fresh Unpredictable Number unless the caller fixed one
     * (EMV Contactless Book A v2.12 §8.1.1.8): a new UN is needed on every
     * kernel activation, including a Start C Restart.
     */
    void newUnpredictableNumber(TransactionRequest data) {
        if (!data.unpredictableNumberFixed) {
            data.unpredictableNumber = nextUn();
        }
    }

    /**
     * Reads a 2-byte value with GET DATA and returns it as an unsigned integer,
     * or -1 when the tag is not returned (EMV v4.4 Book 3 §10.6.3).
     */
    private static int getDataValue(Terminal terminal, int p1, int p2, int tag)
            throws Exception {
        ResponseAPDU r = terminal.getData(p1, p2);
        byte[] value = r.getSW() == 0x9000 ? Tags.find(r.getData(), tag) : null;
        if (value == null || value.length != 2) {
            return -1;
        }
        return ((value[0] & 0xFF) << 8) | (value[1] & 0xFF);
    }

    private byte[] nextUn() {
        byte[] un = new byte[4];
        random.nextBytes(un);
        return un;
    }

    private static String sw(int sw) {
        return String.format("%04X", sw & 0xFFFF);
    }

    /**
     * The issuer's decision for an Authorisation Response Code
     * (EMV v4.4 Book 4 §6.5.2/§6.5.2.2, Annex A6): '00' approves; '01' is a
     * voice referral, which an attended terminal may have its attendant accept
     * or decline; '02' asks to capture the card.  Every other code declines, so
     * the terminal requests an AAC (EMV v4.4 Book 4 §6.3.8).  The terminal never
     * modifies the ARC.
     */
    private boolean issuerApproved(TransactionRequest data, TransactionResult.Mutable result,
            byte[] arc) {
        int code = arcCode(arc);
        if (code == 0) {
            return true;
        }
        if (code == 1) {
            result.referralRequested(true);
            if (data.config.isAttended() && data.config.referralHandler != null) {
                Boolean accept = data.config.referralHandler.referral(arc);
                if (Boolean.TRUE.equals(accept)) {
                    result.attendantForcedAcceptance(true);
                    return true;
                }
            }
            return false;
        }
        if (code == 2) {
            result.cardCaptureRequested(true);
        }
        return false;
    }

    /** The two-digit ISO 8583 response code of an ARC, or -1 when not numeric. */
    private static int arcCode(byte[] arc) {
        if (arc == null || arc.length < 2) {
            return -1;
        }
        int hi = arc[0] & 0xFF;
        int lo = arc[1] & 0xFF;
        if (hi < '0' || hi > '9' || lo < '0' || lo > '9') {
            return -1;
        }
        return (hi - '0') * 10 + (lo - '0');
    }

    /** Records the CID advice bit and reason on the result (EMV v4.4 Book 3 Table 15). */
    private static void noteAdvice(TransactionResult.Mutable result, byte cid) {
        if (Responses.adviceRequired(cid)) {
            result.adviceRequired(true);
            if (Responses.adviceReason(cid) == Responses.CID_SERVICE_NOT_ALLOWED) {
                result.serviceNotAllowed(true);
            }
        }
    }

    private static String cidName(byte cid) {
        switch (cid & 0xC0) {
        case 0x00: return "AAC";
        case 0x40: return "TC";
        case 0x80: return "ARQC";
        default: return String.format("%02X", cid & 0xFF);
        }
    }
}
