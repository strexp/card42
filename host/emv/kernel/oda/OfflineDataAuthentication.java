package card42.host.emv.kernel.oda;

import javax.smartcardio.ResponseAPDU;

import card42.host.emv.kernel.core.OdaVerifier;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TerminalDol;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.data.Tvr;
import card42.host.common.codec.Tags;
import card42.host.emv.oda.CaKeyStore;
import card42.host.emv.oda.CamVerifier;
import card42.host.emv.oda.SdaVerifier;
import card42.host.emv.lib.IssuerKey;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Reporter;

/**
 * Offline Data Authentication orchestration of the terminal kernel
 * (EMV v4.4 Book 2 §5, §6.5, §6.6) in the RSA profile.
 *
 * <p>It recovers and checks the issuer public key certificate with
 * {@link SdaVerifier}, recovers the ICC public key, runs DDA with INTERNAL
 * AUTHENTICATE and verifies CDA during GENERATE AC with {@link CamVerifier}.
 * The outcome is written to the kernel {@link TransactionResult} and the
 * TVR byte 1 bits (SDA/DDA/CDA selected/failed); the verifiers themselves hold
 * no EMV flow logic.
 */
public final class OfflineDataAuthentication implements OdaVerifier {

    private final Reporter reporter;
    private final CaKeyStore caKeyStore;

    public OfflineDataAuthentication(Reporter reporter, CaKeyStore caKeyStore) {
        this.reporter = reporter == null ? Reporter.noop() : reporter;
        this.caKeyStore = caKeyStore;
    }

    /**
     * Runs the single ODA method the AIP and the terminal capabilities select
     * (EMV v4.4 Book 3 §10.3, priority XDA &gt; CDA &gt; DDA &gt; SDA) and records
     * the result in {@code result}.
     */
    @Override
    public void verify(Terminal terminal, TransactionRequest data,
            TransactionResult.Mutable result) throws Exception {
        boolean cardSda = (result.aip() & 0x4000) != 0;
        boolean cardDda = (result.aip() & 0x2000) != 0;
        boolean cardCda = (result.aip() & 0x0100) != 0;
        boolean cardXda = (result.aip() & 0x8000) != 0;
        // Terminal Capabilities byte 3 (EMV v4.4 Book 4 Annex A2 Table 27).
        byte[] terminalCapabilities = data.config.terminalCapabilities;
        int cap3 = terminalCapabilities.length >= 3
                ? terminalCapabilities[2] & 0xFF : 0;
        boolean termSda = (cap3 & 0x80) != 0;
        boolean termDda = (cap3 & 0x40) != 0;
        boolean termCda = (cap3 & 0x08) != 0;
        boolean termXda = (cap3 & 0x04) != 0;

        // The terminal selects the highest-priority method both the ICC and the
        // terminal support (EMV v4.4 Book 3 §10.3).
        boolean xda = cardXda && termXda;
        boolean cda = !xda && cardCda && termCda;
        boolean dda = !xda && !cda && cardDda && termDda;
        boolean sda = !xda && !cda && !dda && cardSda && termSda;
        if (!sda && !dda && !cda) {
            // No supported method (XDA is out of scope; the kernel implements no
            // ECC), so offline data authentication is not performed.
            Tvr.set(result.tvr(), 0, Tvr.ODA_NOT_PERFORMED);
            return;
        }
        // An ODA method was selected and its processing is entered; the TSI
        // 'ODA performed' bit is set regardless of the outcome (EMV v4.4 Book 3 §10.3).
        result.odaAttempted(true);
        if (sda) {
            Tvr.set(result.tvr(), 0, Tvr.SDA_SELECTED);
        }
        if (cda) {
            result.cdaSelected(true);
        }

        // The issuer public key certificate is needed for SDA, DDA and CDA
        // (EMV v4.4 Book 2 §5).  Only SDA verifies the SSAD; DDA/CDA recover the
        // issuer key and then the ICC key (EMV v4.4 Book 3 §10.3).
        SdaVerifier.Result issuer = SdaVerifier.verify(terminal, result.afl(), result.aip(),
                caKeyStore, sda, data.transactionDate);
        if (!issuer.ok) {
            reporter.info("  kernel SDA     : " + issuer.reason);
            if (issuer.dataMissing) {
                // Required ODA certificate data absent (Book 3 §7.5 Table 35).
                Tvr.set(result.tvr(), 0, Tvr.ICC_DATA_MISSING);
            }
            if (sda) {
                result.sdaFailed(true);
                Tvr.set(result.tvr(), 0, Tvr.SDA_FAILED);
            } else if (dda) {
                result.ddaFailed(true);
                Tvr.set(result.tvr(), 0, Tvr.DDA_FAILED);
            } else {
                result.cdaFailed(true);
                Tvr.set(result.tvr(), 0, Tvr.CDA_FAILED);
            }
            result.iccKey(null);
            return;
        }
        if (sda) {
            result.sdaPerformed(true);
            // Data Authentication Code recovered from the SSAD (9F45).
            result.dataAuthenticationCode(issuer.dataAuthenticationCode);
        }
        result.issuerKey(issuer.key);

        if (dda || cda) {
            SdaVerifier.Result icc = SdaVerifier.recoverIccKey(terminal, issuer.key,
                    data.transactionDate);
            result.iccKey(icc.key);
            if (!icc.ok) {
                reporter.info("  kernel ICC key : " + icc.reason);
                if (icc.dataMissing) {
                    Tvr.set(result.tvr(), 0, Tvr.ICC_DATA_MISSING);
                }
                if (dda) {
                    result.ddaFailed(true);
                    Tvr.set(result.tvr(), 0, Tvr.DDA_FAILED);
                } else {
                    result.cdaFailed(true);
                    Tvr.set(result.tvr(), 0, Tvr.CDA_FAILED);
                }
            }
        }

        if (dda && result.iccKey() != null) {
            // The ICC DDOL ('9F49') tells the terminal which data to sign; a
            // CCD ICC that supports DDA must carry one (EMV v4.4 Book 2 CCD §6.5.1).
            // Fall back to the 4-byte Unpredictable Number when absent.
            byte[] ddolDefinition = result.firstValue(0x9F49);
            byte[] ddol = ddolDefinition != null
                    ? TerminalDol.buildDolData(data, result, ddolDefinition)
                    : data.unpredictableNumber.clone();
            ResponseAPDU r = terminal.internalAuthenticate(ddol);
            byte[] sdad = null;
            if (r.getSW() == 0x9000) {
                // A CCD application returns Format 2 (77 { 9F4B }); the
                // generic profile returns Format 1 (primitive '80').
                sdad = Tags.find(r.getData(), 0x9F4B);
                if (sdad == null) {
                    sdad = Tags.find(r.getData(), 0x80);
                }
            }
            CamVerifier.Result ddaResult = sdad == null
                    ? CamVerifier.Result.failure("DDA: no SDAD in the response")
                    : CamVerifier.verifyDda(sdad, ddol, result.iccKey());
            if (!ddaResult.ok) {
                reporter.info("  kernel DDA     : " + ddaResult.reason);
                result.ddaFailed(true);
                Tvr.set(result.tvr(), 0, Tvr.DDA_FAILED);
            } else {
                result.ddaPerformed(true);
                // ICC Dynamic Number recovered from the DDA signature (9F4C).
                result.iccDynamicNumber(ddaResult.iccDynamicNumber);
            }
        }
    }

    /**
     * Verifies a CDA SDAD from a GENERATE AC response (EMV v4.4 Book 2 §6.6) and
     * records a failure in the TVR.
     *
     * @return the recovered Application Cryptogram, or null on failure
     */
    @Override
    public byte[] verifyCda(byte[] responseData, byte[] cdol1Data, byte[] cdol2Data,
            byte[] pdolData, byte[] unpredictableNumber, IssuerKey iccKey,
            int expectedCid, TransactionResult.Mutable result) {
        CamVerifier.Result cda = CamVerifier.verifyCda(responseData, cdol1Data, cdol2Data,
                pdolData, unpredictableNumber, iccKey, null, expectedCid);
        if (!cda.ok) {
            reporter.info("  kernel CDA     : " + cda.reason);
            Tvr.set(result.tvr(), 0, Tvr.CDA_FAILED);
        } else {
            // ICC Dynamic Number recovered from the CDA signature (9F4C).
            result.iccDynamicNumber(cda.iccDynamicNumber);
        }
        return cda.value;
    }
}
