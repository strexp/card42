package card42.host.emv.kernel.core;

import card42.host.emv.lib.IssuerKey;
import card42.host.emv.lib.Responses;

/**
 * The kernel-side write contract.  The implementation is package-private; a
 * third-party caller should consume {@link TransactionResult} (or one of its
 * read views) and only the kernel implementation constructs a writer through
 * {@link TransactionResult#newWriter()}.
 */
public interface TransactionResultWriter extends TransactionResult {

    TransactionResultWriter aidHex(String v);

    TransactionResultWriter fci(byte[] v);

    TransactionResultWriter aip(int v);

    TransactionResultWriter afl(byte[] v);

    TransactionResultWriter pdolData(byte[] v);

    TransactionResultWriter record1(byte[] v);

    TransactionResultWriter cdol1Data(byte[] v);

    TransactionResultWriter cdol2Data(byte[] v);

    TransactionResultWriter tvr(byte[] v);

    TransactionResultWriter tsi(byte[] v);

    TransactionResultWriter cvmResults(byte[] v);

    TransactionResultWriter onlinePinBlock(byte[] v);

    TransactionResultWriter signature(byte[] v);

    TransactionResultWriter sdaPerformed(boolean v);

    TransactionResultWriter sdaFailed(boolean v);

    TransactionResultWriter ddaPerformed(boolean v);

    TransactionResultWriter ddaFailed(boolean v);

    TransactionResultWriter cdaPerformed(boolean v);

    TransactionResultWriter cdaFailed(boolean v);

    TransactionResultWriter cdaSelected(boolean v);

    TransactionResultWriter odaAttempted(boolean v);

    TransactionResultWriter issuerKey(IssuerKey v);

    TransactionResultWriter iccKey(IssuerKey v);

    TransactionResultWriter dataAuthenticationCode(byte[] v);

    TransactionResultWriter iccDynamicNumber(byte[] v);

    TransactionResultWriter requestedFirstAc(byte v);

    TransactionResultWriter firstCid(byte v);

    TransactionResultWriter secondCid(byte v);

    TransactionResultWriter firstAc(Responses.AcResponse v);

    TransactionResultWriter secondAc(Responses.AcResponse v);

    TransactionResultWriter firstResponse(byte[] v);

    TransactionResultWriter secondResponse(byte[] v);

    TransactionResultWriter putRecord(int key, byte[] v);

    TransactionResultWriter wentOnline(boolean v);

    TransactionResultWriter issuerAuthPerformed(boolean v);

    TransactionResultWriter issuerAuthData(byte[] v);

    TransactionResultWriter arc(byte[] v);

    TransactionResultWriter declined(boolean v);

    TransactionResultWriter adviceRequired(boolean v);

    TransactionResultWriter serviceNotAllowed(boolean v);

    TransactionResultWriter cardCaptureRequested(boolean v);

    TransactionResultWriter referralRequested(boolean v);

    TransactionResultWriter attendantForcedAcceptance(boolean v);

    TransactionResultWriter reversalRequired(boolean v);

    TransactionResultWriter issuerScriptResults(byte[] v);

    TransactionResultWriter issuerScriptFailedBeforeFinalAc(boolean v);

    TransactionResultWriter issuerScriptFailedAfterFinalAc(boolean v);

    TransactionResultWriter outcome(Outcome v);
}
