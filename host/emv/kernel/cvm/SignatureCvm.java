package card42.host.emv.kernel.cvm;

import card42.host.emv.kernel.data.Cvm;
import card42.host.emv.kernel.analysis.CvmPerformer;
import card42.host.emv.kernel.core.SignatureProvider;
import card42.host.emv.kernel.core.TransactionResult;

/**
 * Signature CVM performer (EMV v4.4 Book 3 §10.5, Book 4 Table 2).
 *
 * <p>It captures the cardholder signature through the host
 * {@link SignatureProvider} and exposes it on
 * {@link TransactionResult#signature()}.  The terminal cannot verify a signature,
 * so the reported CVM result is 'unknown'; a refused or unavailable capture
 * fails the CVM.
 */
public final class SignatureCvm implements CvmPerformer {

    private final SignatureProvider provider;
    private final TransactionResult.Mutable result;

    public SignatureCvm(SignatureProvider provider, TransactionResult.Mutable result) {
        this.provider = provider;
        this.result = result;
    }

    @Override
    public boolean supports(int method) {
        return method == Cvm.CVM_SIGNATURE;
    }

    @Override
    public int perform(int method, int condition) {
        byte[] captured = provider == null ? null : provider.capture();
        if (captured == null) {
            return Cvm.RESULT_FAILED;
        }
        result.signature(captured);
        return Cvm.RESULT_UNKNOWN;
    }
}
