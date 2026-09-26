package card42.host.emv.kernel.cvm;

import card42.host.emv.kernel.data.Cvm;
import card42.host.emv.kernel.analysis.CvmPerformer;

/**
 * Combined offline PIN and signature CVM performer (EMV v4.4 Book 3 Table 43,
 * Book 4 §6.3.4.5): CVM code '03' (plaintext PIN + signature) and '05'
 * (enciphered PIN + signature).
 *
 * <p>The terminal performs the offline PIN first and only on success captures
 * the signature; the CVM is successful only when both succeed.  The signature
 * itself cannot be verified, so a successful combined CVM reports 'unknown'
 * (EMV v4.4 Book 4 Table 2).
 */
public final class CombinedPinSignatureCvm implements CvmPerformer {

    private final CvmPerformer offlinePin;
    private final CvmPerformer signature;

    public CombinedPinSignatureCvm(CvmPerformer offlinePin, CvmPerformer signature) {
        this.offlinePin = offlinePin;
        this.signature = signature;
    }

    @Override
    public boolean supports(int method) {
        if (method == Cvm.CVM_PLAINTEXT_PIN_SIGNATURE) {
            return offlinePin.supports(Cvm.CVM_PLAINTEXT_PIN_ICC)
                    && signature.supports(Cvm.CVM_SIGNATURE);
        }
        if (method == Cvm.CVM_ENCIPHERED_PIN_SIGNATURE) {
            return offlinePin.supports(Cvm.CVM_ENCIPHERED_PIN_ICC)
                    && signature.supports(Cvm.CVM_SIGNATURE);
        }
        return false;
    }

    @Override
    public int perform(int method, int condition) {
        int pinMethod = method == Cvm.CVM_PLAINTEXT_PIN_SIGNATURE
                ? Cvm.CVM_PLAINTEXT_PIN_ICC : Cvm.CVM_ENCIPHERED_PIN_ICC;
        if (offlinePin.perform(pinMethod, condition) != Cvm.RESULT_SUCCESSFUL) {
            return Cvm.RESULT_FAILED;
        }
        if (signature.perform(Cvm.CVM_SIGNATURE, condition) == Cvm.RESULT_FAILED) {
            return Cvm.RESULT_FAILED;
        }
        return Cvm.RESULT_UNKNOWN;
    }
}
