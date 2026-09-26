package card42.host.emv.kernel.cvm;

import card42.host.emv.kernel.data.Cvm;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.kernel.analysis.CvmPerformer;
import card42.host.emv.kernel.core.OnlinePinProvider;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.data.Tvr;

/**
 * Online PIN CVM performer (EMV v4.4 Book 3 §10.5, EMV v4.4 Book 4 §6.3.4.4).
 *
 * <p>It captures the PIN through the host {@link OnlinePinProvider}, builds the
 * ISO 9564-1 format 0 PIN block with the Application PAN (tag '5A') and asks the
 * host to encrypt it.  The encrypted block is exposed on
 * {@link TransactionResult#onlinePinBlock()} for the issuer/acquirer.  Online PIN
 * cannot be verified offline, so the reported CVM result is 'unknown'.
 */
public final class OnlinePinCvm implements CvmPerformer {

    private final OnlinePinProvider provider;
    private final TransactionRequest data;
    private final TransactionResult.Mutable result;

    public OnlinePinCvm(OnlinePinProvider provider, TransactionRequest data,
                        TransactionResult.Mutable result) {
        this.provider = provider;
        this.data = data;
        this.result = result;
    }

    @Override
    public boolean supports(int method) {
        return method == Cvm.CVM_ONLINE_PIN;
    }

    @Override
    public int perform(int method, int condition) {
        String pin = provider == null ? null : provider.pin();
        if (pin == null) {
            // PIN entry was bypassed (EMV v4.4 Book 4 Table 2).
            Tvr.set(result.tvr(), 2, Tvr.PIN_NOT_ENTERED);
            return Cvm.RESULT_FAILED;
        }
        byte[] pan = result.firstValue(0x5A);
        if (pan == null) {
            Tvr.set(result.tvr(), 2, Tvr.PIN_PAD_NOT_PRESENT);
            return Cvm.RESULT_FAILED;
        }
        byte[] encrypted = provider.encryptPinBlock(AcCrypto.iso9564Format0(pin, pan));
        if (encrypted == null) {
            // No PIN encryption key: the terminal cannot perform online PIN.
            Tvr.set(result.tvr(), 2, Tvr.PIN_PAD_NOT_PRESENT);
            return Cvm.RESULT_FAILED;
        }
        result.onlinePinBlock(encrypted);
        Tvr.set(result.tvr(), 2, Tvr.ONLINE_PIN_ENTERED);
        return Cvm.RESULT_UNKNOWN;
    }
}
