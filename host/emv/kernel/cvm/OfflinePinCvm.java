package card42.host.emv.kernel.cvm;

import javax.smartcardio.ResponseAPDU;

import card42.host.emv.kernel.data.Cvm;
import card42.host.common.codec.Tags;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.kernel.analysis.CvmPerformer;
import card42.host.emv.kernel.core.PinProvider;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.data.Tvr;
import card42.host.emv.oda.SdaVerifier;
import card42.host.emv.lib.IssuerKey;
import card42.host.emv.lib.Terminal;

/**
 * Offline PIN CVM performer of the contact kernel (EMV v4.4 Book 2 §7.2,
 * EMV v4.4 Book 3 §10.5).
 *
 * <p>It supports the two plain offline PIN methods:
 * <ul>
 *   <li>'01' Plaintext PIN for ICC verification -&gt; VERIFY P2=80;</li>
 *   <li>'04' Enciphered PIN for offline verification -&gt; the ICC PIN
 *       encipherment public key certificate (record 4) is recovered with the
 *       issuer public key, an ICC Unpredictable Number is requested with
 *       GET CHALLENGE and the Table 25 block is sent in VERIFY P2=88.</li>
 * </ul>
 *
 * <p>This performer handles the standalone offline PIN methods only; the
 * combined PIN + signature methods ('03'/'05') are handled by
 * {@link CombinedPinSignatureCvm} in the composite performer
 * (EMV v4.4 Book 3 §10.5).
 *
 * <p>The performer reports the CVM outcome to {@link CvmList}; it additionally
 * sets the 'PIN try limit exceeded' TVR bit when the card reports a blocked PIN
 * (EMV v4.4 Book 4 Table 2).
 */
public final class OfflinePinCvm implements CvmPerformer {

    private final PinProvider pinProvider;
    private final Terminal terminal;
    private final TransactionRequest data;
    private final TransactionResult.Mutable result;

    public OfflinePinCvm(PinProvider pinProvider, Terminal terminal, TransactionRequest data,
                         TransactionResult.Mutable result) {
        this.pinProvider = pinProvider;
        this.terminal = terminal;
        this.data = data;
        this.result = result;
    }

    @Override
    public boolean supports(int method) {
        return method == Cvm.CVM_PLAINTEXT_PIN_ICC
                || method == Cvm.CVM_ENCIPHERED_PIN_ICC;
    }

    @Override
    public int perform(int method, int condition) {
        // EMV v4.4 Book 4 §6.3.4.1: read the PIN Try Counter (GET DATA '9F17')
        // before offline PIN; a zero counter means the PIN is blocked, so the
        // terminal skips PIN entry and sets 'PIN try limit exceeded'.
        if (pinTryCounterExhausted()) {
            Tvr.set(result.tvr(), 2, Tvr.PIN_TRY_LIMIT_EXCEEDED);
            return Cvm.RESULT_FAILED;
        }
        String pin = pinProvider == null ? null : pinProvider.pin();
        if (pin == null) {
            // The merchant or cardholder bypassed PIN entry: set 'PIN entry
            // required, PIN pad present, but PIN was not entered'
            // (EMV v4.4 Book 3 §10.5.1, EMV v4.4 Book 4 Table 2).
            Tvr.set(result.tvr(), 2, Tvr.PIN_NOT_ENTERED);
            return Cvm.RESULT_FAILED;
        }
        try {
            ResponseAPDU r = method == Cvm.CVM_ENCIPHERED_PIN_ICC
                    ? verifyEnciphered(pin)
                    : terminal.verifyOfflinePin(pin);
            if (r == null) {
                return Cvm.RESULT_FAILED;
            }
            int sw = r.getSW();
            if (sw == 0x9000) {
                return Cvm.RESULT_SUCCESSFUL;
            }
            if (sw == 0x63C0 || sw == 0x6983 || sw == 0x6984) {
                // PIN try limit exceeded / PIN blocked / PIN data unusable
                // (EMV v4.4 Book 3 §10.5.1, EMV v4.4 Book 4 §6.3.4.1/Table 2).
                // Note 63C1/63C2 (tries remaining > 0) do not set this bit.
                Tvr.set(result.tvr(), 2, Tvr.PIN_TRY_LIMIT_EXCEEDED);
            }
            return Cvm.RESULT_FAILED;
        } catch (Exception e) {
            return Cvm.RESULT_FAILED;
        }
    }

    /** True when GET DATA '9F17' reports a zero PIN Try Counter. */
    private boolean pinTryCounterExhausted() {
        try {
            ResponseAPDU r = terminal.getData(0x9F, 0x17);
            if (r.getSW() != 0x9000) {
                return false;
            }
            byte[] ptc = Tags.find(r.getData(), 0x9F17);
            return ptc != null && ptc.length >= 1 && (ptc[0] & 0xFF) == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Enciphered offline PIN (EMV v4.4 Book 2 §7.2, Table 25).  Returns the
     * VERIFY response, or null when the PIN key or the ICC Unpredictable Number
     * is unavailable (the CVM then fails).
     */
    private ResponseAPDU verifyEnciphered(String pin) throws Exception {
        if (result.issuerKey() == null) {
            return null;
        }
        SdaVerifier.Result pinKey = SdaVerifier.recoverPinKey(terminal, result.issuerKey(),
                data.transactionDate);
        IssuerKey key = pinKey.ok ? pinKey.key : null;
        if (key == null) {
            // EMV v4.4 Book 2 §7.1 step 2: when the Table 24 PIN encipherment
            // data is incomplete but the Table 12 data is complete, the ICC
            // DDA/CDA public key (Book 2 §6) is used for PIN encipherment.
            key = result.iccKey();
            if (key == null) {
                SdaVerifier.Result icc = SdaVerifier.recoverIccKey(terminal, result.issuerKey(),
                        data.transactionDate);
                if (icc.ok) {
                    key = icc.key;
                }
            }
        }
        if (key == null) {
            return null;
        }
        ResponseAPDU challenge = terminal.getChallenge();
        if (challenge.getSW() != 0x9000 || challenge.getData().length < 8) {
            return null;
        }
        byte[] iccUn = new byte[8];
        System.arraycopy(challenge.getData(), 0, iccUn, 0, 8);
        byte[] block = AcCrypto.emvEncipherPin(AcCrypto.iso9564Format2(pin), iccUn,
                key.modulus, key.exponent);
        return terminal.verifyEncryptedPin(block);
    }
}
