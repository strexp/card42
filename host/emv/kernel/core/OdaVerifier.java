package card42.host.emv.kernel.core;

import card42.host.emv.lib.IssuerKey;
import card42.host.emv.lib.Terminal;
import card42.host.emv.kernel.data.TransactionRequest;

/**
 * The Offline Data Authentication step of the terminal kernel (EMV v4.4 Book 2
 * §5, §6.5, §6.6): runs the SDA/DDA/CDA method the AIP and the terminal
 * capabilities select and records the outcome, and verifies a CDA SDAD during
 * GENERATE AC.
 *
 * <p>The kernel orchestrator depends on this abstraction rather than on the
 * concrete ODA implementation, so the flow is not bound to one verifier.
 */
public interface OdaVerifier {

    /**
     * Runs offline data authentication and writes the outcome to {@code result}
     * (TVR/TSI bits and the recovered issuer/ICC keys).
     */
    void verify(Terminal terminal, TransactionRequest data, TransactionResult.Mutable result)
            throws Exception;

    /**
     * Verifies a CDA SDAD from a GENERATE AC response (EMV v4.4 Book 2 §6.6) and
     * records a failure in the TVR.
     *
     * @return the recovered Application Cryptogram, or null on failure
     */
    byte[] verifyCda(byte[] responseData, byte[] cdol1Data, byte[] cdol2Data,
                     byte[] pdolData, byte[] unpredictableNumber, IssuerKey iccKey,
                     int expectedCid, TransactionResult.Mutable result);
}
