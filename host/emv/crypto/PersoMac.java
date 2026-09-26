package card42.host.emv.crypto;

import java.security.GeneralSecurityException;

import card42.host.common.crypto.Iso9797;

/**
 * ISO/IEC 9797-1 MAC algorithm 3 (padding method 2) helper shared by the host
 * tooling.
 *
 * <p>The card uses this algorithm for the Application Cryptogram (EMV v4.4 Book 2
 * §8.1.2, CCD Cryptogram Version '5') and for the secure-messaging MAC
 * (EMV v4.4 Book 2 §9.2.3), so {@code AcCrypto} recomputes the expected AC with
 * it.  The implementation is the generic {@link Iso9797} in the common module;
 * this class keeps the EMV-facing name and signature.
 */
public final class PersoMac {

    private PersoMac() {
    }

    /** Returns the 8-byte algorithm 3 MAC of data under the 16-byte 2-key key. */
    public static byte[] mac(byte[] key16, byte[] data) throws GeneralSecurityException {
        return Iso9797.mac(key16, data);
    }

    /**
     * Algorithm 3 over an already block-aligned message, without adding the
     * padding step.  EMV Format 1 secure messaging pre-pads its message
     * (EMV v4.4 Book 2 Annex D2.3.1), so it uses this variant.  Returns the
     * leftmost {@code outLength} bytes of the 8-byte MAC.
     */
    public static byte[] macPadded(byte[] key16, byte[] padded, int outLength)
            throws GeneralSecurityException {
        return Iso9797.macPadded(key16, padded, outLength);
    }
}
