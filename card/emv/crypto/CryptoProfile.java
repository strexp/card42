package card42.emv;

import card42.common.*;

/* The cryptogram profile of a payment instance: which symmetric algorithm the
 * Application Cryptogram, the ARPC and the secure messaging use.
 *
 * The CCD Common Core Definitions tie the algorithm to the Cryptogram Version
 * (CV) carried in the Issuer Application Data (EMV v4.4 Book 3 Annex C §C9):
 *
 *   CV '5' -> Triple DES, ISO/IEC 9797-1 Algorithm 3 (EMV v4.4 Book 2 §8.1.2)
 *   CV '6' -> AES, ISO/IEC 9797-1 Algorithm 5 / CMAC (EMV v4.4 Book 2 §8.1.2)
 *
 * The CV is selected during personalization (DGI 'E003', a project extension
 * carrying tag 9F69) and defaults to '5' so the existing 3DES profile is
 * unchanged when the DGI is absent.  The AES key length (tag 9F6A) is fixed at
 * 16 bytes: jcsl has no AES-192/256, so the personalization path rejects any
 * other value with 6A80 (docs/specs/common/cryptography.md §1).
 *
 * @author card42
 */

public final class CryptoProfile {

    /** Cryptogram Version '5': Triple DES. */
    public static final byte CV5 = (byte) 5;
    /** Cryptogram Version '6': AES. */
    public static final byte CV6 = (byte) 6;

    private byte cryptogramVersion;

    public CryptoProfile() {
        cryptogramVersion = CV5;
    }

    /**
     * Selects the cryptogram version.  The AES key length is fixed at 16 bytes:
     * jcsl has no AES-192/256, and the personalization path already rejects any
     * other value with 6A80 (docs/specs/common/cryptography.md §1).
     */
    public void select(byte cryptogramVersion) {
        this.cryptogramVersion = cryptogramVersion;
    }

    /** True when the AES / CMAC profile (CV '6') is selected. */
    public boolean isAes() {
        return cryptogramVersion == CV6;
    }

    /** The block-cipher key length in bytes: 16 for 3DES and for AES-128. */
    public short getKeyLength() {
        return (short) 16;
    }
}
