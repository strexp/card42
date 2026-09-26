package card42.host.emv.app.issuer;

import java.util.Arrays;

import card42.host.emv.crypto.AcCrypto;
import card42.host.common.util.Bytes;

/**
 * Issuer-side online cryptography shared by the CLI and tests
 * (EMV v4.4 Book 2 §8.2 / §A1.3.1): ARPC Methods 1/2, the inline Issuer
 * Authentication Data (tag 91 = ARPC || CSU) and the block-cipher KCV.
 */
public final class IssuerCrypto {

    private IssuerCrypto() {
    }

    /** ARPC Method 1 (needs {@code arc}) or Method 2 (EMV v4.4 Book 2 §8.2). */
    public static byte[] arpc(int method, byte[] key, int atc, byte[] arqc, byte[] arc, byte[] csu)
            throws Exception {
        byte[] sk = AcCrypto.sessionKey(key, atc);
        if (method == 1) {
            if (arc == null) {
                throw new IllegalArgumentException("issuer arpc -method=1 needs -arc=<hex>");
            }
            return AcCrypto.computeArpcMethod1(sk, arqc, arc);
        }
        if (method == 2) {
            return AcCrypto.computeArpcMethod2(sk, arqc, csu, new byte[0]);
        }
        throw new IllegalArgumentException("-method must be 1 or 2");
    }

    /** Inline Issuer Authentication Data: ARPC Method 2 || CSU (tag 91). */
    public static byte[] inlineAuthData(byte[] iccKey, int atc, byte[] arqc, byte[] csu)
            throws Exception {
        byte[] sk = AcCrypto.sessionKey(iccKey, atc);
        return Bytes.concat(AcCrypto.computeArpcMethod2(sk, arqc, csu, new byte[0]), csu);
    }

    /** The block-cipher KCV: leftmost 3 bytes of DES3(key)[00 x8]. */
    public static byte[] kcv(byte[] key) throws Exception {
        return Arrays.copyOf(AcCrypto.des3Ecb(key, new byte[8]), 3);
    }
}
