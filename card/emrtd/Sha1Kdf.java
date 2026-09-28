package card42.emrtd;

import javacard.framework.Util;
import javacard.security.MessageDigest;

/* SHA-1 key derivation shared by BAC, PACE and Chip Authentication.
 *
 * KDF(x, counter) = SHA-1(x || 00 00 00 counter), truncated to 16 bytes
 * (ICAO Doc 9303-11 §9.7.2, BSI TR-03110-3 A.2.3.1).  The 3DES profiles adjust
 * the DES parity of the result, the AES profile does not.
 *
 * Each caller owns one instance (its MessageDigest and its small scratch), which
 * is exactly the state the three callers carried separately before.
 *
 * @author card42
 */

final class Sha1Kdf {

    private final MessageDigest sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);

    /** 4-byte SHA-1 derivation suffix 00 00 00 counter. */
    private final byte[] derivation = new byte[4];

    /** Scratch for the 20-byte SHA-1 output; the key is its first 16 bytes. */
    private final byte[] digest = new byte[20];

    /**
     * Derives the 16-byte key of x[off..off+len) for the given counter into
     * out[outOff..outOff+16).  Sets odd DES parity when {@code parity} is true.
     */
    void derive(byte[] x, short xOff, short xLen, byte counter,
                byte[] out, short outOff, boolean parity) {
        derivation[3] = counter;
        sha1.reset();
        sha1.update(x, xOff, xLen);
        sha1.update(derivation, (short) 0, (short) 4);
        sha1.doFinal(digest, (short) 0, (short) 0, digest, (short) 0);
        Util.arrayCopyNonAtomic(digest, (short) 0, out, outOff, (short) 16);
        if (parity) {
            BacCrypto.adjustParity(out, outOff, (short) 16);
        }
    }
}
