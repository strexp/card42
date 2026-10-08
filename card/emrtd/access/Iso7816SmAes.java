package card42.emrtd;

import card42.common.AesCmac;

import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/* ISO/IEC 7816-4 secure messaging for PACE with AES (BSI TR-03110-3 F.4,
 * ICAO Doc 9303-11 §4.6).  The framing is in {@link AbstractSecureMessaging};
 * this profile adds:
 *
 *   - encryption AES-128-CBC with IV = AES-ECB(K_enc, SSC16),
 *   - the AES-CMAC (ISO/IEC 9797-1 algorithm 5) checksum over the M2-padded
 *     (16-byte blocks) message, truncated to 8 bytes,
 *   - the send sequence counter encoded as 16 bytes (8 zero bytes then the
 *     64-bit big-endian counter).
 *
 * @author card42
 */

public final class Iso7816SmAes extends AbstractSecureMessaging {

    private final Cipher aesCbc;
    private final Cipher aesEcb;
    private final AesCmac aesMac;

    /** The 16-byte SSC form (8 zero bytes then the counter). */
    private final byte[] ssc16 = new byte[16];
    private final byte[] iv = new byte[16];

    public Iso7816SmAes() {
        super(KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
                KeyBuilder.LENGTH_AES_128, false), (short) 16);
        aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesEcb = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        aesMac = new AesCmac();
    }

    protected short blockSize() {
        return 16;
    }

    protected void zeroizeMac() {
        aesMac.zeroize();
    }

    protected void loadKey(byte[] k) {
        ((AESKey) key).setKey(k, (short) 0);
    }

    /** Expands the 8-byte SSC to the 16-byte AES form (8 zero bytes then the counter). */
    protected void prepareSsc(byte[] ssc) {
        Util.arrayFillNonAtomic(ssc16, (short) 0, (short) 8, (byte) 0);
        Util.arrayCopyNonAtomic(ssc, (short) 0, ssc16, (short) 8, (short) 8);
    }

    protected short copySsc(byte[] ssc, byte[] dst, short off) {
        Util.arrayCopyNonAtomic(ssc16, (short) 0, dst, off, (short) 16);
        return 16;
    }

    protected void mac(byte[] ksMac, byte[] src, short len, byte[] out) {
        aesMac.macAligned(ksMac, (short) 0, (short) 16, src, (short) 0, len, out,
                (short) 0);
    }

    /** IV = AES-ECB(K_enc, SSC16) (ICAO SAC TR §4.6.3). */
    private void initIv(byte[] k) {
        setEncKey(k);
        aesEcb.init(key, Cipher.MODE_ENCRYPT);
        aesEcb.doFinal(ssc16, (short) 0, (short) 16, iv, (short) 0);
    }

    protected void encryptBlock(byte[] k, byte[] in, short inOff, short len,
                                byte[] out, short outOff) {
        initIv(k);
        aesCbc.init(key, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) 16);
        aesCbc.doFinal(in, inOff, len, out, outOff);
    }

    protected void decryptBlock(byte[] k, byte[] in, short inOff, short len,
                                byte[] out, short outOff) {
        initIv(k);
        aesCbc.init(key, Cipher.MODE_DECRYPT, iv, (short) 0, (short) 16);
        aesCbc.doFinal(in, inOff, len, out, outOff);
    }
}
