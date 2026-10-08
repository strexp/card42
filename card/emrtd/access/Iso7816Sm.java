package card42.emrtd;

import card42.common.RetailMac;

import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/* ISO/IEC 7816-4 secure messaging for BAC (ICAO Doc 9303-11 §9.8).
 *
 * The framing is in {@link AbstractSecureMessaging}; this profile adds the
 * 3DES-CBC encryption with a zero IV and the ISO/IEC 9797-1 algorithm 3
 * (retail) MAC keyed with Ks_mac.  The send sequence counter enters the MAC
 * input in its 8-byte form.
 *
 * The MAC itself is {@link RetailMac}, which prefers the platform ISO 9797-1 MAC
 * engine and falls back to the manual CBC loop on a platform without it.
 *
 * @author card42
 */

public final class Iso7816Sm extends AbstractSecureMessaging {

    private final Cipher des3;
    private final RetailMac retailMac;

    /** Reused all-zero 3DES-CBC initialization vector. */
    private final byte[] zeroIv = new byte[8];

    public Iso7816Sm() {
        super(KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
                KeyBuilder.LENGTH_DES3_2KEY, false), (short) 8);
        des3 = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        retailMac = new RetailMac();
    }

    protected short blockSize() {
        return 8;
    }

    protected void zeroizeMac() {
        retailMac.zeroize();
    }

    protected void loadKey(byte[] k) {
        ((DESKey) key).setKey(k, (short) 0);
    }

    protected void prepareSsc(byte[] ssc) {
        // 3DES SM uses the 8-byte SSC directly; nothing to derive.
    }

    protected short copySsc(byte[] ssc, byte[] dst, short off) {
        Util.arrayCopyNonAtomic(ssc, (short) 0, dst, off, (short) 8);
        return 8;
    }

    protected void mac(byte[] ksMac, byte[] src, short len, byte[] out) {
        retailMac.macAligned(ksMac, (short) 0, (short) 16, src, (short) 0, len, out,
                (short) 0);
    }

    protected void encryptBlock(byte[] k, byte[] in, short inOff, short len,
                                byte[] out, short outOff) {
        setEncKey(k);
        des3.init(key, Cipher.MODE_ENCRYPT, zeroIv, (short) 0, (short) 8);
        des3.doFinal(in, inOff, len, out, outOff);
    }

    protected void decryptBlock(byte[] k, byte[] in, short inOff, short len,
                                byte[] out, short outOff) {
        setEncKey(k);
        des3.init(key, Cipher.MODE_DECRYPT, zeroIv, (short) 0, (short) 8);
        des3.doFinal(in, inOff, len, out, outOff);
    }
}
