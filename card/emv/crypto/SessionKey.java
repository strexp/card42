package card42.emv;

import card42.common.*;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacardx.crypto.Cipher;

/* The EMV session-key derivation shared by the Application Cryptogram
 * (EMVCrypto), the ARPC verification and the secure-messaging MAC and
 * encipherment keys (EMV v4.4 Book 2 §8.2, §9.2/§9.3, Annex A1.3.1).
 *
 * The derivation is the "common session key derivation option": SK := F(KM)[R]
 * where R is the ATC followed by zero bytes for the AC/ARPC key, or the first
 * Application Cryptogram followed by zero bytes for the secure-messaging keys.
 *
 * For Triple DES (CV '5', n = 8) the two blocks are
 *
 *     F1 = R0 || R1 || 'F0' || R3..R7
 *     F2 = R0 || R1 || '0F' || R3..R7
 *     SK = DES3(MK)[F1] || DES3(MK)[F2]
 *
 * For AES (CV '6', n = 16) the derivation is
 *
 *     AES-128: SK = AES(MK)[R]
 *
 * where R is a 16-byte diversification value (R = ATC || 00 x14, or
 * AC || 00 x8).  The AES-192/256 form (SK = AES(MK)[F1] || AES(MK)[F2]) is not
 * used: the jcsl simulator has no AES-192/256 primitives
 * (docs/specs/common/cryptography.md §1), and EMV CPS v2.0 §A.2 only requires
 * AES-128/256 (no AES-192).
 *
 * A SessionKey object owns its ciphers and a small scratch buffer so the
 * transaction path allocates nothing; each user (EMVCrypto, SecureMessaging)
 * holds its own instance.
 *
 * @author card42
 */

public final class SessionKey {

    private final Cipher desCipher;
    private final Cipher aes128;
    private final byte[] data;

    public SessionKey() {
        desCipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
        aes128 = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        data = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Derives the 16-byte Triple DES session key of mk for the 8-byte
     * diversification value R (EMV v4.4 Book 2 section A1.3.1) into out/outOff.
     * The caller passes R = ATC || 00 x6 for the AC/ARPC session key, or
     * R = the first Application Cryptogram for the secure-messaging keys.
     */
    public void derive(DESKey mk, byte[] r, short rOff, byte[] out, short outOff) {
        Util.arrayCopyNonAtomic(r, rOff, data, (short) 0, (short) 8);

        desCipher.init(mk, Cipher.MODE_ENCRYPT);

        // Left 8 bytes: R0 || R1 || F0 || R3..R7.
        data[2] = (byte) 0xF0;
        desCipher.doFinal(data, (short) 0, (short) 8, out, outOff);

        // Right 8 bytes: R0 || R1 || 0F || R3..R7.
        data[2] = (byte) 0x0F;
        desCipher.doFinal(data, (short) 0, (short) 8, out, (short) (outOff + 8));
    }

    /**
     * Convenience for the 3DES AC/ARPC session key: derives with R = ATC || 00 x6.
     */
    public void derive(DESKey mk, short atc, byte[] out, short outOff) {
        Util.setShort(data, (short) 0, atc);
        Util.arrayFillNonAtomic(data, (short) 2, (short) 6, (byte) 0);
        derive(mk, data, (short) 0, out, outOff);
    }

    /**
     * Derives the AES session key of mk for the 16-byte diversification value R
     * (EMV v4.4 Book 2 §A1.3.1).  Only the AES-128 form is implemented
     * (keyLength 16); the result occupies 16 bytes at out/outOff.
     */
    public void deriveAes(AESKey mk, short keyLength, byte[] r, short rOff,
                          byte[] out, short outOff) {
        if (keyLength != 16) {
            javacard.framework.ISOException.throwIt((short) 0x6700);
        }
        Util.arrayCopyNonAtomic(r, rOff, data, (short) 0, (short) 16);
        aes128.init(mk, Cipher.MODE_ENCRYPT);
        aes128.doFinal(data, (short) 0, (short) 16, out, outOff);
    }

    /**
     * Convenience for the AES AC/ARPC session key: derives with
     * R = ATC || 00 x14 (the AES block size is 16).
     */
    public void deriveAes(AESKey mk, short keyLength, short atc, byte[] out, short outOff) {
        Util.setShort(data, (short) 0, atc);
        Util.arrayFillNonAtomic(data, (short) 2, (short) 14, (byte) 0);
        deriveAes(mk, keyLength, data, (short) 0, out, outOff);
    }
}
