package card42.emrtd;

import card42.common.RetailMac;

import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/* Basic Access Control key derivation and mutual authentication
 * (ICAO Doc 9303-11 §4.3, §9.7.2).
 *
 * K_enc and K_mac are the first 16 bytes of SHA-1(K_seed || 00 00 00 x) for
 * x = 1 and 2, with DES parity adjustment.  The mutual authentication follows
 * the standard three-pass BAC exchange; the card verifies M_IFD, recovers
 * RND.IFD || RND.ICC || K_IFD and answers with E_IC || M_IC built from a fresh
 * K_IC.  The session key seed is K_IFD XOR K_IC, from which the session keys
 * are derived by KDF (Doc 9303-11 §4.3.1 step 5 / §9.7.4, Appendix D.3).
 *
 * @author card42
 */

public final class BacCrypto {

    /** Marker appended to K_seed for K_enc (Doc 9303-11 §9.7.2). */
    public static final byte DERIVE_ENC = (byte) 0x01;
    /** Marker appended to K_seed for K_mac (Doc 9303-11 §9.7.2). */
    public static final byte DERIVE_MAC = (byte) 0x02;

    private static final short KEY_LENGTH = (short) 16;

    private final Sha1Kdf kdf;
    private final RetailMac retailMac;
    private final Cipher des3;
    private final DESKey key;

    /** Reused MAC output (the J3R180 does not reclaim per-call allocations). */
    private final byte[] macBuffer = new byte[8];

    /** Reused all-zero 3DES-CBC initialization vector. */
    private final byte[] zeroIv = new byte[8];

    public BacCrypto() {
        kdf = new Sha1Kdf();
        retailMac = new RetailMac();
        des3 = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        key = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
                KeyBuilder.LENGTH_DES3_2KEY, false);
    }

    /**
     * Derives K_enc (marker {@link #DERIVE_ENC}) or K_mac
     * ({@link #DERIVE_MAC}) from the 16-byte seed into out[outOff..+16) with
     * odd DES parity.
     */
    public void deriveKey(byte[] seed, short seedOff, byte marker, byte[] out, short outOff) {
        kdf.derive(seed, seedOff, KEY_LENGTH, marker, out, outOff, true);
    }

    /** Sets odd parity on each of the len key bytes (Doc 9303-11 §9.7.2 note). */
    public static void adjustParity(byte[] buf, short off, short len) {
        for (short i = 0; i < len; i++) {
            short b = (short) (buf[(short) (off + i)] & 0xFF);
            short ones = 0;
            for (short bit = 0; bit < 8; bit++) {
                ones += (short) ((b >> bit) & 1);
            }
            if ((ones & 1) == 0) {
                buf[(short) (off + i)] = (byte) (b ^ 0x01);
            }
        }
    }

    /** True when the 8-byte retail MAC over data equals the supplied MAC. */
    public boolean verifyMac(byte[] kmac, byte[] data, short dataOff, short dataLen,
                             byte[] mac, short macOff) {
        retailMac.mac(kmac, (short) 0, KEY_LENGTH, data, dataOff, dataLen, macBuffer, (short) 0);
        return card42.common.ConstantTime.equals(macBuffer, (short) 0, mac, macOff, (short) 8);
    }

    /** Writes the 8-byte retail MAC over data into out[outOff..) (reuses the MAC engine). */
    public void computeMac(byte[] kmac, byte[] data, short dataOff, short dataLen,
                           byte[] out, short outOff) {
        retailMac.mac(kmac, (short) 0, KEY_LENGTH, data, dataOff, dataLen, out, outOff);
    }

    /** 3DES-CBC encryption with a zero IV (Doc 9303-11 §4.3.3.1). */
    public short encrypt(byte[] k, byte[] in, short inOff, byte[] out, short outOff, short len) {
        key.setKey(k, (short) 0);
        des3.init(key, Cipher.MODE_ENCRYPT, zeroIv, (short) 0, (short) 8);
        return des3.doFinal(in, inOff, len, out, outOff);
    }

    /** 3DES-CBC decryption with a zero IV (Doc 9303-11 §4.3.3.1). */
    public short decrypt(byte[] k, byte[] in, short inOff, byte[] out, short outOff, short len) {
        key.setKey(k, (short) 0);
        des3.init(key, Cipher.MODE_DECRYPT, zeroIv, (short) 0, (short) 8);
        return des3.doFinal(in, inOff, len, out, outOff);
    }

    /**
     * Session key seed = K_IFD XOR K_IC (Doc 9303-11 §4.3.1 step 5 / §9.7.4,
     * Appendix D.3).  The session keys are derived from this seed with the same KDF as
     * the static keys ({@link #deriveKey}), not by XORing K_enc/K_mac with the
     * randoms.
     */
    public static void sessionSeed(byte[] kifd, short kifdOff,
                                   byte[] kic, short kicOff, byte[] out, short outOff) {
        for (short i = 0; i < KEY_LENGTH; i++) {
            out[(short) (outOff + i)] = (byte) (kifd[(short) (kifdOff + i)]
                    ^ kic[(short) (kicOff + i)]);
        }
    }

    /** The initial SSC: the 4 rightmost bytes of RND.ICC || RND.IFD (Doc 9303-11 §9.8.1). */
    public static void initialSsc(byte[] rndIcc, short iccOff, byte[] rndIfd, short ifdOff,
                                  byte[] ssc, short sscOff) {
        Util.arrayCopyNonAtomic(rndIcc, (short) (iccOff + 4), ssc, sscOff, (short) 4);
        Util.arrayCopyNonAtomic(rndIfd, (short) (ifdOff + 4), ssc,
                (short) (sscOff + 4), (short) 4);
    }
}
