package card42.emv;

import card42.common.*;

import javacard.framework.Util;
import javacardx.crypto.Cipher;

/* ARPC verification for issuer authentication (EMV v4.4 Book 2 §8.2).
 *
 * Method 1 (generic EMV, §8.2.1): the 8-byte ARPC is
 * DES3_ECB(SK_AC)[ARQC xor (ARC || 00 x6)] for CV '5' and, for CV '6', the
 * leftmost 8 bytes of AES_ECB(SK_AC)[Y || Y0] with the same
 * Y = ARQC xor (ARC || 00 x6) and Y0 = 00 x8.  Method 2 (CCD, §8.2.2): the
 * 4-byte ARPC is the leftmost 4 bytes of the ISO/IEC 9797-1 algorithm 3 MAC
 * (CV '5') or the AES-CMAC (CV '6') over ARQC || CSU || proprietary
 * authentication data.
 *
 * The session key is the one EMVCrypto derived for the transaction's first AC;
 * it is fetched from there so both use the same key bytes.
 *
 * @author card42
 */

public class Arpc {

    private final EMVCrypto crypto;
    private final EMVProtocolState protocolState;
    private final Cipher desCipher;
    private final Cipher aesCipher;

    public Arpc(EMVCrypto crypto, EMVProtocolState protocolState) {
        this.crypto = crypto;
        this.protocolState = protocolState;
        this.desCipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
        this.aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
    }

    /**
     * ARPC Method 1 (EMV v4.4 Book 2 §8.2.1): for CV '5' the 8-byte ARPC is
     * DES3_ECB(SK_AC)[ARQC xor (ARC || 00 x6)]; for CV '6' it is the leftmost
     * 8 bytes of AES_ECB(SK_AC)[Y || Y0], with Y as before and Y0 = 00 x8.
     * The ARC is carried in the proprietary bytes of the EXTERNAL AUTHENTICATE
     * data (bytes 9-10).
     *
     * Returns true when the recomputed ARPC matches data[off..off+8).
     */
    public boolean verifyMethod1(byte[] data, short off, short len) {
        if (len < (short) 10) {
            return false;
        }
        // The ARPC message uses the shared work scratch (docs/specs/common/risks.md).
        byte[] scratch = protocolState.getWorkScratch((short) 40);
        try {
            // Y := ARQC xor (ARC || 00 x6).
            Util.arrayCopyNonAtomic(protocolState.getArqc(), (short) 0,
                    scratch, (short) 0, (short) 8);
            scratch[0] ^= data[(short) (off + 8)];
            scratch[1] ^= data[(short) (off + 9)];

            if (crypto.getProfile().isAes()) {
                // EMV v4.4 Book 2 §8.2.1: the AES ARPC is the leftmost 8 bytes of
                // AES(SK_AC)[ Y || Y0 ] with Y0 = 00 x8.  The jcsl AES doFinal
                // does not accept aliased buffers, so the 16-byte input
                // Y || Y0 at scratch[0..16) is encrypted into scratch[16..32).
                Util.arrayFillNonAtomic(scratch, (short) 8, (short) 8, (byte) 0);
                aesCipher.init(crypto.getSessionAESKey(), Cipher.MODE_ENCRYPT);
                aesCipher.doFinal(scratch, (short) 0, (short) 16, scratch, (short) 16);
                return ConstantTime.equals(scratch, (short) 16, data, off, (short) 8);
            }
            desCipher.init(crypto.getSessionDESKey(), Cipher.MODE_ENCRYPT);
            desCipher.doFinal(scratch, (short) 0, (short) 8, scratch, (short) 8);

            return ConstantTime.equals(scratch, (short) 8, data, off, (short) 8);
        } finally {
            // The working buffer holds ARQC-derived data: clear it (docs/specs/common/cryptography.md §9).
            Util.arrayFillNonAtomic(scratch, (short) 0, (short) scratch.length, (byte) 0);
        }
    }

    /**
     * ARPC Method 2 (CCD, EMV v4.4 Book 2 §8.2.2): the 4-byte ARPC is the
     * leftmost 4 bytes of the ISO/IEC 9797-1 algorithm 3 MAC over
     * ARQC || CSU || proprietary authentication data, keyed with SK_AC.
     *
     * Returns true when the recomputed ARPC matches data[off..off+4).
     */
    public boolean verifyMethod2(byte[] data, short off, short len) {
        if (len < (short) 8) {
            return false;
        }
        byte[] scratch = protocolState.getWorkScratch((short) 40);
        try {
            // CCD CSU byte 1 b8 "Proprietary Authentication Data Included"
            // decides whether proprietary bytes take part in the ARPC (EMV v4.4
            // EMV v4.4 Book 2 §8.2.2).  When the bit is clear the
            // proprietary length used for the ARPC is 0, whatever trailing bytes
            // the terminal sent; those bytes are not protected and must not
            // drive any card action.
            boolean proprietaryIncluded = (data[(short) (off + 4)] & 0x80) != 0;
            short proprietaryLength = (short) (len - 8);
            if (proprietaryIncluded && proprietaryLength > 8) {
                // EMV v4.4 Book 2 §8.2.2: the proprietary authentication data is 0-8
                // bytes; a longer field cannot be processed.
                return false;
            }
            short msgLength = proprietaryIncluded
                    ? (short) (12 + proprietaryLength) : (short) 12; // ARQC || CSU [+ proprietary]
            Util.arrayCopyNonAtomic(protocolState.getArqc(), (short) 0,
                    scratch, (short) 0, (short) 8);
            Util.arrayCopyNonAtomic(data, (short) (off + 4), scratch,
                    (short) 8, (short) (msgLength - 8));

            CryptoProfile profile = crypto.getProfile();
            if (profile.isAes()) {
                crypto.getAesCmac().mac(crypto.getSessionKey(), (short) 0,
                        profile.getKeyLength(), scratch, (short) 0, msgLength,
                        scratch, (short) 24);
            } else {
                crypto.getRetailMac().mac(crypto.getSessionKey(), (short) 0, (short) 16,
                        scratch, (short) 0, msgLength, scratch, (short) 24);
            }

            return ConstantTime.equals(scratch, (short) 24, data, off, (short) 4);
        } finally {
            Util.arrayFillNonAtomic(scratch, (short) 0, (short) scratch.length, (byte) 0);
        }
    }
}
