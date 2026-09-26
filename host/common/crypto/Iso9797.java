package card42.host.common.crypto;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * ISO/IEC 9797-1 MAC algorithm 3 (padding method 2) and the related 3DES ECB
 * primitives, shared by every host module.
 *
 * <p>The construction (ANSI X9.19 retail MAC) is
 *
 * <pre>
 *   H_k := single-DES-CBC-MAC(K1, M2-pad(MSG))
 *   MAC := DES_enc(K1, DES_dec(K2, H_k))
 * </pre>
 *
 * <p>EMV uses it for the CV '5' Application Cryptogram (EMV v4.4 Book 2 §8.1.2)
 * and the secure-messaging MAC (EMV v4.4 Book 2 §9.2.3); ICAO 9303 uses it for
 * the BAC secure-messaging MAC (Doc 9303-11 §9.5).  The JDK provider wants the
 * full 24-byte 3DES key, so the 16-byte 2-key key is expanded to K1 || K2 || K1
 * for the single-DES operations.
 */
public final class Iso9797 {

    private Iso9797() {
    }

    /** The full 8-byte algorithm 3 MAC of data under the 16-byte 2-key key. */
    public static byte[] mac(byte[] key16, byte[] data) throws GeneralSecurityException {
        int padding = 8 - (data.length % 8);
        byte[] padded = new byte[data.length + padding];
        System.arraycopy(data, 0, padded, 0, data.length);
        padded[data.length] = (byte) 0x80;
        return macPadded(key16, padded, 8);
    }

    /** The leftmost {@code outLength} bytes of the algorithm 3 MAC of data. */
    public static byte[] mac(byte[] key16, byte[] data, int outLength)
            throws GeneralSecurityException {
        int padding = 8 - (data.length % 8);
        byte[] padded = new byte[data.length + padding];
        System.arraycopy(data, 0, padded, 0, data.length);
        padded[data.length] = (byte) 0x80;
        return macPadded(key16, padded, outLength);
    }

    /**
     * Algorithm 3 over an already block-aligned message, without adding the
     * padding step.  EMV Format 1 secure messaging pre-pads its message
     * (EMV v4.4 Book 2 Annex D2.3.1), so it uses this variant.  Returns the
     * leftmost {@code outLength} bytes of the 8-byte MAC.
     */
    public static byte[] macPadded(byte[] key16, byte[] padded, int outLength)
            throws GeneralSecurityException {
        if ((padded.length & 0x07) != 0) {
            throw new IllegalArgumentException("message is not block aligned");
        }
        byte[] k1 = Arrays.copyOfRange(key16, 0, 8);
        byte[] k2 = Arrays.copyOfRange(key16, 8, 16);

        Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
        byte[] h = new byte[8];
        byte[] block = new byte[8];
        des.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k1, "DES"));
        for (int i = 0; i < padded.length; i += 8) {
            for (int j = 0; j < 8; j++) {
                block[j] = (byte) (padded[i + j] ^ h[j]);
            }
            h = des.doFinal(block);
        }
        des.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k2, "DES"));
        h = des.doFinal(h);
        des.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k1, "DES"));
        return Arrays.copyOfRange(des.doFinal(h), 0, outLength);
    }

    /** Expands a 16-byte 2-key 3DES key to the JDK's 24-byte K1 || K2 || K1 form. */
    public static byte[] expandKey(byte[] key16) {
        byte[] key = new byte[24];
        System.arraycopy(key16, 0, key, 0, 16);
        System.arraycopy(key16, 0, key, 16, 8);
        return key;
    }

    /** Single-block 3DES ECB encryption (no padding). */
    public static byte[] des3Ecb(byte[] key16, byte[] block8)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(expandKey(key16), "DESede"));
        return cipher.doFinal(block8);
    }

    /** 3DES ECB decryption (no padding). */
    public static byte[] des3EcbDecrypt(byte[] key16, byte[] block8)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(expandKey(key16), "DESede"));
        return cipher.doFinal(block8);
    }

    /** 3DES CBC encryption with an explicit IV (no padding). */
    public static byte[] des3CbcEncrypt(byte[] key16, byte[] iv8, byte[] data)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(expandKey(key16), "DESede"),
                new javax.crypto.spec.IvParameterSpec(iv8));
        return cipher.doFinal(data);
    }

    /** 3DES CBC decryption with an explicit IV (no padding). */
    public static byte[] des3CbcDecrypt(byte[] key16, byte[] iv8, byte[] data)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(expandKey(key16), "DESede"),
                new javax.crypto.spec.IvParameterSpec(iv8));
        return cipher.doFinal(data);
    }

    /** 3DES CBC encryption with a zero IV (no padding). */
    public static byte[] des3CbcEncrypt(byte[] key16, byte[] data)
            throws GeneralSecurityException {
        return des3CbcEncrypt(key16, new byte[8], data);
    }
}
