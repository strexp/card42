package card42.host.emrtd.access;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import card42.host.common.crypto.AesCmac;

/**
 * Terminal-side ISO/IEC 7816-4 secure messaging for PACE with AES (BSI
 * TR-03110-3 F.4): AES-128-CBC with IV = AES-ECB(K_enc, SSC16), AES-CMAC
 * truncated to 8 bytes, and the 16-byte SSC form (8 zero bytes then the
 * counter).  The framing lives in {@link AbstractSecureMessaging}.
 */
public final class Iso7816SmAes extends AbstractSecureMessaging {

    public Iso7816SmAes(byte[] ksEnc, byte[] ksMac, long ssc) {
        super(ksEnc, ksMac, ssc);
    }

    @Override
    int blockSize() {
        return 16;
    }

    @Override
    byte[] encodedSsc() {
        long ssc = getSendSequenceCounter();
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[8 + i] = (byte) (ssc >>> (8 * (7 - i)));
        }
        return out;
    }

    @Override
    byte[] mac(byte[] key, byte[] padded) throws GeneralSecurityException {
        return Arrays.copyOf(AesCmac.mac(key, padded), 8);
    }

    @Override
    byte[] encrypt(byte[] key, byte[] padded) throws GeneralSecurityException {
        return aesCbc(key, Cipher.ENCRYPT_MODE, padded);
    }

    @Override
    byte[] decrypt(byte[] key, byte[] cipher) throws GeneralSecurityException {
        return aesCbc(key, Cipher.DECRYPT_MODE, cipher);
    }

    /** AES-128-CBC with IV = AES-ECB(K_enc, SSC16). */
    private byte[] aesCbc(byte[] key, int mode, byte[] data) throws GeneralSecurityException {
        Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
        ecb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] iv = ecb.doFinal(encodedSsc());
        Cipher cbc = Cipher.getInstance("AES/CBC/NoPadding");
        cbc.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cbc.doFinal(data);
    }
}
