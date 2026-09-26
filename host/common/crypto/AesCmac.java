package card42.host.common.crypto;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * ISO/IEC 9797-1 Algorithm 5 (CMAC) with AES, the host-side counterpart of the
 * card's {@code card42.AesCmac} (EMV v4.4 Book 2 section A1.2.2).
 *
 * The construction is
 *
 * <pre>
 *   L  := AES(KS)[0^16]
 *   K1 := L  &lt;&lt; 1, then xor '00..87' when msb(L)  was set
 *   K2 := K1 &lt;&lt; 1, then xor '00..87' when msb(K1) was set
 *   XB := XB xor K1 (no padding) or xor K2 (0x80 padding added)
 *   H  := AES(KS)[X1] ; Hi := AES(KS)[Xi xor Hi-1] ; MAC := s leftmost bytes of HB
 * </pre>
 *
 * It is locked against the RFC 4493 test vectors by
 * {@code test/emv/unit/card/crypto/AesVectorTest}.  Only AES-128 is needed by the
 * CV '6' profile (the simulator has no AES-256; docs/specs/common/cryptography.md §1).
 */
public final class AesCmac {

    /** CMAC constant C = 0^16 with the least significant bits set to 10000111b. */
    private static final byte C_LOW = (byte) 0x87;

    private AesCmac() {
    }

    /** Returns the full 16-byte AES-CMAC of msg under the 16-byte key. */
    public static byte[] mac(byte[] key, byte[] msg) throws GeneralSecurityException {
        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));

        byte[] l = aes.doFinal(new byte[16]);
        byte[] k1 = shiftLeft(l);
        if ((l[0] & 0x80) != 0) {
            k1[15] ^= C_LOW;
        }
        byte[] k2 = shiftLeft(k1);
        if ((k1[0] & 0x80) != 0) {
            k2[15] ^= C_LOW;
        }

        boolean aligned = msg.length > 0 && (msg.length % 16) == 0;
        int blocks = aligned ? msg.length / 16 : (msg.length / 16) + 1;
        byte[] last = new byte[16];
        int lastOff = (blocks - 1) * 16;
        if (aligned) {
            System.arraycopy(msg, lastOff, last, 0, 16);
            xor(last, k1);
        } else {
            int n = msg.length - lastOff;
            System.arraycopy(msg, lastOff, last, 0, n);
            last[n] = (byte) 0x80;
            xor(last, k2);
        }

        byte[] h = new byte[16];
        byte[] block = new byte[16];
        for (int i = 0; i < blocks - 1; i++) {
            for (int j = 0; j < 16; j++) {
                block[j] = (byte) (msg[i * 16 + j] ^ h[j]);
            }
            h = aes.doFinal(block);
        }
        for (int j = 0; j < 16; j++) {
            block[j] = (byte) (last[j] ^ h[j]);
        }
        return aes.doFinal(block);
    }

    /** Returns the s leftmost bytes (4..8) of the AES-CMAC of msg. */
    public static byte[] mac(byte[] key, byte[] msg, int s) throws GeneralSecurityException {
        return Arrays.copyOf(mac(key, msg), s);
    }

    private static byte[] shiftLeft(byte[] in) {
        byte[] out = new byte[16];
        int carry = 0;
        for (int i = 15; i >= 0; i--) {
            int b = in[i] & 0xFF;
            out[i] = (byte) ((b << 1) | carry);
            carry = (b >> 7) & 0x01;
        }
        return out;
    }

    private static void xor(byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++) {
            a[i] ^= b[i];
        }
    }
}
