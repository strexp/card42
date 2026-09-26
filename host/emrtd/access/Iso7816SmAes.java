package card42.host.emrtd.access;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import card42.host.common.crypto.AesCmac;

/**
 * Terminal-side ISO/IEC 7816-4 secure messaging for PACE with AES (BSI
 * TR-03110-3 F.4): AES-128-CBC with IV = AES-ECB(K_enc, SSC16), AES-CMAC
 * truncated to 8 bytes, and the 16-byte SSC form (8 zero bytes then the counter).
 * The framing matches {@link Iso7816Sm}.
 */
public final class Iso7816SmAes implements SecureMessaging {

    private final byte[] ksEnc;
    private final byte[] ksMac;
    private long ssc;

    public Iso7816SmAes(byte[] ksEnc, byte[] ksMac, long ssc) {
        this.ksEnc = ksEnc;
        this.ksMac = ksMac;
        this.ssc = ssc;
    }

    @Override
    public long getSendSequenceCounter() {
        return ssc;
    }

    @Override
    public byte[] wrapCommand(int cla, int ins, int p1, int p2, byte[] data, int le)
            throws GeneralSecurityException {
        ssc++;
        byte[] masked = { (byte) (cla | 0x0C), (byte) ins, (byte) p1, (byte) p2 };
        byte[] paddedHeader = pad(masked);

        ByteArrayOutputStream dataDo = new ByteArrayOutputStream();
        if (data != null && data.length > 0) {
            if ((ins & 0x01) != 0) {
                // Odd INS: plain command data in DO'85' (Doc 9303-11 §9.8.4).
                dataDo.write(0x85);
                writeLength(dataDo, data.length);
                dataDo.write(data, 0, data.length);
            } else {
                byte[] ciphertext = aesCbc(ksEnc, true, pad(data));
                dataDo.write(0x87);
                writeLength(dataDo, ciphertext.length + 1);
                dataDo.write(0x01);
                dataDo.write(ciphertext, 0, ciphertext.length);
            }
        }
        byte[] do97 = le > 0 ? new byte[] { (byte) 0x97, 0x01, (byte) le } : new byte[0];

        ByteArrayOutputStream macInput = new ByteArrayOutputStream();
        macInput.write(encodedSsc(), 0, 16);
        macInput.write(paddedHeader, 0, paddedHeader.length);
        macInput.write(dataDo.toByteArray(), 0, dataDo.size());
        macInput.write(do97, 0, do97.length);
        byte[] mac = Arrays.copyOf(AesCmac.mac(ksMac, pad(macInput.toByteArray())), 8);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(dataDo.toByteArray(), 0, dataDo.size());
        out.write(do97, 0, do97.length);
        out.write(0x8E);
        out.write(0x08);
        out.write(mac, 0, 8);
        return out.toByteArray();
    }

    @Override
    public byte[] unwrapResponse(byte[] data, short[] swOut) throws GeneralSecurityException {
        ssc++;
        int p = 0;
        byte[] dataDo = new byte[0];
        byte[] dataDoValue = new byte[0];
        boolean encrypted = false;
        byte[] do99 = new byte[0];
        byte[] cc = null;
        int sw = 0x9000;
        while (p < data.length) {
            int tag = data[p] & 0xFF;
            int len = data[p + 1] & 0xFF;
            int lenLen = 2;
            if ((len & 0x80) != 0) {
                int n = len & 0x7F;
                len = 0;
                for (int i = 0; i < n; i++) {
                    len = (len << 8) | (data[p + 2 + i] & 0xFF);
                }
                lenLen = 2 + n;
            }
            if (tag == 0x87) {
                dataDo = Arrays.copyOfRange(data, p, p + lenLen + len);
                dataDoValue = Arrays.copyOfRange(data, p + lenLen, p + lenLen + len);
                encrypted = true;
            } else if (tag == 0x85) {
                dataDo = Arrays.copyOfRange(data, p, p + lenLen + len);
                dataDoValue = Arrays.copyOfRange(data, p + lenLen, p + lenLen + len);
                encrypted = false;
            } else if (tag == 0x99) {
                do99 = Arrays.copyOfRange(data, p, p + lenLen + len);
                sw = ((data[p + lenLen] & 0xFF) << 8) | (data[p + lenLen + 1] & 0xFF);
            } else if (tag == 0x8E) {
                cc = Arrays.copyOfRange(data, p + lenLen, p + lenLen + len);
            }
            p += lenLen + len;
        }
        if (cc == null) {
            throw new IllegalStateException("response has no DO8E");
        }
        ByteArrayOutputStream macInput = new ByteArrayOutputStream();
        macInput.write(encodedSsc(), 0, 16);
        macInput.write(dataDo, 0, dataDo.length);
        macInput.write(do99, 0, do99.length);
        byte[] expected = Arrays.copyOf(AesCmac.mac(ksMac, pad(macInput.toByteArray())), 8);
        if (!Arrays.equals(expected, cc)) {
            throw new IllegalStateException("response MAC mismatch");
        }
        if (swOut != null) {
            swOut[0] = (short) sw;
        }
        if (dataDoValue.length == 0) {
            return new byte[0];
        }
        if (!encrypted) {
            return dataDoValue; // DO'85': plain response data (Doc 9303-11 §9.8.4)
        }
        byte[] cipher = Arrays.copyOfRange(dataDoValue, 1, dataDoValue.length);
        return unpad(aesCbc(ksEnc, false, cipher));
    }

    /** IV = AES-ECB(K_enc, SSC16). */
    private byte[] aesCbc(byte[] key, boolean encrypt, byte[] data)
            throws GeneralSecurityException {
        Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
        ecb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] iv = ecb.doFinal(encodedSsc());
        Cipher cbc = Cipher.getInstance("AES/CBC/NoPadding");
        cbc.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cbc.doFinal(data);
    }

    private byte[] encodedSsc() {
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[8 + i] = (byte) (ssc >>> (8 * (7 - i)));
        }
        return out;
    }

    private static void writeLength(ByteArrayOutputStream out, int len) {
        if (len <= 0x7F) {
            out.write(len);
        } else if (len <= 0xFF) {
            out.write(0x81);
            out.write(len);
        } else {
            out.write(0x82);
            out.write(len >> 8);
            out.write(len);
        }
    }

    private static byte[] pad(byte[] data) {
        int padded = data.length + 16 - (data.length % 16);
        byte[] out = Arrays.copyOf(data, padded);
        out[data.length] = (byte) 0x80;
        return out;
    }

    private static byte[] unpad(byte[] data) {
        int i = data.length - 1;
        while (i >= 0 && data[i] == 0) {
            i--;
        }
        if (i < 0 || data[i] != (byte) 0x80) {
            throw new IllegalStateException("bad M2 padding");
        }
        return Arrays.copyOf(data, i);
    }
}
