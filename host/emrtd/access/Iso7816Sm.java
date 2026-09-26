package card42.host.emrtd.access;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import card42.host.common.crypto.Iso9797;

/**
 * Terminal-side ISO/IEC 7816-4 secure messaging for BAC (ICAO Doc 9303-11
 * §9.8), the mirror of the card-side {@code card42.emrtd.Iso7816Sm}.
 *
 * <p>Commands are wrapped as {@code [DO87] [DO97] DO8E}; responses are
 * {@code [DO87] DO99 DO8E}.  Encryption is 3DES-CBC with a zero IV; the
 * checksum is the ISO/IEC 9797-1 algorithm 3 (retail) MAC.  The send sequence
 * counter is a 64-bit big-endian counter incremented before every MAC.
 *
 * <p>MAC input:
 * <pre>
 *   command:  pad(SSC || pad(CLA'||INS||P1||P2) || DO87 || DO97)
 *   response: pad(SSC || DO87 || DO99)
 * </pre>
 */
public final class Iso7816Sm implements SecureMessaging {

    private final byte[] ksEnc;
    private final byte[] ksMac;
    private long ssc;

    public Iso7816Sm(byte[] ksEnc, byte[] ksMac, long ssc) {
        this.ksEnc = ksEnc;
        this.ksMac = ksMac;
        this.ssc = ssc;
    }

    public long getSendSequenceCounter() {
        return ssc;
    }

    /** Wraps the command data field; returns {@code [DO87] [DO97] DO8E}. */
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
                byte[] ciphertext = Iso9797.des3CbcEncrypt(ksEnc, pad(data));
                dataDo.write(0x87);
                writeLength(dataDo, ciphertext.length + 1);
                dataDo.write(0x01);
                dataDo.write(ciphertext, 0, ciphertext.length);
            }
        }
        byte[] do97 = le > 0 ? new byte[] { (byte) 0x97, 0x01, (byte) le } : new byte[0];

        ByteArrayOutputStream macInput = new ByteArrayOutputStream();
        macInput.write(encodedSsc(), 0, 8);
        macInput.write(paddedHeader, 0, paddedHeader.length);
        macInput.write(dataDo.toByteArray(), 0, dataDo.size());
        macInput.write(do97, 0, do97.length);
        // N = SSC || pad(header) || [DO87 or DO85] || DO97, M2-padded to a block
        // boundary; algorithm 3 is then applied to N without a second padding
        // block (Doc 9303-11 Appendix D.4).
        byte[] mac = Iso9797.macPadded(ksMac, pad(macInput.toByteArray()), 8);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(dataDo.toByteArray(), 0, dataDo.size());
        out.write(do97, 0, do97.length);
        out.write(0x8E);
        out.write(0x08);
        out.write(mac, 0, 8);
        return out.toByteArray();
    }

    /**
     * Unwraps the response data field {@code [DO87] DO99 DO8E}; returns the
     * plaintext and writes the status word to {@code swOut[0]}.
     */
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
        macInput.write(encodedSsc(), 0, 8);
        macInput.write(dataDo, 0, dataDo.length);
        macInput.write(do99, 0, do99.length);
        byte[] expected = Iso9797.macPadded(ksMac, pad(macInput.toByteArray()), 8);
        if (!Arrays.equals(Arrays.copyOf(expected, cc.length), cc)) {
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
        byte[] cipher = Arrays.copyOfRange(dataDoValue, 1, dataDoValue.length); // skip 0x01
        return unpad(Iso9797.des3CbcDecrypt(ksEnc, new byte[8], cipher));
    }

    private byte[] encodedSsc() {
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (ssc >>> (8 * (7 - i)));
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
        int padded = data.length + 8 - (data.length % 8);
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
