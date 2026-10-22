package card42.host.emrtd.access;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Terminal-side ISO/IEC 7816-4 secure-messaging framing shared by the 3DES
 * ({@link Iso7816Sm}, BAC) and AES ({@link Iso7816SmAes}, PACE) profiles.
 *
 * <p>Commands are wrapped as {@code [DO87] [DO97] DO8E}; responses are
 * {@code [DO87] DO99 DO8E}.  The send sequence counter is incremented before
 * every wrap/unwrap and enters the MAC input in its profile-specific encoded
 * form.  Only the cipher/MAC primitives, the block size and the SSC width
 * differ between profiles, so those are the abstract hooks; the TLV parsing,
 * the MAC input assembly, the M2 padding and the DO writers live here once.
 *
 * <p>MAC input:
 * <pre>
 *   command:  pad(SSC || pad(CLA'||INS||P1||P2) || DO87 || DO97)
 *   response: pad(SSC || DO87 || DO99)
 * </pre>
 */
abstract class AbstractSecureMessaging implements SecureMessaging {

    private final byte[] ksEnc;
    private final byte[] ksMac;
    private long ssc;

    AbstractSecureMessaging(byte[] ksEnc, byte[] ksMac, long ssc) {
        this.ksEnc = ksEnc;
        this.ksMac = ksMac;
        this.ssc = ssc;
    }

    @Override
    public final long getSendSequenceCounter() {
        return ssc;
    }

    /** The cipher block size in bytes: 8 for 3DES, 16 for AES. */
    abstract int blockSize();

    /** The profile-specific encoding of the send sequence counter. */
    abstract byte[] encodedSsc();

    /** MAC over the already block-padded input; returns the 8-byte checksum. */
    abstract byte[] mac(byte[] key, byte[] padded) throws GeneralSecurityException;

    /** Encrypts block-padded plaintext (CBC, profile-specific IV). */
    abstract byte[] encrypt(byte[] key, byte[] padded) throws GeneralSecurityException;

    /** Decrypts ciphertext to block-padded plaintext (CBC, profile-specific IV). */
    abstract byte[] decrypt(byte[] key, byte[] cipher) throws GeneralSecurityException;

    /** Wraps the command data field; returns {@code [DO87] [DO97] DO8E}. */
    @Override
    public final byte[] wrapCommand(int cla, int ins, int p1, int p2, byte[] data, int le)
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
                byte[] ciphertext = encrypt(ksEnc, pad(data));
                dataDo.write(0x87);
                writeLength(dataDo, ciphertext.length + 1);
                dataDo.write(0x01);
                dataDo.write(ciphertext, 0, ciphertext.length);
            }
        }
        // DO'97' carries Le in one byte for a short APDU and two bytes for an
        // extended one (ISO/IEC 7816-4 §5.6.3).  The extended Le 65536 is
        // encoded as 0x00 0x00; READ RECORD uses it to request the whole record.
        byte[] do97 = new byte[0];
        if (le > 0) {
            if (le <= 256) {
                do97 = new byte[] { (byte) 0x97, 0x01, (byte) le };
            } else {
                do97 = new byte[] { (byte) 0x97, 0x02, (byte) (le >> 8), (byte) le };
            }
        }

        ByteArrayOutputStream macInput = new ByteArrayOutputStream();
        byte[] sscBytes = encodedSsc();
        macInput.write(sscBytes, 0, sscBytes.length);
        macInput.write(paddedHeader, 0, paddedHeader.length);
        macInput.write(dataDo.toByteArray(), 0, dataDo.size());
        macInput.write(do97, 0, do97.length);
        // N = SSC || pad(header) || [DO87 or DO85] || DO97, M2-padded to a block
        // boundary; algorithm 3 / CMAC is then applied to N without a second
        // padding block (Doc 9303-11 Appendix D.4).
        byte[] mac = mac(ksMac, pad(macInput.toByteArray()));

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
    @Override
    public final byte[] unwrapResponse(byte[] data, short[] swOut) throws GeneralSecurityException {
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
        // The response envelope {DO87?} DO99 DO8E carries a mandatory MAC
        // (ICAO Doc 9303-11 §9.8.4).
        if (cc == null) {
            throw new IllegalStateException("response has no DO8E");
        }
        ByteArrayOutputStream macInput = new ByteArrayOutputStream();
        byte[] sscBytes = encodedSsc();
        macInput.write(sscBytes, 0, sscBytes.length);
        macInput.write(dataDo, 0, dataDo.length);
        macInput.write(do99, 0, do99.length);
        byte[] expected = mac(ksMac, pad(macInput.toByteArray()));
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
        byte[] cipher = Arrays.copyOfRange(dataDoValue, 1, dataDoValue.length); // skip 0x01
        return unpad(decrypt(ksEnc, cipher));
    }

    /** M2-pads to a block multiple (always appends at least one byte). */
    private byte[] pad(byte[] data) {
        int bs = blockSize();
        int padded = data.length + bs - (data.length % bs);
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
            // ISO/IEC 7816-4 §5.6.3 M2 padding.
            throw new IllegalStateException("bad M2 padding");
        }
        return Arrays.copyOf(data, i);
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
}
