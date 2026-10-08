package card42.emrtd;

import card42.common.ConstantTime;
import card42.common.Tlv;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.Key;

/* The ISO/IEC 7816-4 secure-messaging framing shared by the 3DES ({@link
 * Iso7816Sm}) and AES ({@link Iso7816SmAes}) profiles.
 *
 * The command data field is [DO87] [DO97] DO8E and the response data field is
 * [DO87] DO99 DO8E (ISO/IEC 7816-4 §5.6, Doc 9303-11 §9.8.4).  Only the
 * checksum, the cipher, the block size and the SSC encoding differ between the
 * two profiles; those are the abstract hooks, while the TLV parsing, the MAC
 * input assembly, the M2 padding and the DO writers live here once.
 *
 * The MAC/encryption scratch is the package-shared {@link SmScratch} and K_enc
 * is loaded into the cipher once per session.
 *
 * @author card42
 */

public abstract class AbstractSecureMessaging implements SecureMessaging {

    /** Reused MAC output: 8 bytes for the retail MAC, 16 for AES-CMAC. */
    private final byte[] macBuffer = new byte[16];

    /** The block-cipher key of the active session. */
    protected final Key key;

    /** Last loaded K_enc, so the cipher key schedule runs once per session. */
    private final byte[] loadedEnc = new byte[16];
    private boolean encLoaded;

    /** Le of the last unwrapped command, or -1 when absent. */
    private short le;

    /**
     * Largest plaintext response whose SM envelope fits a 256-byte APDU,
     * computed once from the profile's block size (see {@link #maxResponseData}).
     */
    private final short maxResponseData;

    protected AbstractSecureMessaging(Key key, short blockSize) {
        this.key = key;
        this.maxResponseData = computeMaxResponseData(blockSize);
    }

    public final short getLe() {
        return le;
    }

    public final short maxResponseData() {
        return maxResponseData;
    }

    /**
     * The wrapped response is DO87 (tag + length + indicator + padded data) +
     * DO99 (4) + DO8E (10); pick the largest window whose envelope is at most
     * 256 bytes.
     */
    private static short computeMaxResponseData(short blockSize) {
        short p = (short) 256;
        while (p > 0) {
            short rem = (short) (p % blockSize);
            short padded = (short) (p + (short) (blockSize - rem));
            short lengthValue = (short) (padded + 1);
            short lengthField;
            if (lengthValue <= (short) 0x7F) {
                lengthField = (short) 1;
            } else if (lengthValue <= (short) 0xFF) {
                lengthField = (short) 2;
            } else {
                lengthField = (short) 3;
            }
            short envelope = (short) (padded + lengthField);
            envelope = (short) (envelope + 16);
            if (envelope <= (short) 256) {
                return p;
            }
            p--;
        }
        return 0;
    }

    public final void reset() {
        encLoaded = false;
        Util.arrayFillNonAtomic(loadedEnc, (short) 0, (short) 16, (byte) 0);
        if (key.isInitialized()) {
            key.clearKey();
        }
        zeroizeMac();
    }

    /** Loads K_enc into the cipher key once per session key. */
    protected final void setEncKey(byte[] k) {
        if (encLoaded && ConstantTime.equals(loadedEnc, (short) 0, k, (short) 0, (short) 16)) {
            return;
        }
        loadKey(k);
        Util.arrayCopyNonAtomic(k, (short) 0, loadedEnc, (short) 0, (short) 16);
        encLoaded = true;
    }

    public final short unwrap(byte[] ksEnc, byte[] ksMac, byte[] ssc,
                              byte[] apdu, short dataOff, short dataLen,
                              byte[] out, short outOff) {
        increment(ssc);
        prepareSsc(ssc);
        le = -1;
        byte[] scratch = SmScratch.get();

        short do87Start = -1;
        short do87Val = -1;
        short do87Len = 0;
        short do85Start = -1;
        short do85Val = -1;
        short do85Len = 0;
        short do97Start = -1;
        short do97Val = -1;
        short do97Len = 0;
        short do8eVal = -1;
        short do8eLen = 0;

        short p = dataOff;
        short end = (short) (dataOff + dataLen);
        while (p < end) {
            short tagLen = Tlv.tagLength(apdu, p);
            short lenOff = (short) (p + tagLen);
            if ((short) (p + tagLen) >= end) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            short lfLen = Tlv.lengthFieldLength(apdu, lenOff);
            if (lfLen == 0) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            short tag = Tlv.getTag(apdu, p);
            short len = Tlv.getLength(apdu, lenOff);
            short valOff = (short) (lenOff + lfLen);
            short total = (short) (tagLen + lfLen + len);
            if (total <= 0 || (short) (p + total) > end) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            if (tag == (short) 0x87) {
                do87Start = p;
                do87Len = len;
                do87Val = valOff;
            } else if (tag == (short) 0x85) {
                do85Start = p;
                do85Len = len;
                do85Val = valOff;
            } else if (tag == (short) 0x97) {
                do97Start = p;
                do97Len = len;
                do97Val = valOff;
            } else if (tag == (short) 0x8E) {
                do8eVal = valOff;
                do8eLen = len;
            }
            p = (short) (p + total);
        }
        if (do8eVal < 0 || do8eLen != 8) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // MAC input: SSC || pad(CLA' INS P1 P2) || [DO87 or DO85] || DO97.
        short n = 0;
        n += copySsc(ssc, scratch, n);
        scratch[n++] = (byte) (apdu[ISO7816.OFFSET_CLA] | SM_CLA_MASK);
        scratch[n++] = apdu[ISO7816.OFFSET_INS];
        scratch[n++] = apdu[ISO7816.OFFSET_P1];
        scratch[n++] = apdu[ISO7816.OFFSET_P2];
        n = pad(scratch, n);
        if (do87Start >= 0) {
            n = append(scratch, n, apdu, do87Start, Tlv.totalLength(apdu, do87Start));
        } else if (do85Start >= 0) {
            n = append(scratch, n, apdu, do85Start, Tlv.totalLength(apdu, do85Start));
        }
        if (do97Start >= 0) {
            n = append(scratch, n, apdu, do97Start, Tlv.totalLength(apdu, do97Start));
        }
        n = pad(scratch, n);

        // N is already M2-padded, so the MAC runs without a second padding
        // block (Doc 9303-11 Appendix D.4).
        mac(ksMac, scratch, n, macBuffer);
        if (!ConstantTime.equals(macBuffer, (short) 0, apdu, do8eVal, (short) 8)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (do97Len > 0) {
            le = (short) (apdu[do97Val] & 0xFF);
        }
        // Odd INS carries plain command data in DO'85' (Doc 9303-11 §9.8.4).
        if (do85Start >= 0) {
            Util.arrayCopyNonAtomic(apdu, do85Val, out, outOff, do85Len);
            return do85Len;
        }
        if (do87Start < 0) {
            return 0;
        }
        // DO87 value = 0x01 || ciphertext; decrypt then unpad.
        short cipherLen = (short) (do87Len - 1);
        decryptBlock(ksEnc, apdu, (short) (do87Val + 1), cipherLen, scratch, (short) 0);
        return unpad(scratch, cipherLen, out, outOff);
    }

    public final short wrap(byte[] ksEnc, byte[] ksMac, byte[] ssc,
                            byte[] response, short respLen, short sw,
                            byte[] out, short outOff) {
        increment(ssc);
        prepareSsc(ssc);
        short n = outOff;
        byte[] scratch = SmScratch.get();

        short do87Len = 0;
        if (respLen > 0) {
            short padLen = paddedLength(respLen);
            encrypt(ksEnc, response, (short) 0, respLen, scratch, (short) 0);
            out[n++] = (byte) 0x87;
            n = writeLength(out, n, (short) (padLen + 1));
            out[n++] = (byte) 0x01;
            Util.arrayCopyNonAtomic(scratch, (short) 0, out, n, padLen);
            n += padLen;
            do87Len = (short) (n - outOff);
        }

        short do99Off = n;
        out[n++] = (byte) 0x99;
        out[n++] = (byte) 0x02;
        out[n++] = (byte) (sw >> 8);
        out[n++] = (byte) sw;

        // MAC input: pad(SSC || DO87 || DO99).
        short m = 0;
        m += copySsc(ssc, scratch, m);
        if (do87Len > 0) {
            m = append(scratch, m, out, outOff, do87Len);
        }
        m = append(scratch, m, out, do99Off, (short) 4);
        m = pad(scratch, m);
        mac(ksMac, scratch, m, macBuffer);

        out[n++] = (byte) 0x8E;
        out[n++] = (byte) 0x08;
        Util.arrayCopyNonAtomic(macBuffer, (short) 0, out, n, (short) 8);
        n += 8;
        return (short) (n - outOff);
    }

    /** Increments the 64-bit big-endian SSC (Doc 9303-11 §9.8.1). */
    protected static void increment(byte[] ssc) {
        for (short i = 7; i >= 0; i--) {
            ssc[i]++;
            if (ssc[i] != 0) {
                break;
            }
        }
    }

    // --- profile hooks -------------------------------------------------------

    /** The cipher block size in bytes: 8 for 3DES, 16 for AES. */
    protected abstract short blockSize();

    /** Releases the MAC engine's key schedule on session reset. */
    protected abstract void zeroizeMac();

    /** Loads K_enc into the concrete key object. */
    protected abstract void loadKey(byte[] k);

    /** Derives the profile's SSC form before it is used by the cipher/MAC. */
    protected abstract void prepareSsc(byte[] ssc);

    /** Appends the profile's SSC form to {@code dst[off..)}; returns its length. */
    protected abstract short copySsc(byte[] ssc, byte[] dst, short off);

    /** MACs {@code src[0..len)} into {@code out} (the profile writes >= 8 bytes). */
    protected abstract void mac(byte[] ksMac, byte[] src, short len, byte[] out);

    /** Encrypts one M2-padded block run. */
    protected abstract void encryptBlock(byte[] k, byte[] in, short inOff, short len,
                                         byte[] out, short outOff);

    /** Decrypts one ciphertext run (no padding removal). */
    protected abstract void decryptBlock(byte[] k, byte[] in, short inOff, short len,
                                         byte[] out, short outOff);

    // --- shared primitives ---------------------------------------------------

    /** Pads and encrypts {@code in[inOff..+inLen)} into {@code out[outOff..)}. */
    private void encrypt(byte[] k, byte[] in, short inOff, short inLen,
                         byte[] out, short outOff) {
        byte[] scratch = SmScratch.get();
        short padded = paddedLength(inLen);
        Util.arrayCopyNonAtomic(in, inOff, scratch, (short) 512, inLen);
        scratch[(short) (512 + inLen)] = (byte) 0x80;
        for (short i = (short) (512 + inLen + 1); i < (short) (512 + padded); i++) {
            scratch[i] = 0;
        }
        encryptBlock(k, scratch, (short) 512, padded, out, outOff);
    }

    /** Length after M2 padding: append 0x80 and zeros to a block multiple. */
    private short paddedLength(short len) {
        short b = blockSize();
        return (short) ((len + b) - (len % b));
    }

    /** Appends 0x80 then zeros until the length is a block multiple. */
    private short pad(byte[] buf, short len) {
        short b = blockSize();
        buf[len] = (byte) 0x80;
        len++;
        while ((len % b) != 0) {
            buf[len] = 0;
            len++;
        }
        return len;
    }

    private static short append(byte[] dst, short dstOff, byte[] src, short srcOff, short len) {
        Util.arrayCopyNonAtomic(src, srcOff, dst, dstOff, len);
        return (short) (dstOff + len);
    }

    /** Writes the BER length of len at out[off..); returns the new offset. */
    private static short writeLength(byte[] out, short off, short len) {
        if (len <= (short) 0x7F) {
            out[off] = (byte) len;
            return (short) (off + 1);
        }
        if (len <= (short) 0xFF) {
            out[off] = (byte) 0x81;
            out[(short) (off + 1)] = (byte) len;
            return (short) (off + 2);
        }
        out[off] = (byte) 0x82;
        out[(short) (off + 1)] = (byte) (len >> 8);
        out[(short) (off + 2)] = (byte) len;
        return (short) (off + 3);
    }

    /** Strips the 0x80 00.. M2 padding written by the peer. */
    private static short unpad(byte[] buf, short len, byte[] out, short outOff) {
        short i = (short) (len - 1);
        while (i >= 0 && buf[i] == 0) {
            i--;
        }
        if (i < 0 || buf[i] != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Util.arrayCopyNonAtomic(buf, (short) 0, out, outOff, i);
        return i;
    }
}
