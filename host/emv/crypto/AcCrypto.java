package card42.host.emv.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import card42.host.common.crypto.AesCmac;
import card42.host.common.crypto.Iso9797;
import card42.host.common.util.Bytes;
import card42.host.common.util.Hex;

/**
 * Terminal-side EMV cryptography (EMV v4.4 Book 2 §5, §7.2, §8.2, Annex
 * A1.3.1): EMV session-key derivation, RSA public-key recovery/encryption, the
 * ISO 9564-1 format 2 PIN block and the ARPC methods.  Part of the reference
 * host stack.
 *
 * <p>The {@code expectedAc} / {@code expectedAcAes} methods recompute the
 * Application Cryptogram off-card; they are <em>test oracles</em> used by the
 * integration suites to check the card, not terminal runtime behaviour.
 */
public final class AcCrypto {

    private AcCrypto() {
    }

    /**
     * EMV session key derivation (EMV v4.4 Book 2, Annex A1.3.1): the 8-byte
     * diversification value R is the ATC followed by six '00' bytes for the
     * AC/ARPC key.  For the 3DES form the two blocks are
     * R0 || R1 || 'F0' || R3..R7 and R0 || R1 || '0F' || R3..R7.
     */
    public static byte[] sessionKey(byte[] mk16, int atc)
            throws GeneralSecurityException {
        byte[] r = new byte[8];
        r[0] = (byte) (atc >> 8);
        r[1] = (byte) atc;
        return sessionKey(mk16, r);
    }

    /**
     * EMV session key derivation for an explicit 8-byte diversification value
     * (EMV v4.4 Book 2, Annex A1.3.1).  The secure-messaging keys pass the
     * first Application Cryptogram as R (EMV v4.4 Book 2 Annex A1.3.1).
     */
    public static byte[] sessionKey(byte[] mk16, byte[] r)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(expandKey(mk16), "DESede"));

        byte[] f1 = Arrays.copyOf(r, 8);
        byte[] f2 = Arrays.copyOf(r, 8);
        f1[2] = (byte) 0xF0;
        f2[2] = (byte) 0x0F;

        byte[] out = new byte[16];
        System.arraycopy(cipher.doFinal(f1), 0, out, 0, 8);
        System.arraycopy(cipher.doFinal(f2), 0, out, 8, 8);
        return out;
    }

    /**
     * Test oracle: recomputes the expected AC from the ICC master key, the AIP
     * and the on-card ATC for a GENERATE AC whose data field is
     * {@code cdolLength} zero bytes.  The AC input is the CDOL data followed by
     * AIP || ATC || IAD (EMV v4.4 Book 2 section 8.1.1 / Table CCD 3).
     */
    public static byte[] expectedAc(byte[] iccKey, int aip, int atc, int cdolLength,
                                    byte[] iad) throws GeneralSecurityException {
        return expectedAc(iccKey, aip, atc, new byte[cdolLength], iad);
    }

    /**
     * Test oracle: recomputes the expected AC from the ICC master key, the AIP,
     * the on-card ATC, the actual CDOL data and the IAD returned in the
     * response (the terminal data is followed by AIP || ATC || IAD, EMV v4.4
     * Book 2 section 8.1.1).
     */
    public static byte[] expectedAc(byte[] iccKey, int aip, int atc, byte[] cdolData,
                                    byte[] iad) throws GeneralSecurityException {
        byte[] acInput = new byte[cdolData.length + 2 + 2 + iad.length];
        System.arraycopy(cdolData, 0, acInput, 0, cdolData.length);
        int o = cdolData.length;
        acInput[o] = (byte) (aip >> 8);
        acInput[o + 1] = (byte) aip;
        acInput[o + 2] = (byte) (atc >> 8);
        acInput[o + 3] = (byte) atc;
        System.arraycopy(iad, 0, acInput, o + 4, iad.length);
        // EMV v4.4 Book 2 §8.1.2: the CCD CV '5' AC is the ISO/IEC 9797-1
        // algorithm 3 MAC.
        return PersoMac.mac(sessionKey(iccKey, atc), acInput);
    }

    /** ISO 9564-1 format 2 PIN block (8 bytes, padded with 0xF). */
    public static byte[] iso9564Format2(String pin) {
        byte[] block = new byte[8];
        Arrays.fill(block, (byte) 0xFF);
        block[0] = (byte) (0x20 | pin.length());
        byte[] digits = Hex.bcd(pin);
        System.arraycopy(digits, 0, block, 1, digits.length);
        return block;
    }

    /**
     * ISO 9564-1 format 0 PIN block (8 bytes) for the online PIN CVM
     * (EMV v4.4 Book 4 §6.3.4.4): the PIN block '0 || N || PIN || F padding' is
     * XORed with the PAN field '0000 || rightmost 12 PAN digits excluding the
     * check digit'.  The result is ready for the host's PIN encryption callback.
     */
    public static byte[] iso9564Format0(String pin, byte[] pan) {
        byte[] pinBlock = new byte[8];
        Arrays.fill(pinBlock, (byte) 0xFF);
        pinBlock[0] = (byte) pin.length();
        byte[] digits = Hex.bcd(pin);
        System.arraycopy(digits, 0, pinBlock, 1, digits.length);

        String panDigits = Hex.format(pan);
        if (panDigits.length() > 1) {
            panDigits = panDigits.substring(0, panDigits.length() - 1); // drop check digit
        }
        if (panDigits.length() > 12) {
            panDigits = panDigits.substring(panDigits.length() - 12);
        }
        String panField = "0000000000000000".substring(panDigits.length()) + panDigits;
        byte[] panBlock = Hex.parse(panField);

        byte[] block = new byte[8];
        for (int i = 0; i < 8; i++) {
            block[i] = (byte) (pinBlock[i] ^ panBlock[i]);
        }
        return block;
    }

    /**
     * Raw RSA Recovery Function (EMV v4.4 Book 2 Annex B2.1.3): message^e mod n
     * as a fixed modulus-length byte string.  This is the public-key operation
     * the terminal applies to the Table 25 PIN block.
     */
    public static byte[] rsaRecover(byte[] message, BigInteger modulus, BigInteger exponent) {
        return toFixed(new BigInteger(1, message).modPow(exponent, modulus),
                modulusLength(modulus));
    }

    /**
     * EMV enciphered offline PIN (EMV v4.4 Book 2 §7.2, Table 25): the
     * modulus-length block '7F' || PIN block(8) || ICC UN(8) || random padding,
     * enciphered with the ICC PIN public key through the Recovery Function.
     */
    public static byte[] emvEncipherPin(byte[] pinBlock, byte[] iccUn,
                                        BigInteger modulus, BigInteger exponent) {
        int n = modulusLength(modulus);
        byte[] block = new byte[n];
        new java.security.SecureRandom().nextBytes(block);
        block[0] = 0x7F;
        System.arraycopy(pinBlock, 0, block, 1, 8);
        System.arraycopy(iccUn, 0, block, 9, 8);
        return rsaRecover(block, modulus, exponent);
    }

    private static int modulusLength(BigInteger modulus) {
        return (modulus.bitLength() + 7) / 8;
    }

    /** Big-endian byte string of exactly length bytes, left-padded with zero. */
    private static byte[] toFixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        int start = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
        int size = raw.length - start;
        byte[] out = new byte[length];
        System.arraycopy(raw, start, out, length - size, size);
        return out;
    }

    // --- Issuer authentication (EMV v4.4 Book 2 §8.2) -------------------------

    /**
     * ARPC Method 1 (EMV v4.4 Book 2 section 8.2.1): DES3_ECB(SK_AC)[ARQC xor
     * (ARC || 00 x6)], 8 bytes.
     */
    public static byte[] computeArpcMethod1(byte[] sk16, byte[] arqc, byte[] arc)
            throws GeneralSecurityException {
        byte[] y = new byte[8];
        System.arraycopy(arqc, 0, y, 0, 8);
        y[0] ^= arc[0];
        y[1] ^= arc[1];
        return des3Ecb(sk16, y);
    }

    /**
     * ARPC Method 2 (EMV v4.4 Book 2 section 8.2.2): the leftmost 4 bytes of the
     * ISO/IEC 9797-1 algorithm 3 MAC over ARQC || CSU || proprietary, keyed
     * with SK_AC.
     */
    public static byte[] computeArpcMethod2(byte[] sk16, byte[] arqc, byte[] csu,
                                            byte[] proprietary)
            throws GeneralSecurityException {
        byte[] msg = Bytes.concat(arqc, csu, proprietary);
        return macAlg3(sk16, msg, 4);
    }

    // --- ISO/IEC 9797-1 algorithm 3 (secure messaging, EMV v4.4 Book 2 §9.2/§9.3) ---------

    /**
     * ISO/IEC 9797-1 MAC algorithm 3 with padding method 2: the CBC part uses
     * the left key block as a single DES key, and the final block is transformed
     * with the right key block (ANSI X9.19 retail MAC).  Returns the leftmost
     * outLength bytes of the 8-byte MAC.
     */
    public static byte[] macAlg3(byte[] key16, byte[] msg, int outLength)
            throws GeneralSecurityException {
        int padding = 8 - (msg.length % 8);
        byte[] padded = new byte[msg.length + padding];
        System.arraycopy(msg, 0, padded, 0, msg.length);
        padded[msg.length] = (byte) 0x80;
        return macAlg3Padded(key16, padded, outLength);
    }

    /**
     * ISO/IEC 9797-1 algorithm 3 over an already block-aligned message, without
     * adding the algorithm's padding step.  EMV Format 1 secure messaging
     * pre-pads the message (EMV v4.4 Book 2 Annex D2.3.1), so its MAC is computed with
     * this variant (EMV v4.4 Book 2 section 9.2.3).  The single implementation
     * lives in {@link PersoMac#macPadded}; this is the AcCrypto entry point.
     */
    public static byte[] macAlg3Padded(byte[] key16, byte[] padded, int outLength)
            throws GeneralSecurityException {
        return PersoMac.macPadded(key16, padded, outLength);
    }

    /** Expands a 16-byte 2-key 3DES key to the JDK's 24-byte K1 || K2 || K1 form. */
    private static byte[] expandKey(byte[] key16) {
        return Iso9797.expandKey(key16);
    }

    /** Single-block 3DES ECB encryption (no padding). */
    public static byte[] des3Ecb(byte[] key16, byte[] block8)
            throws GeneralSecurityException {
        return Iso9797.des3Ecb(key16, block8);
    }

    /** 3DES CBC encryption with a zero IV (no padding). */
    public static byte[] des3CbcEncrypt(byte[] key16, byte[] data)
            throws GeneralSecurityException {
        return Iso9797.des3CbcEncrypt(key16, data);
    }

    // --- AES / CV '6' (EMV v4.4 Book 2 §8.1.2, §A1.3.1) ----------------------

    /**
     * AES session key derivation (EMV v4.4 Book 2 Annex A1.3.1): SK = AES(MK)[R]
     * with a 16-byte diversification value R.
     */
    public static byte[] sessionKeyAes(byte[] mk16, byte[] r16)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(mk16, "AES"));
        return cipher.doFinal(r16);
    }

    /**
     * AES AC/ARPC session key for an ATC: R = ATC || 00 x14 (the AES block size
     * is 16, EMV v4.4 Book 2 §A1.3.1).
     */
    public static byte[] sessionKeyAes(byte[] mk16, int atc)
            throws GeneralSecurityException {
        byte[] r = new byte[16];
        r[0] = (byte) (atc >> 8);
        r[1] = (byte) atc;
        return sessionKeyAes(mk16, r);
    }

    /**
     * AES secure-messaging session key: R = first AC || 00 x8 (the AES block
     * size is 16, EMV v4.4 Book 2 §A1.3.1).
     */
    public static byte[] sessionKeyAesSm(byte[] mk16, byte[] firstAc8)
            throws GeneralSecurityException {
        byte[] r = new byte[16];
        System.arraycopy(firstAc8, 0, r, 0, 8);
        return sessionKeyAes(mk16, r);
    }

    /**
     * Test oracle: recomputes the expected CV '6' AC: CMAC(SK_AC)[CDOL data ||
     * AIP || ATC || IAD], truncated to 8 bytes (EMV v4.4 Book 2 §8.1.2).
     */
    public static byte[] expectedAcAes(byte[] iccKey, int aip, int atc,
                                       byte[] cdolData, byte[] iad)
            throws GeneralSecurityException {
        byte[] acInput = new byte[cdolData.length + 2 + 2 + iad.length];
        System.arraycopy(cdolData, 0, acInput, 0, cdolData.length);
        int o = cdolData.length;
        acInput[o] = (byte) (aip >> 8);
        acInput[o + 1] = (byte) aip;
        acInput[o + 2] = (byte) (atc >> 8);
        acInput[o + 3] = (byte) atc;
        System.arraycopy(iad, 0, acInput, o + 4, iad.length);
        return AesCmac.mac(sessionKeyAes(iccKey, atc), acInput, 8);
    }

    /**
     * ARPC Method 2 for CV '6' (EMV v4.4 Book 2 §8.2.2): the leftmost 4 bytes of
     * the AES-CMAC over ARQC || CSU || proprietary, keyed with SK_AC.
     */
    public static byte[] computeArpcMethod2Aes(byte[] sk16, byte[] arqc, byte[] csu,
                                               byte[] proprietary)
            throws GeneralSecurityException {
        return AesCmac.mac(sk16, Bytes.concat(arqc, csu, proprietary), 4);
    }

    // --- DOL helpers (DDA/CDA, EMV v4.4 Book 2 §6.5/§6.6) ---------------------

    /** Total value length described by a DOL definition (tag+length entries). */
    public static int dolDataLength(byte[] dol) {
        int p = 0;
        int total = 0;
        while (p < dol.length) {
            int b = dol[p] & 0xFF;
            p += (b & 0x1F) == 0x1F ? 2 : 1;
            int lb = dol[p] & 0xFF;
            int lLen = (lb & 0x80) == 0 ? 1 : 1 + (lb & 0x7F);
            int len = 0;
            for (int i = 0; i < lLen - 1; i++) {
                len = (len << 8) | (dol[p + 1 + i] & 0xFF);
            }
            if ((lb & 0x80) == 0) {
                len = lb;
            }
            total += len;
            p += lLen;
        }
        return total;
    }

    /** Offset of the value of tag in a DOL definition, or -1. */
    public static int dolValueOffset(byte[] dol, int tag) {
        int p = 0;
        int offset = 0;
        while (p < dol.length) {
            int b = dol[p] & 0xFF;
            int t;
            int tagLen;
            if ((b & 0x1F) == 0x1F) {
                t = (b << 8) | (dol[p + 1] & 0xFF);
                tagLen = 2;
            } else {
                t = b;
                tagLen = 1;
            }
            p += tagLen;
            int lb = dol[p] & 0xFF;
            int lLen;
            int len;
            if ((lb & 0x80) == 0) {
                lLen = 1;
                len = lb;
            } else {
                lLen = 1 + (lb & 0x7F);
                len = 0;
                for (int i = 0; i < lLen - 1; i++) {
                    len = (len << 8) | (dol[p + 1 + i] & 0xFF);
                }
            }
            if (t == tag) {
                return offset;
            }
            offset += len;
            p += lLen;
        }
        return -1;
    }
}
