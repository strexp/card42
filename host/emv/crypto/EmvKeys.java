package card42.host.emv.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import card42.host.common.util.Hex;
import card42.host.common.util.Digests;
import card42.host.common.util.Bytes;

/**
 * EMV ICC master-key derivation (EMV v4.4 Book 2 Annex A1.4), host-side.
 *
 * <p>All three Annex A1.4 methods are implemented:
 *
 * <ul>
 *   <li><b>Option A</b> ({@link #optionA}, A1.4.1): Triple DES, the default
 *       form for PANs of at most 16 digits.</li>
 *   <li><b>Option B</b> ({@link #optionB}, A1.4.2): Triple DES with a SHA-1 /
 *       decimalisation step for PANs longer than 16 digits.  CCD CV '5'
 *       requires this method (EMV v4.4 Book 2 CCD §8.3 / §9.4), and
 *       {@link #desMasterKey} selects it (Option B falls back to Option A for
 *       short PANs, as the specification requires).</li>
 *   <li><b>Option C</b> ({@link #aesMasterKey}, A1.4.3): AES, required by the
 *       CV '6' profile.</li>
 * </ul>
 *
 * <p>The issuer derives one ICC master key per key role from an independent
 * Issuer Master Key: the Application Cryptogram key (CAM / MK_AC), the secure
 * messaging MAC UDK (MK_MAC) and the secure messaging ENC UDK (MK_ENC);
 * {@link #iccMasterKeys} performs the three derivations at once.
 *
 * <pre>
 *   Option A (3DES, PAN &le; 16 digits):
 *     X  := decimal PAN digits || PAN Sequence Number digits
 *     Y  := the 16 rightmost digits of X, left-padded with '0' (8-byte BCD)
 *     ZL := DES3(IMK)[Y]      ZR := DES3(IMK)[Y ^ FF x8]
 *     MK := odd-parity adjust of (ZL || ZR)
 *
 *   Option B (3DES, PAN &gt; 16 digits):
 *     pad the PAN to an even number of digits, append the PSN, SHA-1 the BCD
 *     encoding, take the first 16 decimal digits (decimalising A-F as 0-5 when
 *     needed) as Y, then continue as Option A step 2.
 *
 *   Option C (AES-128): MK := AES(IMK)[Y] with Y the 16-byte BCD of
 *     PAN || PSN, left-padded with hexadecimal zeros.
 * </pre>
 *
 * <p>The Option A/B implementation is checked against independent public
 * vectors in {@code test/emv/unit/card/crypto/EmvKeysTest.java} (EFTlab and pyEMV),
 * so a derivation bug cannot hide behind the card and host sharing this code.
 */
public final class EmvKeys {

    private EmvKeys() {
    }

    /** The three ICC master keys derived from the AC / MAC / ENC issuer keys. */
    public static final class IccMasterKeys {
        /** ICC Application Cryptogram master key (MK_AC / CAM). */
        public final byte[] ac;
        /** ICC secure-messaging MAC master key (MAC UDK). */
        public final byte[] mac;
        /** ICC secure-messaging ENC master key (ENC UDK). */
        public final byte[] enc;

        IccMasterKeys(byte[] ac, byte[] mac, byte[] enc) {
            this.ac = ac;
            this.mac = mac;
            this.enc = enc;
        }
    }

    // --- A1.4.1 Option A / A1.4.2 Option B (Triple DES) ---------------------

    /**
     * Derives the 16-byte ICC master key with the method the CV '5' profile
     * requires: Option B, which falls back to Option A for PANs of at most 16
     * digits (EMV v4.4 Book 2 §A1.4.2, CCD §8.3/§9.4).
     */
    public static byte[] desMasterKey(byte[] imk, String pan, int panSeq)
            throws GeneralSecurityException {
        return optionB(imk, pan, panSeq);
    }

    /**
     * Option A master-key derivation (EMV v4.4 Book 2 §A1.4.1).  The PAN and
     * PAN Sequence Number digits are right-justified to 16 digits and the two
     * resulting 8-byte values are enciphered with Triple DES; the 16 bytes are
     * then parity-adjusted.
     */
    public static byte[] optionA(byte[] imk, String pan, int panSeq)
            throws GeneralSecurityException {
        byte[] dataA = optionAData(pan, panSeq);
        return parityAdjusted(des3Ecb(imk, Bytes.concat(dataA, invert(dataA))));
    }

    /**
     * Option B master-key derivation (EMV v4.4 Book 2 §A1.4.2).  For a PAN of
     * at most 16 digits this is Option A; otherwise the PAN/PSN digits are
     * SHA-1 hashed and decimalised to 16 digits before the Option A step.
     */
    public static byte[] optionB(byte[] imk, String pan, int panSeq)
            throws GeneralSecurityException {
        String digits = decimalDigits(pan);
        if (digits.length() <= 16) {
            return optionA(imk, pan, panSeq);
        }
        String input = digits + panSequenceDigits(panSeq);
        if ((input.length() & 1) != 0) {
            input = "0" + input;
        }
        byte[] dataA = Hex.bcd(decimalise(Digests.sha1(Hex.bcd(input))));
        return parityAdjusted(des3Ecb(imk, Bytes.concat(dataA, invert(dataA))));
    }

    /**
     * The AC / MAC / ENC ICC master keys derived from three independent issuer
     * master keys (EMV v4.4 Book 2 §8.3/§9.4 for CV '5', §8.3/§9.4 for CV '6').
     *
     * @param aes {@code true} for the AES (Option C) profile, {@code false}
     *            for the Triple DES (Option B) profile
     */
    public static IccMasterKeys iccMasterKeys(byte[] imkAc, byte[] imkMac,
            byte[] imkEnc, String pan, int panSeq, boolean aes)
            throws GeneralSecurityException {
        if (aes) {
            return new IccMasterKeys(
                    aesMasterKey(imkAc, pan, panSeq, 16),
                    aesMasterKey(imkMac, pan, panSeq, 16),
                    aesMasterKey(imkEnc, pan, panSeq, 16));
        }
        return new IccMasterKeys(
                desMasterKey(imkAc, pan, panSeq),
                desMasterKey(imkMac, pan, panSeq),
                desMasterKey(imkEnc, pan, panSeq));
    }

    /** 8-byte BCD Y for Option A: the 16 rightmost PAN/PSN digits. */
    private static byte[] optionAData(String pan, int panSeq) {
        String x = decimalDigits(pan) + panSequenceDigits(panSeq);
        String y = x.length() > 16 ? x.substring(x.length() - 16) : x;
        while (y.length() < 16) {
            y = "0" + y;
        }
        return Hex.bcd(y);
    }

    /**
     * Decimalises a SHA-1 digest to 16 digits (EMV v4.4 Book 2 §A1.4.2): first
     * the decimal nibbles from the left, then, if fewer than 16, the remaining
     * non-decimal nibbles mapped A-F to 0-5.
     */
    private static String decimalise(byte[] digest) {
        StringBuilder y = new StringBuilder(16);
        for (int pass = 0; pass < 2 && y.length() < 16; pass++) {
            for (int i = 0; i < digest.length && y.length() < 16; i++) {
                appendDecimalised(y, (digest[i] >> 4) & 0x0F, pass);
                appendDecimalised(y, digest[i] & 0x0F, pass);
            }
        }
        return y.toString();
    }

    private static void appendDecimalised(StringBuilder y, int nibble, int pass) {
        if (y.length() >= 16) {
            return;
        }
        if (pass == 0) {
            if (nibble <= 9) {
                y.append((char) ('0' + nibble));
            }
        } else if (nibble >= 0x0A) {
            y.append((char) ('0' + (nibble - 0x0A)));
        }
    }

    private static byte[] invert(byte[] a) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ 0xFF);
        }
        return out;
    }

    /** Sets the least significant bit of each byte for odd parity (DES keys). */
    private static byte[] parityAdjusted(byte[] z) {
        byte[] out = z.clone();
        for (int i = 0; i < out.length; i++) {
            int b = out[i] & 0xFE;
            if ((Integer.bitCount(b) & 1) == 0) {
                b |= 0x01;
            }
            out[i] = (byte) b;
        }
        return out;
    }

    /** Triple DES ECB over one or more 8-byte blocks with a double-length key. */
    private static byte[] des3Ecb(byte[] key16, byte[] data)
            throws GeneralSecurityException {
        byte[] key = new byte[24];
        System.arraycopy(key16, 0, key, 0, 16);
        System.arraycopy(key16, 0, key, 16, 8);
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"));
        return cipher.doFinal(data);
    }

    // --- A1.4.3 Option C (AES) ---------------------------------------------

    /**
     * Derives the AES ICC master key from the Issuer Master Key, the PAN and
     * the PAN Sequence Number (EMV v4.4 Book 2 §A1.4.3 Option C).
     *
     * @param imk       the 16-byte Issuer Master Key
     * @param pan       the Application PAN as decimal digits
     * @param panSeq    the PAN Sequence Number (0x00 when absent)
     * @param keyLength 16 or 32 bytes (AES-128 / AES-256)
     */
    public static byte[] aesMasterKey(byte[] imk, String pan, int panSeq, int keyLength)
            throws GeneralSecurityException {
        byte[] y = diversificationValue(pan, panSeq);

        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(imk, "AES"));

        byte[] zl = aes.doFinal(y);
        if (keyLength == 16) {
            return zl;
        }
        if (keyLength != 32) {
            throw new IllegalArgumentException("AES key length must be 16 or 32 bytes");
        }
        byte[] yStar = new byte[16];
        for (int i = 0; i < 16; i++) {
            yStar[i] = (byte) (y[i] ^ 0xFF);
        }
        byte[] zr = aes.doFinal(yStar);
        return Bytes.concat(zl, zr);
    }

    /**
     * Builds Y: the decimal digits of the PAN followed by the PAN Sequence
     * Number, left-padded with hexadecimal zeros to 16 bytes (EMV v4.4 Book 2 §A1.4.3).
     */
    public static byte[] diversificationValue(String pan, int panSeq) {
        String digits = decimalDigits(pan) + panSequenceDigits(panSeq);
        if ((digits.length() & 1) != 0) {
            digits = "0" + digits;
        }
        // The decimal digits are packed as BCD: each pair becomes one byte, so
        // the digit string is read as a hexadecimal number and left-padded with
        // zero bytes to 16 (EMV v4.4 Book 2 §A1.4.3 "pad it to the left with hexadecimal
        // zeros ... in numeric format").
        BigInteger value = new BigInteger(digits, 16);
        byte[] raw = value.toByteArray();
        int start = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
        int size = raw.length - start;
        if (size > 16) {
            // A PAN longer than 16 bytes cannot be represented; A1.4.3 assumes
            // it fits (a PAN is at most 19 digits, so PAN + PSN fits in 16 bytes).
            throw new IllegalArgumentException("PAN + PAN sequence number does not fit in 16 bytes");
        }
        byte[] y = new byte[16];
        System.arraycopy(raw, start, y, 16 - size, size);
        return y;
    }

    /** The decimal digits of a PAN, ignoring formatting separators. */
    private static String decimalDigits(String pan) {
        return pan.replaceAll("[^0-9]", "");
    }

    /**
     * The decimal digit string of a BCD PAN Sequence Number (tag 5F34, EMV v4.4 Book 2
     * §A1.4.3).  Each nibble is one decimal digit; a low nibble of 'F' is the
     * pad nibble of an odd-length value and is dropped (e.g. 0x12 -> "12",
     * 0x01 -> "01", 0x1F -> "1", 0x00 -> "00").
     */
    private static String panSequenceDigits(int panSeq) {
        int hi = (panSeq >> 4) & 0x0F;
        int lo = panSeq & 0x0F;
        if (hi > 9 || (lo > 9 && lo != 0x0F)) {
            throw new IllegalArgumentException("PAN sequence number is not BCD: "
                    + String.format("%02X", panSeq & 0xFF));
        }
        if (lo == 0x0F) {
            return String.valueOf((char) ('0' + hi));
        }
        return new String(new char[] { (char) ('0' + hi), (char) ('0' + lo) });
    }
}
