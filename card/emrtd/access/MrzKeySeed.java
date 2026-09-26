package card42.emrtd;

import javacard.security.MessageDigest;

/* BAC key seed from the MRZ information (ICAO Doc 9303-11 §4.3.2).
 *
 * The seed is the first 16 bytes of SHA-1(MRZ_information), where
 * MRZ_information is the concatenation of the document number, its check
 * digit, the date of birth, its check digit, the date of expiry and its check
 * digit (24 characters for a TD3 passport).  The check digit is the 7-3-1
 * weighted sum of the field, with '<' counted as 0 and 'A'..'Z' as 10..35.
 *
 * @author card42
 */

public final class MrzKeySeed {

    /** Length of the TD3 MRZ information used for BAC: 3 fields of 8 bytes. */
    public static final short MRZ_INFO_LENGTH = (short) 24;

    private MrzKeySeed() {
    }

    /**
     * Writes the 7-3-1 check digit of the field mrz[off..off+len) to
     * out[outOff] and returns 1.  '<' is 0 and 'A'..'Z' are 10..35
     * (Doc 9303-3 §4.9).
     */
    public static short checkDigit(byte[] mrz, short off, short len, byte[] out, short outOff) {
        short sum = 0;
        short[] weights = { 7, 3, 1 };
        for (short i = 0; i < len; i++) {
            sum += (short) (value(mrz[(short) (off + i)]) * weights[i % 3]);
        }
        out[outOff] = (byte) (sum % 10);
        return 1;
    }

    /**
     * Writes the 16-byte BAC key seed of the 24-byte MRZ information to
     * out[outOff..outOff+16).  The SHA-1 result is 20 bytes; only the first 16
     * are the seed (Doc 9303-11 §4.3.2).
     */
    public static short seed(byte[] mrzInfo, short off, byte[] out, short outOff) {
        MessageDigest sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        sha1.doFinal(mrzInfo, off, MRZ_INFO_LENGTH, out, outOff);
        return (short) 16;
    }

    private static byte value(byte c) {
        if (c >= '0' && c <= '9') {
            return (byte) (c - '0');
        }
        if (c >= 'A' && c <= 'Z') {
            return (byte) (c - 'A' + 10);
        }
        return 0; // '<' and anything else
    }
}
