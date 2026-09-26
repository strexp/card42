package card42.host.emrtd.access;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * BAC key seed from the MRZ (ICAO Doc 9303-11 §4.3.2), the host-side mirror of
 * the card's {@code card42.emrtd.MrzKeySeed} (H2.1).
 *
 * <p>The seed is the first 16 bytes of SHA-1(MRZ_information), where
 * MRZ_information = document number (9, '&lt;'-padded) || check digit ||
 * date of birth (6) || check digit || date of expiry (6) || check digit.
 */
public final class MrzKeySeed {

    private MrzKeySeed() {
    }

    /** The 24-byte MRZ information for a TD3 document. */
    public static byte[] mrzInformation(String documentNumber, String dateOfBirth,
                                        String dateOfExpiry) {
        String doc = padRight(documentNumber, 9);
        String info = doc + (char) ('0' + checkDigit(doc))
                + dateOfBirth + (char) ('0' + checkDigit(dateOfBirth))
                + dateOfExpiry + (char) ('0' + checkDigit(dateOfExpiry));
        return info.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    /** The 16-byte BAC key seed of a 24-byte MRZ information string. */
    public static byte[] seed(byte[] mrzInformation) {
        try {
            return Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest(mrzInformation), 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Convenience: the seed of a document number / DOB / DOE triple. */
    public static byte[] seed(String documentNumber, String dateOfBirth, String dateOfExpiry) {
        return seed(mrzInformation(documentNumber, dateOfBirth, dateOfExpiry));
    }

    /** The 7-3-1 check digit of an MRZ field (Doc 9303-3 §4.9). */
    public static int checkDigit(String field) {
        int[] weights = { 7, 3, 1 };
        int sum = 0;
        for (int i = 0; i < field.length(); i++) {
            sum += value(field.charAt(i)) * weights[i % 3];
        }
        return sum % 10;
    }

    private static int value(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'A' && c <= 'Z') {
            return c - 'A' + 10;
        }
        return 0; // '<' and anything else
    }

    private static String padRight(String s, int length) {
        StringBuilder b = new StringBuilder(s);
        while (b.length() < length) {
            b.append('<');
        }
        return b.substring(0, length);
    }
}
