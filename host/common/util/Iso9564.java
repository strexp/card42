package card42.host.common.util;

import java.util.Arrays;

/**
 * ISO 9564-1 PIN block formats used by the EMV host:
 *
 * <ul>
 *   <li>format 0: online PIN, XORed with the PAN field (Book 4 §6.3.4.4);</li>
 *   <li>format 1: reference PIN for the card (CPS v2.0 Annex A);</li>
 *   <li>format 2: the EMV offline-PIN encipherment block (Table 25).</li>
 * </ul>
 *
 * <p>Keeping the builders here removes the copies in {@code Hex},
 * {@code AcCrypto} and {@code Apdus}.
 */
public final class Iso9564 {

    private Iso9564() {
    }

    /** Format 1: control nibble 0, PIN length, BCD digits, F padding. */
    public static byte[] format1(String digits) {
        checkDigits(digits);
        byte[] block = new byte[8];
        Arrays.fill(block, (byte) 0xFF);
        block[0] = (byte) (digits.length() & 0x0F);
        byte[] bcd = Hex.bcd(digits);
        System.arraycopy(bcd, 0, block, 1, Math.min(bcd.length, 7));
        return block;
    }

    /** Format 2: control nibble 2, PIN length, BCD digits, F padding. */
    public static byte[] format2(String digits) {
        checkDigits(digits);
        byte[] block = new byte[8];
        Arrays.fill(block, (byte) 0xFF);
        block[0] = (byte) (0x20 | digits.length());
        byte[] bcd = Hex.bcd(digits);
        System.arraycopy(bcd, 0, block, 1, Math.min(bcd.length, 7));
        return block;
    }

    /** Format 0: the format-1 block XORed with 0000 || rightmost 12 PAN digits. */
    public static byte[] format0(String digits, byte[] pan) {
        byte[] pinBlock = format1(digits);
        pinBlock[0] = (byte) (digits.length() & 0x0F);

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

    private static void checkDigits(String digits) {
        if (digits == null || digits.length() < 4 || digits.length() > 12) {
            throw new IllegalArgumentException(
                    "PIN must be 4..12 digits: " + digits);
        }
        for (int i = 0; i < digits.length(); i++) {
            char c = digits.charAt(i);
            if (c < '0' || c > '9') {
                throw new IllegalArgumentException("PIN must be numeric: " + digits);
            }
        }
    }
}
