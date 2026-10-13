package card42.host.emv.oda;

/**
 * Certificate field checks shared by the SDA and ICC certificate verification
 * (EMV v4.4 Book 2 §5.3/§6.3/§6.4).  Pure functions of the recovered
 * certificate bytes and the transaction date; split out of {@link SdaVerifier}.
 */
final class CertificateChecks {

    private CertificateChecks() {
    }

    /**
     * True when the certificate's Issuer Identifier (4 bytes at offset 2) equals
     * the leftmost PAN digits; the hexadecimal 'F' padding nibbles are wildcards
     * (EMV v4.4 Book 2 §5.3/§6.3 step 8).
     */
    static boolean issuerIdentifierMatchesPan(byte[] recCert, byte[] pan) {
        for (int i = 0; i < 8; i++) {
            int id = nibbleAt(recCert, 2, i);
            if (id == 0xF) {
                continue; // padding
            }
            if (nibbleAt(pan, 0, i) != id) {
                return false;
            }
        }
        return true;
    }

    /**
     * True when the certificate's Application PAN (10 bytes at offset 2) equals
     * the card PAN; the 'F' padding nibbles are wildcards (EMV v4.4 Book 2
     * §6.4 step 8).
     */
    static boolean applicationPanMatches(byte[] recCert, byte[] pan) {
        for (int i = 0; i < 20; i++) {
            int certPan = nibbleAt(recCert, 2, i);
            if (certPan == 0xF) {
                continue; // padding
            }
            if (nibbleAt(pan, 0, i) != certPan) {
                return false;
            }
        }
        return true;
    }

    /**
     * True when the certificate expiration date (MMYY at {@code offset}) is not
     * before the transaction date (tag '9A', YYMMDD); a null date skips the
     * check (EMV v4.4 Book 2 §5.3/§6.3 step 9).
     *
     * <p>The 2-digit years are expanded per EMV v4.4 Book 4 §6.7.1/§6.7.3
     * (data authentication dates before, including and after 2000): YY 00-49 is
     * 20YY and YY 50-99 is 19YY.  Both dates are BCD-encoded, so each byte is
     * decoded before comparison; a raw byte comparison would mis-order dates
     * across the century boundary.
     */
    static boolean certificateNotExpired(byte[] recCert, int offset,
            byte[] transactionDate) {
        if (transactionDate == null || transactionDate.length < 2) {
            return true;
        }
        int expiryMonth = bcd(recCert[offset]);
        int expiryYear = fourDigitYear(bcd(recCert[offset + 1]));
        int txYear = fourDigitYear(bcd(transactionDate[0]));
        int txMonth = bcd(transactionDate[1]);
        if (txYear != expiryYear) {
            return txYear < expiryYear;
        }
        return txMonth <= expiryMonth;
    }

    /** Decodes one BCD byte (two decimal digits), or 0xFF for a non-decimal nibble. */
    static int bcd(byte value) {
        int hi = (value >> 4) & 0x0F;
        int lo = value & 0x0F;
        if (hi > 9 || lo > 9) {
            return 0xFF;
        }
        return hi * 10 + lo;
    }

    /**
     * Expands a 2-digit year to four digits (EMV v4.4 Book 4 §6.7.3): 00-49 is
     * 20YY, 50-99 is 19YY.
     */
    static int fourDigitYear(int yy) {
        if (yy == 0xFF) {
            return 0xFF; // non-BCD: keep it out of any valid comparison range
        }
        return yy < 50 ? 2000 + yy : 1900 + yy;
    }

    /** The nibble at the given nibble index within a field starting at byteOffset. */
    static int nibbleAt(byte[] b, int byteOffset, int nibble) {
        int idx = byteOffset + (nibble >> 1);
        if (idx >= b.length) {
            return 0xF;
        }
        int v = b[idx] & 0xFF;
        return (nibble & 1) == 0 ? (v >> 4) & 0x0F : v & 0x0F;
    }
}
