package card42.host.emv.oda;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;

import javax.smartcardio.ResponseAPDU;

import card42.host.emv.lib.IssuerKey;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Bytes;
import card42.host.common.util.Digests;
import card42.host.common.codec.Tags;

/**
 * Terminal-side Static Data Authentication (EMV v4.4 Book 2 §5): reads the
 * records listed by the AFL, recovers the issuer key and verifies the SSAD.
 * Part of the reference host stack (ODA).
 *
 * <p>It reads the records listed by the AFL, rebuilds the static data input,
 * recovers the issuer public key from its CA certificate and recovers/verifies
 * the Signed Static Application Data with that key.  The same recovered key is
 * then used to verify the ICC PIN encipherment public key certificate
 * (EMV v4.4 Book 2 §7.2).
 *
 * <p>The CA public key is selected by the CA Public Key Index ('8F') from the
 * caller-supplied {@link CaKeyStore}; the library holds no key material and
 * never reports to stdout: every method returns a {@link Result} the caller
 * interprets.
 */
public final class SdaVerifier {

    /** The outcome of one SDA verification step. */
    public static final class Result {
        /** True when the step succeeded. */
        public final boolean ok;
        /** A short failure description, or null when {@link #ok}. */
        public final String reason;
        /** The recovered key on success, or null. */
        public final IssuerKey key;
        /**
         * The Data Authentication Code recovered from the SSAD on a successful
         * SDA (tag '9F45', EMV v4.4 Book 2 §5.4), or null when SDA was not
         * performed.
         */
        public final byte[] dataAuthenticationCode;
        /**
         * True when the failure is due to required ICC data being absent
         * (EMV v4.4 Book 3 §7.5 Table 35 'ICC data missing').
         */
        public final boolean dataMissing;

        Result(boolean ok, String reason, IssuerKey key) {
            this(ok, reason, key, null, false);
        }

        Result(boolean ok, String reason, IssuerKey key, byte[] dataAuthenticationCode) {
            this(ok, reason, key, dataAuthenticationCode, false);
        }

        Result(boolean ok, String reason, IssuerKey key, byte[] dataAuthenticationCode,
                boolean dataMissing) {
            this.ok = ok;
            this.reason = reason;
            this.key = key;
            this.dataAuthenticationCode = dataAuthenticationCode;
            this.dataMissing = dataMissing;
        }
    }

    private SdaVerifier() {
    }

    /**
     * Verifies the SDA certificate chain of the selected application
     * (EMV v4.4 Book 2 §5).  On success the recovered issuer public key is in
     * {@link Result#key} (needed to verify the ICC PIN certificate).
     */
    public static Result verify(Terminal terminal, byte[] afl, int aip, CaKeyStore caStore)
            throws Exception {
        return verify(terminal, afl, aip, caStore, true, null);
    }

    /**
     * Recovers the issuer public key and, when {@code requireSsad} is true,
     * verifies the Signed Static Application Data (SDA).  DDA and CDA need only
     * the issuer public key to recover the ICC public key; they must not be
     * required to carry the SSAD (EMV v4.4 Book 3 §10.3: the terminal selects a
     * single ODA method, DDA/CDA do not perform SDA).
     */
    public static Result verify(Terminal terminal, byte[] afl, int aip, CaKeyStore caStore,
            boolean requireSsad) throws Exception {
        return verify(terminal, afl, aip, caStore, requireSsad, null);
    }

    /**
     * As {@link #verify(Terminal, byte[], int, CaKeyStore, boolean)} but also
     * checks the issuer certificate expiration date against {@code transactionDate}
     * (tag '9A', YYMMDD; null skips the expiry check) (EMV v4.4 Book 2 §5.3/§6.3
     * step 9).
     */
    public static Result verify(Terminal terminal, byte[] afl, int aip, CaKeyStore caStore,
            boolean requireSsad, byte[] transactionDate) throws Exception {

        ByteArrayOutputStream daInput = new ByteArrayOutputStream();
        byte[] cert = null;
        byte[] remainder = null;
        byte[] exponent = null;
        byte[] ssad = null;
        byte[] caIndex = null;
        byte[] sdaTagList = null;
        byte[] pan = null;

        for (int e = 0; e + 3 < afl.length; e += 4) {
            int sfi = (afl[e] & 0xFF) >> 3;
            int first = afl[e + 1] & 0xFF;
            int lastRecord = afl[e + 2] & 0xFF;
            int oda = afl[e + 3] & 0xFF;
            for (int record = first; record <= lastRecord; record++) {
                ResponseAPDU rr = terminal.readRecord(record, sfi);
                if (rr.getSW() != 0x9000) {
                    // EMV v4.4 Book 3 section 10.2: a record read that does not
                    // return 9000 terminates the transaction; do not skip it
                    // (docs/specs/common/toolchain.md §6).
                    return new Result(false, "SDA READ RECORD SFI " + sfi + " rec " + record
                            + " -> " + sw(rr.getSW()), null);
                }
                byte[] data = rr.getData();
                if (oda > 0) {
                    // SFI 1-10: only the value of the 70 template; SFI > 10:
                    // the whole record (EMV v4.4 Book 3 section 10.3).
                    if (sfi <= 10) {
                        byte[] body = Tags.find(data, 0x70);
                        if (body != null) {
                            daInput.write(body, 0, body.length);
                        }
                    } else {
                        daInput.write(data, 0, data.length);
                    }
                    oda--;
                }
                byte[] t;
                if ((t = Tags.find(data, 0x8F)) != null) caIndex = t;
                if ((t = Tags.find(data, 0x90)) != null) cert = t;
                if ((t = Tags.find(data, 0x92)) != null) remainder = t;
                if ((t = Tags.find(data, 0x9F32)) != null) exponent = t;
                if ((t = Tags.find(data, 0x93)) != null) ssad = t;
                if ((t = Tags.find(data, 0x9F4A)) != null) sdaTagList = t;
                if ((t = Tags.find(data, 0x5A)) != null) pan = t;
            }
        }

        // The Issuer Public Key Remainder ('92') is present only when the issuer
        // modulus is longer than NCA-36 (EMV v4.4 Book 2 §5.1/Table 6).
        if (cert == null || exponent == null || (requireSsad && ssad == null)) {
            return new Result(false, "SDA data present (8F/90/92/9F32/93)", null, null, true);
        }
        if (caIndex == null) {
            return new Result(false, "SDA CA Public Key Index (8F) missing", null, null, true);
        }
        CaKey ca = caStore == null ? null : caStore.byIndex(caIndex);
        if (ca == null) {
            return new Result(false, "unknown SDA CA Public Key Index "
                    + card42.host.common.util.Hex.format(caIndex), null);
        }
        // The Issuer Public Key Certificate length must equal the CA Public Key
        // Modulus length (EMV v4.4 Book 2 §5.3 step 1).
        if (cert.length != (ca.modulus.bitLength() + 7) / 8) {
            return new Result(false, "SDA issuer certificate length", null);
        }

        // If a Static Data Authentication Tag List is present, only tag 82
        // (AIP) is allowed and its value is appended to the static data input.
        // It is processed for SDA, DDA and CDA (EMV v4.4 Book 2 §5.3 step 5 and
        // §6.4 step 5; EMV v4.4 Book 3 §10.3).
        if (sdaTagList != null) {
            for (byte tag : sdaTagList) {
                if ((tag & 0xFF) != 0x82) {
                    return new Result(false, "SDA tag list contains unsupported tag "
                            + String.format("%02X", tag), null);
                }
                daInput.write((aip >> 8) & 0xFF);
                daInput.write(aip & 0xFF);
            }
        }

        // Issuer public key certificate: recover with the CA public key and
        // check the structure, hash, PAN, expiry and algorithm indicator
        // (EMV v4.4 Book 2 §5.3 steps 3-11, Table 6).
        byte[] recCert = Sda.recover(cert, ca.modulus, ca.exponent);
        boolean certStructure = recCert[0] == 0x6A && recCert[1] == 0x02
                && recCert[recCert.length - 1] == (byte) 0xBC;
        // Issuer Public Key Algorithm Indicator (offset 12): RSA ('01') only.
        boolean algorithm = recCert[12] == 0x01;
        // Issuer Identifier (offset 2) matches the leftmost PAN digits, with
        // hexadecimal 'F' padding treated as a wildcard (step 8).
        boolean panMatch = pan == null || issuerIdentifierMatchesPan(recCert, pan);
        // Certificate Expiration Date (offset 6, MMYY) not before the
        // transaction date (step 9).
        boolean expiry = certificateNotExpired(recCert, 6, transactionDate);
        byte[] certHashInput = remainder == null
                ? Bytes.concat(Arrays.copyOfRange(recCert, 1, recCert.length - 21), exponent)
                : Bytes.concat(Arrays.copyOfRange(recCert, 1, recCert.length - 21),
                        remainder, exponent);
        boolean certHash = Arrays.equals(Digests.sha1(certHashInput),
                Arrays.copyOfRange(recCert, recCert.length - 21, recCert.length - 1));
        if (!(certStructure && algorithm && panMatch && expiry && certHash)) {
            return new Result(false, "SDA issuer public key certificate", null);
        }

        // Issuer public key modulus = leftmost digits (offset 15) followed by
        // the remainder only when NI > NCA-36; a shorter key is stored padded
        // with 'BB' and its length is the Issuer Public Key Length byte at
        // offset 13 (EMV v4.4 Book 2 Table 6).
        int keyDigits = recCert.length - 36;
        int issuerModulusLength = recCert[13] & 0xFF;
        byte[] issuerModulus;
        if (issuerModulusLength > keyDigits) {
            if (remainder == null) {
                return new Result(false, "SDA issuer public key remainder", null, null, true);
            }
            issuerModulus = Bytes.concat(
                    Arrays.copyOfRange(recCert, 15, 15 + keyDigits), remainder);
        } else {
            issuerModulus = Arrays.copyOfRange(recCert, 15, 15 + issuerModulusLength);
        }

        // SSAD: recover with the issuer public key and check the hash over the
        // recovered data and the static data input (EMV v4.4 Book 2, table 7).
        // Only when SDA is the selected ODA method (requireSsad).
        byte[] dataAuthenticationCode = null;
        if (requireSsad) {
            byte[] recSsad = Sda.recover(ssad,
                    new BigInteger(1, issuerModulus), new BigInteger(1, exponent));
            boolean ssadStructure = recSsad[0] == 0x6A && recSsad[1] == 0x03
                    && recSsad[recSsad.length - 1] == (byte) 0xBC;
            byte[] ssadHashInput = Bytes.concat(
                    Arrays.copyOfRange(recSsad, 1, recSsad.length - 21),
                    daInput.toByteArray());
            boolean ssadHash = Arrays.equals(Digests.sha1(ssadHashInput),
                    Arrays.copyOfRange(recSsad, recSsad.length - 21, recSsad.length - 1));
            if (!(ssadStructure && ssadHash)) {
                return new Result(false, "SDA signed static application data", null);
            }
            // Table 7: 6A || Signed Data Format || Hash Algorithm Indicator ||
            // Data Authentication Code (2 bytes) || ...
            dataAuthenticationCode = new byte[] { recSsad[3], recSsad[4] };
        }
        return new Result(true, null, new IssuerKey(new BigInteger(1, issuerModulus),
                new BigInteger(1, exponent), daInput.toByteArray(), issuerModulus.length, pan),
                dataAuthenticationCode);
    }

    /**
     * Reads the ICC PIN encipherment public key certificate from record 4,
     * recovers it with the issuer public key and verifies its structure and
     * hash (EMV v4.4 Book 2, table 23).  The recovered key is in {@link Result#key}.
     */
    public static Result recoverPinKey(Terminal terminal, IssuerKey issuer)
            throws Exception {
        return recoverPinKey(terminal, issuer, null);
    }

    /** As {@link #recoverPinKey(Terminal, IssuerKey)} with the certificate
     * expiry checked against {@code transactionDate} (tag '9A', YYMMDD). */
    public static Result recoverPinKey(Terminal terminal, IssuerKey issuer,
            byte[] transactionDate) throws Exception {
        // The PIN certificate hash omits the static data to be authenticated
        // (EMV v4.4 Book 2 Table 23 note 31).
        return recoverIssuerSignedKey(terminal, issuer, 4,
                0x9F2D, 0x9F2F, 0x9F2E, "PIN", "ICC PIN", "9F2D/9F2F/9F2E", false,
                transactionDate);
    }

    /**
     * Reads the ICC DDA/CDA public key certificate from record 5, recovers it
     * with the issuer public key and verifies its structure and hash (EMV Book
     * 2, table 13).  The recovered key is in {@link Result#key}.
     */
    public static Result recoverIccKey(Terminal terminal, IssuerKey issuer)
            throws Exception {
        return recoverIccKey(terminal, issuer, null);
    }

    /** As {@link #recoverIccKey(Terminal, IssuerKey)} with the certificate
     * expiry checked against {@code transactionDate} (tag '9A', YYMMDD). */
    public static Result recoverIccKey(Terminal terminal, IssuerKey issuer,
            byte[] transactionDate) throws Exception {
        // The ICC DDA/CDA certificate hash includes the static data to be
        // authenticated (EMV v4.4 Book 2 §6.4 step 5 / Table 14).
        return recoverIssuerSignedKey(terminal, issuer, 5,
                0x9F46, 0x9F48, 0x9F47, "ICC", "ICC", "9F46/9F48/9F47", true,
                transactionDate);
    }

    /**
     * Reads one ICC public key certificate record, recovers it with the issuer
     * public key and verifies its structure (format '04') and hash (EMV v4.4
     * Book 2 Tables 13/23).  The two ICC certificates differ only in the record
     * and tags, whether the static data to be authenticated is part of the hash
     * input, and the diagnostic wording, so one routine serves both.
     *
     * @param includeStaticData true for the DDA/CDA certificate, false for the
     *                          PIN encipherment certificate
     */
    private static Result recoverIssuerSignedKey(Terminal terminal, IssuerKey issuer,
            int record, int certTag, int remainderTag, int exponentTag,
            String recordLabel, String name, String tagList, boolean includeStaticData,
            byte[] transactionDate) throws Exception {
        ResponseAPDU rec = terminal.readRecord(record, 1);
        if (rec.getSW() != 0x9000) {
            return new Result(false,
                    "READ RECORD " + recordLabel + " certificate -> " + sw(rec.getSW()), null);
        }
        byte[] cert = Tags.find(rec.getData(), certTag);
        byte[] remainder = Tags.find(rec.getData(), remainderTag);
        byte[] exponent = Tags.find(rec.getData(), exponentTag);
        // The ICC Public Key Remainder is present only when the ICC modulus is
        // longer than NI-42 (EMV v4.4 Book 2 Table 14).
        if (cert == null || exponent == null) {
            return new Result(false, name + " certificate data present (" + tagList + ")",
                    null, null, true);
        }
        // The ICC Public Key Certificate length must equal the Issuer Public Key
        // Modulus length (EMV v4.4 Book 2 §6.4 step 1).
        if (cert.length != issuer.modulusBytes) {
            return new Result(false, name + " public key certificate length", null);
        }

        // Recover the certificate with the issuer public key (EMV v4.4 Book 2
        // Tables 13/23).  The leftmost 21 bytes hold the header and the
        // certificate expiration/ serial data; the hash follows the key
        // modulus.
        int leftmost = issuer.modulusBytes - 42;
        byte[] recCert = Sda.recover(cert, issuer.modulus, issuer.exponent);
        boolean structure = recCert[0] == 0x6A && recCert[1] == 0x04
                && recCert[recCert.length - 1] == (byte) 0xBC;
        // ICC Public Key Algorithm Indicator (offset 18): RSA ('01') only.
        boolean algorithm = recCert[18] == 0x01;
        // Application PAN (offset 2) matches the card PAN, with 'F' padding
        // (EMV v4.4 Book 2 §6.4 step 8).
        boolean panMatch = issuer.pan == null || applicationPanMatches(recCert, issuer.pan);
        // Certificate Expiration Date (offset 12, MMYY).
        boolean expiry = certificateNotExpired(recCert, 12, transactionDate);
        byte[] base = Arrays.copyOfRange(recCert, 1, 21 + leftmost);
        byte[] certHashInput = remainder == null
                ? (includeStaticData
                        ? Bytes.concat(base, exponent,
                                issuer.staticData == null ? new byte[0] : issuer.staticData)
                        : Bytes.concat(base, exponent))
                : (includeStaticData
                        ? Bytes.concat(base, remainder, exponent,
                                issuer.staticData == null ? new byte[0] : issuer.staticData)
                        : Bytes.concat(base, remainder, exponent));
        boolean hash = Arrays.equals(Digests.sha1(certHashInput),
                Arrays.copyOfRange(recCert, 21 + leftmost, 21 + leftmost + 20));
        if (!(structure && algorithm && panMatch && expiry && hash)) {
            return new Result(false, name + " public key certificate", null);
        }
        // ICC modulus = leftmost digits (offset 21) followed by the remainder
        // only when NIC > NI-42; a shorter key is stored padded with 'BB' and
        // its length is the ICC Public Key Length byte at offset 19.
        int iccModulusLength = recCert[19] & 0xFF;
        byte[] modulus;
        if (iccModulusLength > leftmost) {
            if (remainder == null) {
                return new Result(false, name + " public key remainder", null, null, true);
            }
            modulus = Bytes.concat(
                    Arrays.copyOfRange(recCert, 21, 21 + leftmost), remainder);
        } else {
            modulus = Arrays.copyOfRange(recCert, 21, 21 + iccModulusLength);
        }
        return new Result(true, null, new IssuerKey(new BigInteger(1, modulus),
                new BigInteger(1, exponent), issuer.staticData, modulus.length, issuer.pan));
    }

    /**
     * True when the certificate's Issuer Identifier (4 bytes at offset 2) equals
     * the leftmost PAN digits; the hexadecimal 'F' padding nibbles are wildcards
     * (EMV v4.4 Book 2 §5.3/§6.3 step 8).
     */
    private static boolean issuerIdentifierMatchesPan(byte[] recCert, byte[] pan) {
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
    private static boolean applicationPanMatches(byte[] recCert, byte[] pan) {
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
    private static boolean certificateNotExpired(byte[] recCert, int offset,
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
    private static int bcd(byte value) {
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
    private static int fourDigitYear(int yy) {
        if (yy == 0xFF) {
            return 0xFF; // non-BCD: keep it out of any valid comparison range
        }
        return yy < 50 ? 2000 + yy : 1900 + yy;
    }

    /** The nibble at the given nibble index within a 4-byte field at byteOffset. */
    private static int nibbleAt(byte[] b, int byteOffset, int nibble) {
        int idx = byteOffset + (nibble >> 1);
        if (idx >= b.length) {
            return 0xF;
        }
        int v = b[idx] & 0xFF;
        return (nibble & 1) == 0 ? (v >> 4) & 0x0F : v & 0x0F;
    }

    private static String sw(int sw) {
        return String.format("%04X", sw & 0xFFFF);
    }
}
