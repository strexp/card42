package card42.host.emrtd.lds.lds1;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import card42.host.emrtd.lds.common.LdsDate;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.LdsText;
import card42.host.emrtd.lds.common.MrzCheckDigit;
import card42.host.emrtd.lds.common.ParseStatus;

/**
 * The machine readable zone of a travel document (ICAO Doc 9303-4:
 * TD1 3x30, TD2 2x36, TD3 2x44).
 *
 * <p>The model keeps every field in its raw MRZ spelling (including '&lt;'
 * fillers) and adds the parsed check digits and calendar dates.  Check-digit
 * and date problems are reported as {@link LdsIssue}s; the fields are never
 * discarded or "corrected" because a report still needs them.
 *
 * <p>The same parser is used for DG1 and for an MRZ typed or scanned at a
 * terminal, so manual input and card data validate identically.
 */
public final class Mrz {

    /** The three MRZ layouts of Doc 9303-4. */
    public enum Layout {
        TD1(3, 30),
        TD2(2, 36),
        TD3(2, 44),
        UNKNOWN(0, 0);

        public final int lines;
        public final int width;

        Layout(int lines, int width) {
            this.lines = lines;
            this.width = width;
        }

        public int length() {
            return lines * width;
        }
    }

    /** The input exactly as supplied (before CR/LF removal). */
    public final String raw;
    /** The MRZ with CR/LF removed, i.e. the characters that were parsed. */
    public final String normalized;
    public final Layout layout;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    public final String line1;
    public final String line2;
    /** The TD1 third line, or null for TD2/TD3. */
    public final String line3;

    /** The two-character document code as printed (e.g. "P&lt;", "I&lt;"). */
    public final String documentCode;
    public final String issuingState;
    public final String surname;
    public final String givenNames;
    /** The complete name field with '&lt;' fillers. */
    public final String rawNameField;
    public final String documentNumber;
    public final String documentNumberCheckDigit;
    public final String nationality;
    public final String dateOfBirth;
    public final LdsDate birthDate;
    public final String dateOfBirthCheckDigit;
    /** "M", "F" or "&lt;". */
    public final String sex;
    public final String dateOfExpiry;
    public final LdsDate expiryDate;
    public final String dateOfExpiryCheckDigit;
    /** TD3 personal number, or null. */
    public final String personalNumber;
    /** TD3 personal number check digit, or null. */
    public final String personalNumberCheckDigit;
    /** TD1 optional data 1 (line 1), or null. */
    public final String optionalData1;
    /** TD1 optional data 2, or TD2 optional data. */
    public final String optionalData2;
    public final String compositeCheckDigit;

    public final boolean documentNumberCheckOk;
    public final boolean dateOfBirthCheckOk;
    public final boolean dateOfExpiryCheckOk;
    public final boolean personalNumberCheckOk;
    public final boolean compositeCheckOk;

    private Mrz(Builder b) {
        this.raw = b.raw;
        this.normalized = b.normalized;
        this.layout = b.layout;
        this.status = b.status;
        this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(b.issues));
        this.line1 = b.line1;
        this.line2 = b.line2;
        this.line3 = b.line3;
        this.documentCode = b.documentCode;
        this.issuingState = b.issuingState;
        this.surname = b.surname;
        this.givenNames = b.givenNames;
        this.rawNameField = b.rawNameField;
        this.documentNumber = b.documentNumber;
        this.documentNumberCheckDigit = b.documentNumberCheckDigit;
        this.nationality = b.nationality;
        this.dateOfBirth = b.dateOfBirth;
        this.birthDate = b.birthDate;
        this.dateOfBirthCheckDigit = b.dateOfBirthCheckDigit;
        this.sex = b.sex;
        this.dateOfExpiry = b.dateOfExpiry;
        this.expiryDate = b.expiryDate;
        this.dateOfExpiryCheckDigit = b.dateOfExpiryCheckDigit;
        this.personalNumber = b.personalNumber;
        this.personalNumberCheckDigit = b.personalNumberCheckDigit;
        this.optionalData1 = b.optionalData1;
        this.optionalData2 = b.optionalData2;
        this.compositeCheckDigit = b.compositeCheckDigit;
        this.documentNumberCheckOk = b.documentNumberCheckOk;
        this.dateOfBirthCheckOk = b.dateOfBirthCheckOk;
        this.dateOfExpiryCheckOk = b.dateOfExpiryCheckOk;
        this.personalNumberCheckOk = b.personalNumberCheckOk;
        this.compositeCheckOk = b.compositeCheckOk;
    }

    /** Parses an MRZ, inferring the MRZ century from the current year. */
    public static Mrz parse(String raw) {
        return parse(raw, LocalDate.now().getYear());
    }

    /** Parses an MRZ, using {@code referenceYear} to resolve two-digit years. */
    public static Mrz parse(String raw, int referenceYear) {
        Builder b = new Builder(raw, referenceYear);
        if (raw == null || raw.isEmpty()) {
            b.issues.add(LdsIssue.error(LdsIssue.Code.EMPTY_VALUE, 1, 0, "empty MRZ"));
            b.status = ParseStatus.INVALID;
            return new Mrz(b);
        }
        b.normalized = raw.replace("\r", "").replace("\n", "");
        int length = b.normalized.length();
        if (length >= Layout.TD1.length()) {
            b.layout = Layout.TD1;
        } else if (length >= Layout.TD3.length()) {
            b.layout = Layout.TD3;
        } else if (length >= Layout.TD2.length()) {
            b.layout = Layout.TD2;
        } else {
            b.layout = Layout.UNKNOWN;
            b.issues.add(LdsIssue.error(LdsIssue.Code.UNSUPPORTED_LAYOUT, 1, 0,
                    "MRZ length " + length + " is not TD1/TD2/TD3"));
            b.status = ParseStatus.INVALID;
            return new Mrz(b);
        }
        if (length != b.layout.length()) {
            b.issues.add(LdsIssue.warn(LdsIssue.Code.TRAILING_DATA, 1, b.layout.length(),
                    "MRZ has " + (length - b.layout.length()) + " extra character(s)"));
        }
        if (b.layout == Layout.TD1) {
            parseTd1(b);
        } else if (b.layout == Layout.TD2) {
            parseTd2(b);
        } else {
            parseTd3(b);
        }
        b.status = b.issues.isEmpty() ? ParseStatus.OK : ParseStatus.PARTIAL;
        return new Mrz(b);
    }

    /** The MRZ as a byte array in US-ASCII. */
    public static Mrz parse(byte[] raw) {
        return parse(LdsText.ascii(raw));
    }

    private static void parseTd1(Builder b) {
        String l1 = b.line1 = slice(b.normalized, 0, 30);
        String l2 = b.line2 = slice(b.normalized, 30, 60);
        b.line3 = slice(b.normalized, 60, 90);
        b.documentCode = slice(l1, 0, 2);
        b.issuingState = slice(l1, 2, 5).trim();
        b.documentNumber = slice(l1, 5, 14).trim();
        b.documentNumberCheckDigit = slice(l1, 14, 15);
        b.optionalData1 = trimFillers(slice(l1, 15, 30));
        b.dateOfBirth = slice(l2, 0, 6);
        b.dateOfBirthCheckDigit = slice(l2, 6, 7);
        b.sex = slice(l2, 7, 8);
        b.dateOfExpiry = slice(l2, 8, 14);
        b.dateOfExpiryCheckDigit = slice(l2, 14, 15);
        b.nationality = slice(l2, 15, 18).trim();
        b.optionalData2 = trimFillers(slice(l2, 18, 29));
        b.compositeCheckDigit = slice(l2, 29, 30);
        b.rawNameField = b.line3;
        splitName(b, b.line3);
        b.documentNumberCheckOk = check(b, "document number",
                b.documentNumber, b.documentNumberCheckDigit);
        b.dateOfBirthCheckOk = check(b, "date of birth",
                b.dateOfBirth, b.dateOfBirthCheckDigit);
        b.dateOfExpiryCheckOk = check(b, "date of expiry",
                b.dateOfExpiry, b.dateOfExpiryCheckDigit);
        b.compositeCheckOk = check(b, "composite",
                slice(l1, 5, 15) + slice(l1, 15, 30) + slice(l2, 0, 7)
                        + slice(l2, 8, 15) + slice(l2, 18, 29),
                b.compositeCheckDigit);
        dates(b);
    }

    private static void parseTd2(Builder b) {
        String l1 = b.line1 = slice(b.normalized, 0, 36);
        String l2 = b.line2 = slice(b.normalized, 36, 72);
        b.documentCode = slice(l1, 0, 2);
        b.issuingState = slice(l1, 2, 5).trim();
        b.rawNameField = slice(l1, 5, 36);
        splitName(b, b.rawNameField);
        b.documentNumber = slice(l2, 0, 9).trim();
        b.documentNumberCheckDigit = slice(l2, 9, 10);
        b.nationality = slice(l2, 10, 13).trim();
        b.dateOfBirth = slice(l2, 13, 19);
        b.dateOfBirthCheckDigit = slice(l2, 19, 20);
        b.sex = slice(l2, 20, 21);
        b.dateOfExpiry = slice(l2, 21, 27);
        b.dateOfExpiryCheckDigit = slice(l2, 27, 28);
        b.optionalData2 = trimFillers(slice(l2, 28, 35));
        b.compositeCheckDigit = slice(l2, 35, 36);
        b.documentNumberCheckOk = check(b, "document number",
                b.documentNumber, b.documentNumberCheckDigit);
        b.dateOfBirthCheckOk = check(b, "date of birth",
                b.dateOfBirth, b.dateOfBirthCheckDigit);
        b.dateOfExpiryCheckOk = check(b, "date of expiry",
                b.dateOfExpiry, b.dateOfExpiryCheckDigit);
        b.compositeCheckOk = check(b, "composite",
                slice(l2, 0, 10) + slice(l2, 13, 20) + slice(l2, 21, 28)
                        + slice(l2, 28, 35),
                b.compositeCheckDigit);
        dates(b);
    }

    private static void parseTd3(Builder b) {
        String l1 = b.line1 = slice(b.normalized, 0, 44);
        String l2 = b.line2 = slice(b.normalized, 44, 88);
        b.documentCode = slice(l1, 0, 2);
        b.issuingState = slice(l1, 2, 5).trim();
        b.rawNameField = slice(l1, 5, 44);
        splitName(b, b.rawNameField);
        b.documentNumber = slice(l2, 0, 9).trim();
        b.documentNumberCheckDigit = slice(l2, 9, 10);
        b.nationality = slice(l2, 10, 13).trim();
        b.dateOfBirth = slice(l2, 13, 19);
        b.dateOfBirthCheckDigit = slice(l2, 19, 20);
        b.sex = slice(l2, 20, 21);
        b.dateOfExpiry = slice(l2, 21, 27);
        b.dateOfExpiryCheckDigit = slice(l2, 27, 28);
        b.personalNumber = trimFillers(slice(l2, 28, 42));
        b.personalNumberCheckDigit = slice(l2, 42, 43);
        b.compositeCheckDigit = slice(l2, 43, 44);
        b.documentNumberCheckOk = check(b, "document number",
                b.documentNumber, b.documentNumberCheckDigit);
        b.dateOfBirthCheckOk = check(b, "date of birth",
                b.dateOfBirth, b.dateOfBirthCheckDigit);
        b.dateOfExpiryCheckOk = check(b, "date of expiry",
                b.dateOfExpiry, b.dateOfExpiryCheckDigit);
        b.personalNumberCheckOk = check(b, "personal number",
                slice(l2, 28, 42), b.personalNumberCheckDigit);
        b.compositeCheckOk = check(b, "composite",
                slice(l2, 0, 10) + slice(l2, 13, 20) + slice(l2, 21, 28)
                        + slice(l2, 28, 42) + slice(l2, 42, 43),
                b.compositeCheckDigit);
        dates(b);
    }

    private static void dates(Builder b) {
        b.birthDate = LdsDate.birthDate(b.dateOfBirth, b.referenceYear);
        if (!b.birthDate.valid) {
            b.issues.add(LdsIssue.error(LdsIssue.Code.BAD_DATE, 1, 0,
                    "date of birth is not a valid YYMMDD date"));
        }
        b.expiryDate = LdsDate.expiryDate(b.dateOfExpiry, b.referenceYear);
        if (!b.expiryDate.valid) {
            b.issues.add(LdsIssue.error(LdsIssue.Code.BAD_DATE, 1, 0,
                    "date of expiry is not a valid YYMMDD date"));
        }
    }

    /** Adds a BAD_CHECK_DIGIT issue when the digit is not what the field expects. */
    private static boolean check(Builder b, String field, String value, String digit) {
        char expected = digit.isEmpty() ? '<' : digit.charAt(0);
        if (expected >= '0' && expected <= '9'
                && MrzCheckDigit.compute(value) == expected - '0') {
            return true;
        }
        b.issues.add(LdsIssue.error(LdsIssue.Code.BAD_CHECK_DIGIT, 1, 0,
                field + " check digit does not match"));
        return false;
    }

    private static void splitName(Builder b, String field) {
        int sep = field.indexOf("<<");
        if (sep < 0) {
            b.surname = field.replace('<', ' ').trim();
            b.givenNames = "";
        } else {
            b.surname = field.substring(0, sep).replace('<', ' ').trim();
            b.givenNames = field.substring(sep + 2).replace('<', ' ').trim();
        }
    }

    private static String trimFillers(String value) {
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == '<') {
            end--;
        }
        return value.substring(0, end);
    }

    private static String slice(String s, int from, int to) {
        if (s == null || from >= s.length()) {
            return "";
        }
        return s.substring(from, Math.min(to, s.length()));
    }

    /** A short label for reports ("TD1", "TD2", "TD3"). */
    public String layoutName() {
        return layout.name();
    }

    /** True when every check digit and date is valid. */
    public boolean fullyValid() {
        return status == ParseStatus.OK;
    }

    private static final class Builder {
        final String raw;
        final int referenceYear;
        final List<LdsIssue> issues = new ArrayList<LdsIssue>();
        String normalized = "";
        Layout layout = Layout.UNKNOWN;
        ParseStatus status = ParseStatus.INVALID;
        String line1;
        String line2;
        String line3;
        String documentCode;
        String issuingState;
        String surname;
        String givenNames;
        String rawNameField;
        String documentNumber;
        String documentNumberCheckDigit;
        String nationality;
        String dateOfBirth;
        LdsDate birthDate;
        String dateOfBirthCheckDigit;
        String sex;
        String dateOfExpiry;
        LdsDate expiryDate;
        String dateOfExpiryCheckDigit;
        String personalNumber;
        String personalNumberCheckDigit;
        String optionalData1;
        String optionalData2;
        String compositeCheckDigit;
        boolean documentNumberCheckOk;
        boolean dateOfBirthCheckOk;
        boolean dateOfExpiryCheckOk;
        boolean personalNumberCheckOk;
        boolean compositeCheckOk;

        Builder(String raw, int referenceYear) {
            this.raw = raw;
            this.referenceYear = referenceYear;
        }
    }
}
