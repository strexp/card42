package card42.host.emrtd.lds.lds2;

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
 * The machine readable zone of a visa (ICAO Doc 9303-7): MRV-A is two 44-character
 * lines, MRV-B two 36-character lines.
 *
 * <p>The field positions follow the visa layouts of Doc 9303-7.  As with
 * {@link card42.host.emrtd.lds.lds1.Mrz}, check-digit and date problems are
 * reported as issues and the raw fields are kept.  The application data of the
 * visa record (number of entries, duration of stay, ...) lives in
 * {@link VisaRecord}, not in the MRZ.
 */
public final class Mrv {

    /** The two visa MRZ layouts. */
    public enum Layout {
        MRV_A(2, 44),
        MRV_B(2, 36),
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

    public final String raw;
    public final String normalized;
    public final Layout layout;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    public final String line1;
    public final String line2;
    public final String documentCode;
    public final String issuingState;
    public final String visaNumber;
    public final String visaNumberCheckDigit;
    public final String surname;
    public final String givenNames;
    public final String rawNameField;
    public final String nationality;
    public final String dateOfBirth;
    public final String dateOfBirthCheckDigit;
    public final LdsDate birthDate;
    public final String sex;
    public final String dateOfExpiry;
    public final String dateOfExpiryCheckDigit;
    public final LdsDate expiryDate;
    public final String optionalData;
    public final String compositeCheckDigit;
    public final boolean visaNumberCheckOk;
    public final boolean dateOfBirthCheckOk;
    public final boolean dateOfExpiryCheckOk;
    public final boolean compositeCheckOk;

    private Mrv(Builder b) {
        this.raw = b.raw;
        this.normalized = b.normalized;
        this.layout = b.layout;
        this.status = b.status;
        this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(b.issues));
        this.line1 = b.line1;
        this.line2 = b.line2;
        this.documentCode = b.documentCode;
        this.issuingState = b.issuingState;
        this.visaNumber = b.visaNumber;
        this.visaNumberCheckDigit = b.visaNumberCheckDigit;
        this.surname = b.surname;
        this.givenNames = b.givenNames;
        this.rawNameField = b.rawNameField;
        this.nationality = b.nationality;
        this.dateOfBirth = b.dateOfBirth;
        this.dateOfBirthCheckDigit = b.dateOfBirthCheckDigit;
        this.birthDate = b.birthDate;
        this.sex = b.sex;
        this.dateOfExpiry = b.dateOfExpiry;
        this.dateOfExpiryCheckDigit = b.dateOfExpiryCheckDigit;
        this.expiryDate = b.expiryDate;
        this.optionalData = b.optionalData;
        this.compositeCheckDigit = b.compositeCheckDigit;
        this.visaNumberCheckOk = b.visaNumberCheckOk;
        this.dateOfBirthCheckOk = b.dateOfBirthCheckOk;
        this.dateOfExpiryCheckOk = b.dateOfExpiryCheckOk;
        this.compositeCheckOk = b.compositeCheckOk;
    }

    /** Parses an MRV with the current year as the century reference. */
    public static Mrv parse(String raw) {
        return parse(raw, LocalDate.now().getYear());
    }

    /** Parses an MRV-A or MRV-B string. */
    public static Mrv parse(String raw, int referenceYear) {
        Builder b = new Builder(raw, referenceYear);
        if (raw == null || raw.isEmpty()) {
            b.issues.add(LdsIssue.error(LdsIssue.Code.EMPTY_VALUE, 0, 0, "empty MRV"));
            b.status = ParseStatus.INVALID;
            return new Mrv(b);
        }
        b.normalized = raw.replace("\r", "").replace("\n", "");
        int length = b.normalized.length();
        if (length >= Layout.MRV_A.length()) {
            b.layout = Layout.MRV_A;
        } else if (length >= Layout.MRV_B.length()) {
            b.layout = Layout.MRV_B;
        } else {
            b.layout = Layout.UNKNOWN;
            b.issues.add(LdsIssue.error(LdsIssue.Code.UNSUPPORTED_LAYOUT, 0, 0,
                    "MRV length " + length + " is not MRV-A/MRV-B"));
            b.status = ParseStatus.INVALID;
            return new Mrv(b);
        }
        if (length != b.layout.length()) {
            b.issues.add(LdsIssue.warn(LdsIssue.Code.TRAILING_DATA, 0,
                    b.layout.length(), "MRV has extra character(s)"));
        }
        parseLayout(b);
        b.status = b.issues.isEmpty() ? ParseStatus.OK : ParseStatus.PARTIAL;
        return new Mrv(b);
    }

    /** Parses an MRV from its ASCII bytes. */
    public static Mrv parse(byte[] raw) {
        return parse(LdsText.ascii(raw));
    }

    private static void parseLayout(Builder b) {
        int width = b.layout.width;
        String l1 = b.line1 = slice(b.normalized, 0, width);
        String l2 = b.line2 = slice(b.normalized, width, width * 2);
        b.documentCode = slice(l1, 0, 2);
        b.issuingState = slice(l1, 2, 5).trim();
        b.rawNameField = slice(l1, 5, width);
        splitName(b, b.rawNameField);
        b.visaNumber = slice(l2, 0, 9).trim();
        b.visaNumberCheckDigit = slice(l2, 9, 10);
        b.nationality = slice(l2, 10, 13).trim();
        b.dateOfBirth = slice(l2, 13, 19);
        b.dateOfBirthCheckDigit = slice(l2, 19, 20);
        b.sex = slice(l2, 20, 21);
        b.dateOfExpiry = slice(l2, 21, 27);
        b.dateOfExpiryCheckDigit = slice(l2, 27, 28);
        b.optionalData = trimFillers(slice(l2, 28, width - 1));
        b.compositeCheckDigit = slice(l2, width - 1, width);
        b.visaNumberCheckOk = check(b, "visa number", b.visaNumber,
                b.visaNumberCheckDigit);
        b.dateOfBirthCheckOk = check(b, "date of birth", b.dateOfBirth,
                b.dateOfBirthCheckDigit);
        b.dateOfExpiryCheckOk = check(b, "date of expiry", b.dateOfExpiry,
                b.dateOfExpiryCheckDigit);
        // Doc 9303-7 does not define a composite check digit for MRV-A/MRV-B
        // (unlike TD1/TD2/TD3); the last character is kept for display only.
        b.compositeCheckOk = true;
        b.birthDate = LdsDate.birthDate(b.dateOfBirth, b.referenceYear);
        if (!b.birthDate.valid) {
            b.issues.add(LdsIssue.error(LdsIssue.Code.BAD_DATE, 0, 0,
                    "date of birth is not a valid YYMMDD date"));
        }
        b.expiryDate = LdsDate.expiryDate(b.dateOfExpiry, b.referenceYear);
        if (!b.expiryDate.valid) {
            b.issues.add(LdsIssue.error(LdsIssue.Code.BAD_DATE, 0, 0,
                    "date of expiry is not a valid YYMMDD date"));
        }
    }

    private static boolean check(Builder b, String field, String value, String digit) {
        char expected = digit.isEmpty() ? '<' : digit.charAt(0);
        if (expected >= '0' && expected <= '9'
                && MrzCheckDigit.compute(value) == expected - '0') {
            return true;
        }
        b.issues.add(LdsIssue.error(LdsIssue.Code.BAD_CHECK_DIGIT, 0, 0,
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
        String documentCode;
        String issuingState;
        String visaNumber;
        String visaNumberCheckDigit;
        String surname;
        String givenNames;
        String rawNameField;
        String nationality;
        String dateOfBirth;
        String dateOfBirthCheckDigit;
        LdsDate birthDate;
        String sex;
        String dateOfExpiry;
        String dateOfExpiryCheckDigit;
        LdsDate expiryDate;
        String optionalData;
        String compositeCheckDigit;
        boolean visaNumberCheckOk;
        boolean dateOfBirthCheckOk;
        boolean dateOfExpiryCheckOk;
        boolean compositeCheckOk;

        Builder(String raw, int referenceYear) {
            this.raw = raw;
            this.referenceYear = referenceYear;
        }
    }
}
