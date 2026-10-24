package card42.host.emrtd.lds.common;

import java.time.DateTimeException;
import java.time.LocalDate;

/**
 * An LDS date: DD/MM/YY in the MRZ (ICAO Doc 9303-4 §4.8) or YYYYMMDD in the
 * data groups (Doc 9303-10 §4.7.11/§4.7.12).
 *
 * <p>The two-digit MRZ year has no century.  The parser therefore takes a
 * reference year from the caller instead of using an implicit "current year"
 * rule; this keeps the result deterministic for tests and lets a report pass
 * the verification date.  Invalid dates are reported, never "corrected": the
 * {@link #date} field stays null and {@link #valid} is false.
 */
public final class LdsDate {

    /** The original text exactly as read from the document. */
    public final String raw;
    /** The calendar date, or null when {@link #valid} is false. */
    public final LocalDate date;
    public final boolean valid;

    private LdsDate(String raw, LocalDate date, boolean valid) {
        this.raw = raw;
        this.date = date;
        this.valid = valid;
    }

    private static LdsDate invalid(String raw) {
        return new LdsDate(raw, null, false);
    }

    /**
     * A date of birth from a six-digit {@code YYMMDD} MRZ field.  A birth date
     * cannot be in the future, so the latest candidate century not after
     * {@code referenceYear} is chosen (69 with reference 2026 is 1969).
     */
    public static LdsDate birthDate(String raw, int referenceYear) {
        if (!isDigits(raw, 6)) {
            return invalid(raw);
        }
        int yy = Integer.parseInt(raw.substring(0, 2));
        int candidate = 2000 + yy;
        if (candidate > referenceYear) {
            candidate = 1900 + yy;
        }
        return calendar(raw, candidate, raw.substring(2, 4), raw.substring(4, 6));
    }

    /**
     * A date of expiry from a six-digit {@code YYMMDD} MRZ field.  Of the two
     * candidate centuries, the one closest to {@code referenceYear} is chosen:
     * 94 with reference 2026 is 1994 (an expired document), 30 is 2030.
     */
    public static LdsDate expiryDate(String raw, int referenceYear) {
        if (!isDigits(raw, 6)) {
            return invalid(raw);
        }
        int yy = Integer.parseInt(raw.substring(0, 2));
        int past = 1900 + yy;
        int future = 2000 + yy;
        int candidate = Math.abs(future - referenceYear) <= Math.abs(past - referenceYear)
                ? future : past;
        return calendar(raw, candidate, raw.substring(2, 4), raw.substring(4, 6));
    }

    /**
     * A generic six-digit {@code YYMMDD} field with no known semantics: the
     * century that puts the year inside a window of +/-50 years around the
     * reference is chosen.
     */
    public static LdsDate yymmdd(String raw, int referenceYear) {
        if (!isDigits(raw, 6)) {
            return invalid(raw);
        }
        int yy = Integer.parseInt(raw.substring(0, 2));
        int candidate = 2000 + yy;
        if (candidate > referenceYear + 50) {
            candidate -= 100;
        } else if (candidate < referenceYear - 50) {
            candidate += 100;
        }
        return calendar(raw, candidate, raw.substring(2, 4), raw.substring(4, 6));
    }

    /** An eight-digit {@code YYYYMMDD} field (DG11/DG12). */
    public static LdsDate yyyymmdd(String raw) {
        if (!isDigits(raw, 8)) {
            return invalid(raw);
        }
        return calendar(raw, Integer.parseInt(raw.substring(0, 4)),
                raw.substring(4, 6), raw.substring(6, 8));
    }

    /** The date part of a {@code YYYYMMDDhhmmss} or {@code YYYYMMDD} field. */
    public static LdsDate yyyymmddhhmmss(String raw) {
        if (raw == null || raw.length() < 8) {
            return invalid(raw);
        }
        return yyyymmdd(raw.substring(0, 8));
    }

    private static LdsDate calendar(String raw, int year, String month, String day) {
        try {
            return new LdsDate(raw, LocalDate.of(year, Integer.parseInt(month),
                    Integer.parseInt(day)), true);
        } catch (DateTimeException e) {
            return invalid(raw);
        }
    }

    private static boolean isDigits(String s, int length) {
        if (s == null || s.length() != length) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        return valid && date != null ? date.toString() : (raw == null ? "" : raw);
    }
}
