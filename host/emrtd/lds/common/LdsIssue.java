package card42.host.emrtd.lds.common;

/**
 * One data-quality observation produced while parsing a data group
 * (ICAO Doc 9303-10 §4.7).
 *
 * <p>The message is diagnostic only: it names the field or structure, never a
 * field <em>value</em>, so it is safe to log.  {@code offset} is the byte
 * offset inside the raw EF (offset 0 is the outer tag) when known, or -1.
 * {@code dg} is the data group number (0 when unknown).
 */
public final class LdsIssue {

    /** How severe the observation is. */
    public enum Severity {
        /** Informational; the model is complete. */
        INFO,
        /** The model is usable but something was skipped or guessed. */
        WARN,
        /** A mandatory structure or a check digit is wrong; the field is absent. */
        ERROR
    }

    /**
     * Stable issue codes for callers that map them to their own messages or
     * i18n keys.  New codes may be added; existing codes do not change meaning.
     */
    public enum Code {
        /** A mandatory structure (outer tag, MRZ, biometric header, ...) is missing. */
        MISSING_MANDATORY,
        /** A TLVs tag or length is truncated. */
        TRUNCATED_TLV,
        /** A length field is inconsistent with the surrounding record. */
        BAD_LENGTH,
        /** A tag is malformed or appears where it is not allowed. */
        BAD_TAG,
        /** An unknown or vendor-specific tag was kept as raw bytes. */
        UNKNOWN_TAG,
        /** An MRZ check digit does not match. */
        BAD_CHECK_DIGIT,
        /** A date is syntactically or calendrically invalid. */
        BAD_DATE,
        /** Text was not valid UTF-8 and the ISO-8859-1 fallback was used. */
        BAD_ENCODING,
        /** An image/record format is not recognised. */
        UNKNOWN_FORMAT,
        /** A declared instance count differs from the number of records found. */
        COUNT_MISMATCH,
        /** The layout is not one this parser implements. */
        UNSUPPORTED_LAYOUT,
        /** Bytes follow the complete outer object and were ignored. */
        TRAILING_DATA,
        /** The bytes do not start with the expected data-group tag. */
        OUTER_TAG_MISMATCH,
        /** The EF is empty. */
        EMPTY_VALUE
    }

    public final Severity severity;
    public final Code code;
    public final int dg;
    public final int offset;
    public final String message;

    public LdsIssue(Severity severity, Code code, int dg, int offset, String message) {
        this.severity = severity;
        this.code = code;
        this.dg = dg;
        this.offset = offset;
        this.message = message;
    }

    /** A warning: the model stays usable. */
    public static LdsIssue warn(Code code, int dg, int offset, String message) {
        return new LdsIssue(Severity.WARN, code, dg, offset, message);
    }

    /** An error: a mandatory structure or a check failed. */
    public static LdsIssue error(Code code, int dg, int offset, String message) {
        return new LdsIssue(Severity.ERROR, code, dg, offset, message);
    }

    /** An informational observation. */
    public static LdsIssue info(Code code, int dg, int offset, String message) {
        return new LdsIssue(Severity.INFO, code, dg, offset, message);
    }

    @Override
    public String toString() {
        return severity + " " + code + (dg > 0 ? " DG" + dg : "")
                + (offset >= 0 ? " @" + offset : "") + ": " + message;
    }
}
