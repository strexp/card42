package card42.host.emrtd.lds.common;

/**
 * How much of a data group could be turned into the field model
 * (ICAO Doc 9303-10 §4.7).
 *
 * <p>The raw EF is always kept by the parsers, so a caller can still show the
 * hexadecimal form when the status is {@link #PARTIAL} or {@link #INVALID}.
 * Data problems never abort the parse; they are reported as
 * {@link LdsIssue}s instead.
 */
public enum ParseStatus {

    /** The mandatory structure is complete. */
    OK,

    /**
     * The outer structure and the key fields are readable, but optional
     * fields are missing, an encoding had to be guessed or an unknown
     * vendor extension was skipped.
     */
    PARTIAL,

    /** The key structure is unreadable; only {@code raw()} is meaningful. */
    INVALID;

    /** True unless the key structure is unreadable. */
    public boolean isUsable() {
        return this != INVALID;
    }
}
