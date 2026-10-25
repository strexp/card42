package card42.host.common.util;

/**
 * ISO 7816 status-word formatting shared by the host modules.
 *
 * <p>Always renders four hexadecimal digits ({@code 9000}, {@code 6A82},
 * {@code 0900}), unlike {@link Integer#toHexString(int)}, which drops leading
 * zeros and made error messages ambiguous.  {@link #describe(int)} adds the
 * ISO 7816-4 meaning for the status words an eMRTD reader has to distinguish
 * (a missing file, an incorrect P1/P2, an unsupported instruction).
 */
public final class Sw {

    /** {@code 6A81}: the command or a command parameter is not supported. */
    public static final int FUNCTION_NOT_SUPPORTED = 0x6A81;
    /** {@code 6A82}: the referenced file or application was not found. */
    public static final int FILE_NOT_FOUND = 0x6A82;
    /** {@code 6A86}: P1/P2 are incorrect (e.g. an offset past the EF end). */
    public static final int INCORRECT_P1P2 = 0x6A86;
    /** {@code 6D00}: the instruction is not supported. */
    public static final int INSTRUCTION_NOT_SUPPORTED = 0x6D00;

    private Sw() {
    }

    /** The four-digit uppercase hex form of a status word. */
    public static String format(int sw) {
        return String.format("%04X", sw & 0xFFFF);
    }

    /**
     * The ISO 7816-4 meaning of a status word, or null when this class does not
     * name it.  An eMRTD reader uses the distinction between {@code 6A81}
     * (unsupported command form), {@code 6A82} (file absent) and {@code 6D00}
     * (unsupported instruction) for diagnostics; they must not collapse into
     * one generic "read failed".
     */
    public static String describe(int sw) {
        switch (sw & 0xFFFF) {
        case FUNCTION_NOT_SUPPORTED:
            return "function not supported";
        case FILE_NOT_FOUND:
            return "file or application not found";
        case INCORRECT_P1P2:
            return "incorrect P1/P2";
        case INSTRUCTION_NOT_SUPPORTED:
            return "instruction not supported";
        default:
            return null;
        }
    }

    /** {@code format(sw)} followed by the description when one is known. */
    public static String formatWithDescription(int sw) {
        String description = describe(sw);
        return description == null ? format(sw) : format(sw) + " (" + description + ")";
    }
}
