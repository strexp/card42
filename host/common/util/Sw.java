package card42.host.common.util;

/**
 * ISO 7816 status-word formatting shared by the host modules.
 *
 * <p>Always renders four hexadecimal digits ({@code 9000}, {@code 6A82},
 * {@code 0900}), unlike {@link Integer#toHexString(int)}, which drops leading
 * zeros and made error messages ambiguous.
 */
public final class Sw {

    private Sw() {
    }

    /** The four-digit uppercase hex form of a status word. */
    public static String format(int sw) {
        return String.format("%04X", sw & 0xFFFF);
    }
}
