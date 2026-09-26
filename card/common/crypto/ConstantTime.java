package card42.common;

/* Constant-time byte comparison (docs/specs/common/cryptography.md §9).
 *
 * Util.arrayCompare is not guaranteed to run without a data-dependent
 * short-circuit, so every secret comparison (block-tail MAC, ARPC, secure
 * messaging MAC) uses this XOR accumulation instead.  The loop always reads
 * every byte of the range.
 *
 * @author card42
 */

public final class ConstantTime {

    private ConstantTime() {
    }

    /** True when a[aOff..aOff+len) equals b[bOff..bOff+len). */
    public static boolean equals(byte[] a, short aOff, byte[] b, short bOff, short len) {
        byte diff = 0;
        for (short i = 0; i < len; i++) {
            diff |= (byte) (a[(short) (aOff + i)] ^ b[(short) (bOff + i)]);
        }
        return diff == 0;
    }
}
