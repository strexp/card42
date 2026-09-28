package card42.common;

import javacard.framework.JCSystem;

/* RAM-first scratch allocation with an EEPROM fallback.
 *
 * A J3R180 has only a few kilobytes of {@code MEMORY_TRANSIENT_DESELECT} for
 * the whole card, and an exhausted budget makes {@code JCSystem.makeTransient*}
 * throw a {@code SystemException} (surfacing as 6F00 during applet
 * installation).  Every card scratch buffer therefore follows the same policy:
 * allocate in transient (RAM) space so it is {@code CLEAR_ON_DESELECT} and
 * costs no EEPROM programming cycles, and only when the platform has no
 * transient room left fall back to a persistent array so the applet still
 * installs and runs (docs/specs/common/risks.md §2 — "priority: transient must
 * not blow up, EEPROM writes second").
 *
 * <p>Callers must allocate during applet construction/installation, never from
 * a command path: a {@code CLEAR_ON_DESELECT} array can only be created for the
 * currently selected applet context, and re-allocating per command would defeat
 * the package-shared, once-only scratch design.  The current context is the
 * caller's (a shared-library method runs in the caller's applet context), so
 * ownership and CLEAR_ON_DESELECT semantics are the same as a direct call.
 *
 * @author card42
 */

public final class TransientBuffers {

    private TransientBuffers() {
    }

    /**
     * A {@code CLEAR_ON_DESELECT} byte array, or a persistent array when the
     * transient budget is exhausted.
     */
    public static byte[] makeByteArray(short length) {
        try {
            return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);
        } catch (RuntimeException e) {
            return new byte[length];
        }
    }

    /**
     * A {@code CLEAR_ON_DESELECT} short array, or a persistent array when the
     * transient budget is exhausted.
     */
    public static short[] makeShortArray(short length) {
        try {
            return JCSystem.makeTransientShortArray(length, JCSystem.CLEAR_ON_DESELECT);
        } catch (RuntimeException e) {
            return new short[length];
        }
    }
}
