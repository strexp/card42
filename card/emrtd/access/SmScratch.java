package card42.emrtd;

import card42.common.TransientBuffers;

/* Package-shared scratch for the eMRTD secure-messaging wrappers
 * ({@link AbstractSecureMessaging}, {@link Iso7816Sm}, {@link Iso7816SmAes}).
 *
 * The wrappers build the MAC input ([SSC] DO87 DO97 / [SSC] DO87 DO99) and the
 * M2-padded ciphertext of the response in one scratch area.  Those writes used
 * to land in a per-instance persistent (EEPROM) array, so every READ BINARY
 * wrote several hundred bytes to EEPROM.  This class hands out one byte[] that
 * is allocated in the transient (RAM) space when the platform has room, with a
 * persistent fallback otherwise, so the wrappers never fail for lack of RAM.
 *
 * The buffer is shared across every eMRTD applet instance of the package: only
 * the selected applet processes a command at a time, so a single buffer is
 * enough and the per-instance persistent footprint shrinks by 1 KB each.  This
 * also avoids the multi-instance transient exhaustion that per-instance lazy
 * allocations cause on a J3R180 (docs/specs/common/risks.md §2).
 *
 * The buffer is allocated once, from {@code EmrtdApplet}'s constructor via
 * {@link #init()} during installation, so no command path performs a transient
 * allocation (docs/specs/common/risks.md §2).  {@link #get()} keeps the lazy
 * first-use allocation for any caller that does not go through the applet.
 * The personalization path never uses these wrappers.
 *
 * @author card42
 */

final class SmScratch {

    /**
     * Largest area used by a wrapper: the encryption input starts at offset 512
     * and holds the response plus M2 padding (512 + 272 = 784 for a 256-byte
     * response), and the MAC input starts at 0 and holds SSC + the wrapped
     * response + status object (< 320).  800 covers both.
     */
    private static final short SIZE = (short) 800;

    private static byte[] buffer;

    private SmScratch() {
    }

    /**
     * Allocates the shared scratch once, at install (see
     * {@code EmrtdApplet}), so no secure-messaging command path performs a
     * transient allocation.  Idempotent.
     */
    static void init() {
        get();
    }

    /** The shared scratch array, allocated on first use. */
    static byte[] get() {
        byte[] b = buffer;
        if (b == null) {
            b = allocate();
            buffer = b;
        }
        return b;
    }

    /**
     * Prefers a transient (CLEAR_ON_DESELECT) array and degrades to a persistent
     * one when the context has no transient budget left, so an out-of-RAM card
     * still runs the command instead of returning 6F00.
     */
    private static byte[] allocate() {
        return TransientBuffers.makeByteArray(SIZE);
    }
}
