package card42.emrtd;

import card42.common.TransientBuffers;

/* Package-shared transient (RAM) session buffers for the eMRTD applets.
 *
 * The LDS1/LDS2 response path used to build its plaintext and wrapped secure
 * messaging responses in per-instance persistent (EEPROM) arrays
 * ({@code EmrtdApplet.plain}/{@code response} 256 B and a static 512 B
 * {@code smOut}).  Every READ BINARY then wrote hundreds of bytes to EEPROM;
 * the pure-JVM baseline (docs/specs/common/risks.md §2) shows those two
 * buffers as the dominant writers of a passport session.  The buffers are
 * read/written within a single command, so they live in RAM
 * (CLEAR_ON_DESELECT) and are shared by every instance of the package.
 *
 * <p>{@link #io} doubles as the unwrapped-command buffer and the wrapped
 * response buffer.  The two uses never overlap in time: the command data is
 * fully consumed by {@code dispatch} before {@code wrap} runs (see
 * {@code EmrtdApplet.processCommand}).  {@link #response} is the plaintext
 * response that {@code wrap} reads while writing {@link #io}, so it must stay
 * a distinct array.
 *
 * <p>Both buffers are allocated once, in {@link #init()} during installation;
 * no command path allocates a transient array.  The total (576 B) is part of
 * the J3R180 budget documented in docs/specs/common/risks.md §2.
 *
 * @author card42
 */

final class EmrtdScratch {

    /**
     * Command/response I/O buffer: the unwrapped command data (up to the
     * 256-byte short-APDU bound) and, later in the same command, the wrapped
     * SM response (up to ~290 bytes for a 256-byte AA signature).  320 covers
     * both.
     */
    static byte[] io;

    /** Plaintext response built by a command handler (max 256 bytes). */
    static byte[] response;

    private static boolean initialized;

    private EmrtdScratch() {
    }

    /** Allocates the shared buffers once, at install; idempotent. */
    static void init() {
        if (initialized) {
            return;
        }
        io = TransientBuffers.makeByteArray((short) 320);
        response = TransientBuffers.makeByteArray((short) 256);
        initialized = true;
    }
}
