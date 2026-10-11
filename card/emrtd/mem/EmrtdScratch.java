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
 * <p>{@link #io} and {@link #response} (576 B) are allocated once, in
 * {@link #init()} during installation; no command path allocates them.
 * {@link #raw} (320 B, extended commands only) is allocated last, by
 * {@link #initExtended()}, so it takes the EEPROM fallback if the transient
 * budget runs short.  The total (896 B) is part of the J3R180 budget
 * documented in docs/specs/common/risks.md §2.
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

    /**
     * Raw incoming command assembled when the APDU is longer than the JCRE
     * buffer (an extended-length command such as Terminal Authentication's
     * {@code PSO:Verify Certificate}, whose SM envelope exceeds 255 bytes).
     * Distinct from {@link #io}, which holds the unwrapped plaintext.
     *
     * <p>Allocated by {@link #initExtended()} <em>after</em> {@link #io},
     * {@link #response} and {@code SmScratch}: if the J3R180's transient budget
     * does not stretch to this 320-byte buffer, this is the one that degrades to
     * a persistent (EEPROM) array.  Only the rare extended command touches it,
     * whereas {@code SmScratch} writes on every secure-messaging response, so
     * the wrong degradation would cost ~4x on the READ BINARY hot path
     * (630 ms vs 150 ms per 231-byte block).
     */
    static byte[] raw;

    private static boolean initialized;

    private EmrtdScratch() {
    }

    /**
     * Allocates the hot-path buffers ({@link #io}, {@link #response}) once, at
     * install; idempotent.  Call before {@code SmScratch.init()} so the buffers
     * used by every secure-messaging command get the transient budget first.
     */
    static void init() {
        if (initialized) {
            return;
        }
        io = TransientBuffers.makeByteArray((short) 320);
        response = TransientBuffers.makeByteArray((short) 256);
        initialized = true;
    }

    /**
     * Allocates {@link #raw}, once, after {@code SmScratch.init()}; idempotent.
     * It is the last transient request, so it is the one that falls back to
     * EEPROM when the context budget is exhausted.
     */
    static void initExtended() {
        if (raw == null) {
            raw = TransientBuffers.makeByteArray((short) 320);
        }
    }
}
