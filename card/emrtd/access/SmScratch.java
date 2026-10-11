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
 * <p>The buffer is shared across every eMRTD applet instance of the package:
 * only the selected applet processes a command at a time, so a single buffer is
 * enough and the per-instance persistent footprint shrinks by 1 KB each.  This
 * also avoids the multi-instance transient exhaustion that per-instance lazy
 * allocations cause on a J3R180 (docs/specs/common/risks.md §2).
 *
 * <p>The buffer is allocated once, from {@code EmrtdApplet}'s constructor via
 * {@link #init()} during installation, so no command path performs a transient
 * allocation (docs/specs/common/risks.md §2).  {@link #get()} keeps the lazy
 * first-use allocation for any caller that does not go through the applet.
 * The personalization path never uses these wrappers.
 *
 * <p>The small per-command helpers below (MAC output, the two per-profile K_enc
 * dedup caches, the AES SSC form and IV) were persistent instance arrays in
 * {@link AbstractSecureMessaging}/{@link Iso7816SmAes}; they are pure scratch,
 * so they live here as shared transient arrays.  The 3DES and AES wrappers keep
 * separate {@code loadedEnc} caches because a session can switch profiles
 * (PACE AES then Chip Authentication 3DES) and sharing one cache would defeat
 * the "load the key once per session key" short-circuit.
 *
 * @author card42
 */

final class SmScratch {

    /**
     * The wrapping scratch is used in two phases that never overlap, so one
     * region serves both (docs/specs/common/risks.md §2):
     *
     *   - MAC input: SSC (16) + the largest DO'87'/DO'85' (the extended-command
     *     envelope, up to the 320-byte {@code EmrtdScratch.raw} including its
     *     4 header bytes) + DO'99' (4), M2-padded to a 16-byte boundary = 352;
     *   - encryption input: the plaintext response plus M2 padding (272 for a
     *     256-byte AA signature).
     *
     * The ciphertext is written straight to the caller's output buffer, so the
     * two phases share offset 0 and no second staging region is needed.  352
     * replaces the earlier 800-byte buffer (which held the encryption input at
     * offset 512 while also reserving ~320 for the MAC input) and returns about
     * 448 bytes to the exhausted eMRTD transient context (TODO.emrtd.md §A3).
     */
    private static final short SIZE = (short) 352;

    /** The framing scratch handed out by {@link #get()} (see {@link #SIZE}). */
    private static byte[] buffer;

    /** Reused MAC output: 8 bytes for the retail MAC, 16 for AES-CMAC. */
    private static byte[] macBuffer;

    /** Last K_enc loaded into the 3DES cipher, so setEncKey runs once per session. */
    private static byte[] loadedEnc3des;

    /** Last K_enc loaded into the AES cipher. */
    private static byte[] loadedEncAes;

    /** The 16-byte AES SSC form (8 zero bytes then the counter). */
    private static byte[] ssc16;

    /** The AES-CBC initialization vector AES-ECB(K_enc, SSC16). */
    private static byte[] iv;

    /** Le of the last unwrapped command, or -1 when absent. */
    private static short[] leState;

    private SmScratch() {
    }

    /**
     * Allocates the shared scratch once, at install (see {@code EmrtdApplet}),
     * so no secure-messaging command path performs a transient allocation.
     * Idempotent.
     */
    static void init() {
        get();
        if (macBuffer == null) {
            macBuffer = TransientBuffers.makeByteArray((short) 16);
            loadedEnc3des = TransientBuffers.makeByteArray((short) 16);
            loadedEncAes = TransientBuffers.makeByteArray((short) 16);
            ssc16 = TransientBuffers.makeByteArray((short) 16);
            iv = TransientBuffers.makeByteArray((short) 16);
            leState = TransientBuffers.makeShortArray((short) 1);
        }
    }

    /** The shared framing scratch array, allocated on first use. */
    static byte[] get() {
        byte[] b = buffer;
        if (b == null) {
            b = allocate();
            buffer = b;
        }
        return b;
    }

    static byte[] macBuffer() {
        init();
        return macBuffer;
    }

    static byte[] loadedEnc3des() {
        init();
        return loadedEnc3des;
    }

    static byte[] loadedEncAes() {
        init();
        return loadedEncAes;
    }

    static byte[] ssc16() {
        init();
        return ssc16;
    }

    static byte[] iv() {
        init();
        return iv;
    }

    /**
     * The shared Le cell of the last unwrapped command (RAM): the value is
     * written and read within one command, so it must not cost an EEPROM write
     * per secure-messaging command.
     */
    static short[] le() {
        init();
        return leState;
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
