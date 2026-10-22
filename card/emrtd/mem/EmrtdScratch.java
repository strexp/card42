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
 * {@link #initSession()} adds the BAC/PACE/Chip-Authentication session keys and
 * the BAC command scratch as package-shared transient arrays: they were
 * per-instance persistent arrays, so every session re-derived and zeroized
 * them into EEPROM.
 *
 * <p>{@link #raw} (320 B, extended commands only) is deliberately a
 * <em>persistent</em> (EEPROM) array.  The J3R180 eMRTD transient context
 * (measured ~2056 B) is nearly exhausted by io/response plus {@code SmScratch}
 * and the per-instance MAC scratch; trading this rarely-used extended-command
 * buffer for the hot session scratch above was the only way to fit the latter
 * without an EEPROM fallback (docs/specs/common/risks.md §2).  Only an
 * extended-length secure-messaging command touches it.
 *
 * <p>{@link #record}/{@link #recordEnvelope} (1 KB each) are the exception on
 * the response side: they are only allocated by an LDS2 role and stay
 * persistent, because an extended-Le READ RECORD can return a 900-byte
 * EF.Certificates record which cannot fit the 256/512-byte short-APDU buffers,
 * and adding 2 KB to the eMRTD transient context would push the hot-path
 * scratch into EEPROM (see the field notes and docs/specs/emrtd/emrtd.md §2/§11).
 *
 * @author card42
 */

final class EmrtdScratch {

    /**
     * Command/response I/O buffer: the unwrapped command data (up to the
     * short-APDU 256-byte bound, or a larger extended Terminal-Authentication
     * {@code PSO:Verify Certificate} with an RSA chain) and, later in the same
     * command, the wrapped SM response (up to ~290 bytes for a 256-byte AA
     * signature).  512 covers an RSA-1024 PSO body+signature (~417 bytes) and
     * the wrapped response.
     */
    static byte[] io;

    /** Plaintext response built by a command handler (max 256 bytes). */
    static byte[] response;

    /**
     * Raw incoming command assembled when the APDU is longer than the JCRE
     * buffer (an extended-length command whose secure-messaging envelope
     * exceeds 255 bytes).  Distinct from {@link #io}, which holds the unwrapped
     * plaintext.
     *
     * <p>Persistent on purpose: it is the rare extended-command buffer, and its
     * bytes are spent on the hot shared session scratch instead
     * (docs/specs/common/risks.md §2).  512 bytes cover a Terminal
     * Authentication {@code PSO:Verify Certificate} with an RSA-1024 chain
     * (the certificate body plus a 128-byte RSA signature, SM-wrapped exceeds
     * 320 bytes).
     */
    static byte[] raw;

    /**
     * Large LDS2 record response (plaintext) and its SM envelope.  An LDS2
     * record can be up to 900 bytes (EF.Certificates, Doc 9303-10 Table 83),
     * which does not fit the 256-byte {@link #response} or the 512-byte
     * {@link #io} envelope.  These two buffers are allocated only for the LDS2
     * roles (an LDS1-only card pays nothing) and are persistent on purpose:
     * extending the transient hot-path buffers by 2 KB would exceed the eMRTD
     * context budget and force the real hot-path scratch into EEPROM
     * (docs/specs/common/risks.md §2).  A large READ RECORD is rare, so its
     * EEPROM writes are preferable to slowing every READ BINARY.
     *
     * <p>{@link #record} doubles as the SM framing scratch: it holds the
     * plaintext, is M2-padded in place, is encrypted into {@link #recordEnvelope},
     * and is then reused for the MAC input (SSC || DO87 || DO99).  1024 bytes
     * cover a 900-byte record with M2 padding (912), its 3DES/AES SM envelope
     * (~930) and the padded MAC input (~944).
     */
    static byte[] record;

    /** SM envelope of a large record response (1024 bytes, see {@link #record}). */
    static byte[] recordEnvelope;

    /*
     * BAC/PACE/Chip-Authentication session state, package-shared transient.
     * These were per-instance persistent arrays: a session derived
     * K_enc/K_mac/Ks_enc/Ks_mac, the SSC and the challenge, and zeroized them
     * again on the next SELECT/DESELECT, writing the same bytes to EEPROM each
     * time.  Only one applet instance processes a command at a time, so one
     * shared set is enough (docs/specs/common/risks.md §2).
     */
    static byte[] challenge;      // GET CHALLENGE RND.ICC (8)
    static byte[] kenc;           // BAC K_enc (16)
    static byte[] kmac;           // BAC K_mac (16)
    static byte[] ksEnc;          // session Ks_enc (16)
    static byte[] ksMac;          // session Ks_mac (16)
    static byte[] ssc;            // send sequence counter (8)
    static byte[] caEnc;          // staged Chip Authentication Ks_enc (16)
    static byte[] caMac;          // staged Chip Authentication Ks_mac (16)

    /*
     * BAC EXTERNAL AUTHENTICATE scratch (E_IFD, K_IC, S2, session seed).  Was a
     * set of static persistent arrays in ExternalAuthenticate; it is per-command
     * working state, so it is shared transient scratch here.
     */
    static byte[] bacEIfd;        // E_IFD (32)
    static byte[] bacKic;         // K_IC (16)
    static byte[] bacS2;          // S2 = RND.ICC || RND.IFD || K_IC (32)
    static byte[] bacSessionSeed; // K_IFD XOR K_IC (16)

    private static boolean initialized;
    private static boolean sessionInitialized;

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
        io = TransientBuffers.makeByteArray((short) 512);
        response = TransientBuffers.makeByteArray((short) 256);
        initialized = true;
    }

    /**
     * Allocates the BAC/PACE/Chip-Authentication session state once, at install;
     * idempotent.  Called after {@code SmScratch.init()} so the 352-byte SM
     * framing scratch (written by every secure-messaging response) keeps the
     * transient budget ahead of these smaller session buffers.
     */
    static void initSession() {
        if (sessionInitialized) {
            return;
        }
        challenge = TransientBuffers.makeByteArray((short) 8);
        kenc = TransientBuffers.makeByteArray((short) 16);
        kmac = TransientBuffers.makeByteArray((short) 16);
        ksEnc = TransientBuffers.makeByteArray((short) 16);
        ksMac = TransientBuffers.makeByteArray((short) 16);
        ssc = TransientBuffers.makeByteArray((short) 8);
        caEnc = TransientBuffers.makeByteArray((short) 16);
        caMac = TransientBuffers.makeByteArray((short) 16);
        bacEIfd = TransientBuffers.makeByteArray((short) 32);
        bacKic = TransientBuffers.makeByteArray((short) 16);
        bacS2 = TransientBuffers.makeByteArray((short) 32);
        bacSessionSeed = TransientBuffers.makeByteArray((short) 16);
        sessionInitialized = true;
    }

    /**
     * Allocates {@link #raw} once, at install; idempotent.  It is a persistent
     * (EEPROM) array on purpose (see the class note).
     */
    static void initExtended() {
        if (raw == null) {
            raw = new byte[(short) 512];
        }
    }

    /**
     * Allocates the large LDS2 record response buffers once, only for an LDS2
     * role; idempotent.  They are persistent (see {@link #record}); an LDS1
     * instance never touches them, so it does not pay the 2 KB.
     */
    static void initRecord() {
        if (record == null) {
            record = new byte[(short) 1024];
            recordEnvelope = new byte[(short) 1024];
        }
    }
}
