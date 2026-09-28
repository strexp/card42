package card42.emv;

import card42.common.TransientBuffers;

/* Package-shared transient (RAM) scratch for the EMV applets.
 *
 * Every EMV applet instance of this package shares one set of session
 * buffers.  The J3R180 has only a few kilobytes of
 * {@code MEMORY_TRANSIENT_DESELECT} for the whole context; the previous design
 * gave every instance its own response / work / chain buffers and allocated
 * the lazy ones on first use during a command.  With the test instances
 * (04/06/08) deployed next to the production ones the shared budget ran out
 * and any further {@code JCSystem.makeTransientByteArray} failed with a
 * {@code SystemException} (surfacing as 6F00); see TODO.emv.md §B3.
 *
 * All buffers are allocated once, in {@link #init()} during installation
 * (the applet constructor runs with the package context current, where the
 * platform allows a CLEAR_ON_DESELECT allocation), and never during command
 * processing.  Only one applet instance is selected at a time, so a single
 * buffer per logical use is enough and the transient footprint is independent
 * of the number of instances.
 *
 * The buffers are CLEAR_ON_DESELECT: the platform wipes them when the package
 * context is deselected, so no session data survives a session.  The
 * persistent vs. transient split and the J3R180 budget are documented in
 * docs/specs/common/risks.md §2.
 *
 * @author card42
 */

final class EmvScratch {

    /** Outgoing response buffer (records and AC responses; 256 covers a RSA-2048 SDAD). */
    static byte[] response;

    /**
     * Shared work scratch for the mutually exclusive large users: the
     * enciphered-PIN recovery block, the DDA/CDA ISO 9796-2 message and the
     * ARPC / secure-messaging MAC input.  288 covers a 2048-bit DDA/CDA message
     * (prefix up to 234 bytes plus the terminal DDOL, in practice <= 32) and the
     * 256-byte PIN recovery block; a longer DDOL is refused rather than
     * truncated.
     */
    static byte[] work;

    /** Command-chaining accumulation buffer (short-APDU maximum). */
    static byte[] chain;

    /** PDOL-related data of the current GPO. */
    static byte[] pdol;

    /** First-AC CDOL1 copy, kept for the CDA signature and the CSU update. */
    static byte[] firstCdol;

    /** CDA header (9F27/9F36/IAD) and the 4-byte Unpredictable Number. */
    static byte[] cdaHeader;
    static byte[] cdaUn;

    /** Secure-messaging session keys, ICV and derived-AC marker. */
    static byte[] smMacKey;
    static byte[] smEncKey;
    static byte[] smIcv;
    static byte[] smDerivedAc;

    /** AC session key bytes, the 2-byte AIP/ATC scratch and the last AC. */
    static byte[] sessionKey;
    static byte[] acScratch;
    static byte[] lastAc;

    /** Session-key derivation scratch. */
    static byte[] skData;

    /** Card Verification Results scratch. */
    static byte[] cvr;

    /** Recoverable-message length returned by the DDA signer. */
    static short[] m1Length;

    /** Volatile protocol state, ARQC stash and GET CHALLENGE value. */
    static byte[] volatileState;
    static byte[] arqc;
    static byte[] challenge;

    private static boolean initialized;

    private EmvScratch() {
    }

    /**
     * Allocates the shared buffers once.  Idempotent, so every constructor
     * that may run first (and the pure-JVM unit tests) can call it safely.
     * Never called from a command path.
     */
    static void init() {
        if (initialized) {
            return;
        }
        response = TransientBuffers.makeByteArray((short) 256);
        work = TransientBuffers.makeByteArray((short) 288);
        chain = TransientBuffers.makeByteArray((short) 255);
        pdol = TransientBuffers.makeByteArray((short) 64);
        firstCdol = TransientBuffers.makeByteArray((short) 128);
        cdaHeader = TransientBuffers.makeByteArray((short) 48);
        cdaUn = TransientBuffers.makeByteArray((short) 4);
        smMacKey = TransientBuffers.makeByteArray((short) 16);
        smEncKey = TransientBuffers.makeByteArray((short) 16);
        smIcv = TransientBuffers.makeByteArray((short) 16);
        smDerivedAc = TransientBuffers.makeByteArray((short) 8);
        sessionKey = TransientBuffers.makeByteArray((short) 16);
        acScratch = TransientBuffers.makeByteArray((short) 4);
        lastAc = TransientBuffers.makeByteArray((short) 16);
        skData = TransientBuffers.makeByteArray((short) 16);
        cvr = TransientBuffers.makeByteArray(Iad.CVR_LENGTH);
        m1Length = TransientBuffers.makeShortArray((short) 1);
        volatileState = TransientBuffers.makeByteArray((short) 10);
        arqc = TransientBuffers.makeByteArray((short) 8);
        challenge = TransientBuffers.makeByteArray((short) 8);
        initialized = true;
    }
}
