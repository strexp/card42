package card42.common;

/* A block-cipher message authentication code over the CV '5' / CV '6' profiles
 * (EMV v4.4 Book 2 §8.1.2, §9.2.3):
 *
 *   RetailMac  ISO/IEC 9797-1 Algorithm 3 with 3DES (CV '5')
 *   AesCmac    ISO/IEC 9797-1 Algorithm 5 / CMAC with AES (CV '6')
 *
 * The Application Cryptogram, the ARPC Method 2 and the secure-messaging MAC
 * all use one of these through this interface, so the profile only selects the
 * implementation once and the call sites stay algorithm-independent.
 *
 * The streaming start/update/doFinal form lets a message that is spread over
 * several buffers (the AC input, the Format 1 secure-messaging message) be
 * MACed without a large scratch array.  doFinal returns the full MAC (8 bytes
 * for RetailMac, 16 for AesCmac); the caller truncates it to s.
 *
 * @author card42
 */

public interface MacAlgorithm {

    /**
     * Starts a streaming MAC under key.  keyLen is 16 for 3DES and 16 for AES;
     * AES-256 is not available on the target platform
     * (docs/specs/common/cryptography.md §1).
     */
    void start(byte[] key, short keyOff, short keyLen);

    /** Feeds one segment of the message into the streaming MAC. */
    void update(byte[] msg, short msgOff, short msgLen);

    /** Finishes the MAC and writes the full block (8 or 16 bytes) to out. */
    short doFinal(byte[] out, short outOff);

    /** One-shot MAC with ISO/IEC 9797-1 padding method 2. */
    short mac(byte[] key, short keyOff, short keyLen,
              byte[] msg, short msgOff, short msgLen,
              byte[] out, short outOff);

    /**
     * One-shot MAC of an already block-aligned message (EMV Format 1 secure
     * messaging pre-pads the message, so the algorithm's own padding step is
     * omitted; EMV v4.4 Book 2 §9.2.3).
     */
    short macAligned(byte[] key, short keyOff, short keyLen,
                     byte[] msg, short msgOff, short msgLen,
                     byte[] out, short outOff);
}
