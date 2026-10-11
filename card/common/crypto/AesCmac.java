package card42.common;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/* ISO/IEC 9797-1 Algorithm 5 (CMAC) with AES, used by the CV '6' profile for
 * the Application Cryptogram, the ARPC Method 2 and the secure-messaging MAC
 * (EMV v4.4 Book 2 §A1.2.2, §8.1.2, §9.2.3).
 *
 * The construction is
 *
 *   L  := AES(KS)[0^16]
 *   K1 := L  << 1, then xor '00..87' when msb(L)  was set
 *   K2 := K1 << 1, then xor '00..87' when msb(K1) was set
 *   XB := XB xor K1 (no padding) or xor K2 (0x80 padding added)
 *   H  := AES(KS)[X1] ; Hi := AES(KS)[Xi xor Hi-1] ; MAC := s leftmost bytes of HB
 *
 * The one-shot {@link #mac}/{@link #macAligned} forms – which are the only
 * forms the card uses – run the CBC chaining through the platform
 * {@code ALG_AES_BLOCK_128_CBC_NOPAD} engine: the bulk of the message is
 * encrypted in chunks of {@link #STAGING} bytes and only the last ciphertext
 * block (the CMAC chaining value) is retained, then the final masked block is
 * one ECB call.  A 352-byte eMRTD secure-messaging MAC input therefore costs a
 * few platform calls instead of one ECB call per 16-byte block, which is what
 * made the AES profile ~10x slower than 3DES on a J3R180 (the platform has no
 * AES-CMAC {@code Signature}, so CMAC is hand-built; docs/specs/common/
 * cryptography.md §4.1).  The output staging is allocated once at
 * construction, never on a command path.
 *
 * The streaming {@link #start}/{@link #update}/{@link #doFinal} form buffers
 * the last block so doFinal can apply the K1/K2 mask; it keeps the per-block
 * ECB construction because it must work without the output staging.  The MAC
 * therefore covers a message fed in several segments (the AC input) and an
 * already aligned message (Format 1 secure messaging, which adds no padding);
 * doFinal returns the full 16-byte block and the caller truncates it to s.
 *
 * The jcsl AES doFinal does not tolerate aliased input and output buffers
 * (docs/specs/common/cryptography.md §4.1), so the chaining value and the XOR
 * result are kept in separate blocks.
 *
 * @author card42
 */

public final class AesCmac implements MacAlgorithm {

    private static final short BLOCK = (short) 16;
    /** C = 0^16 with the least significant bits set to 10000111b (EMV v4.4 Book 2 §A1.2.2). */
    private static final byte CMAC_C_LOW = (byte) 0x87;

    /**
     * CBC output staging for the one-shot path: the bulk of the message is
     * CBC-encrypted in chunks of this size and only the last ciphertext block of
     * each chunk is kept, so this bounds the peak scratch instead of one buffer
     * per message byte.  256 bytes (16 blocks) turns the largest card MAC input
     * (a 352-byte eMRTD secure-messaging message) into two platform CBC calls
     * plus one ECB call.
     */
    private static final short STAGING = (short) 256;

    private final Cipher ecb128;
    private final Cipher cbc128;
    private final AESKey key128;

    private final byte[] zero = new byte[BLOCK];
    private final byte[] l = new byte[BLOCK];
    private final byte[] k1 = new byte[BLOCK];
    private final byte[] k2 = new byte[BLOCK];

    /** Last loaded 16-byte key, so setKey and the subkey derivation run once. */
    private final byte[] loadedKey = new byte[BLOCK];
    private boolean keyLoaded;

    /** Current CMAC chaining value: the CBC IV of the one-shot path, or the
     *  streaming XOR value; zero at the start of a MAC. */
    private final byte[] state;

    /** Streaming tail block and the final masked block. */
    private final byte[] pending;
    private short pendingLength;

    /** CBC ciphertext staging for the one-shot path (transient, install-time). */
    private final byte[] cbcOut;

    public AesCmac() {
        ecb128 = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        cbc128 = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        key128 = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
                KeyBuilder.LENGTH_AES_128, false);
        // Allocated at construction so no command path performs a transient
        // allocation; a card without transient budget falls back to EEPROM
        // instead of failing the install (docs/specs/common/risks.md §2).
        state = TransientBuffers.makeByteArray(BLOCK);
        pending = TransientBuffers.makeByteArray(BLOCK);
        cbcOut = TransientBuffers.makeByteArray(STAGING);
    }

    public void start(byte[] key, short keyOff, short keyLen) {
        if (keyLen != 16) {
            // Only AES-128 is available on the simulator (docs/specs/common/cryptography.md §1).
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (!keyLoaded || !sameKey(key, keyOff)) {
            key128.setKey(key, keyOff);
            Util.arrayCopyNonAtomic(key, keyOff, loadedKey, (short) 0, BLOCK);
            keyLoaded = true;
            // The subkeys L/K1/K2 depend only on the key, so they are derived
            // once per session instead of on every MAC.
            ecb128.init(key128, Cipher.MODE_ENCRYPT);
            ecb128.doFinal(zero, (short) 0, BLOCK, l, (short) 0);
            shiftLeft(l, k1);
            shiftLeft(k1, k2);
        }
        Util.arrayFillNonAtomic(state, (short) 0, BLOCK, (byte) 0);
        pendingLength = 0;
    }

    /** True when the 16 bytes at key/keyOff equal the last loaded session key. */
    private boolean sameKey(byte[] key, short keyOff) {
        return ConstantTime.equals(loadedKey, (short) 0, key, keyOff, BLOCK);
    }

    /**
     * One-shot CMAC with ISO/IEC 9797-1 padding method 2.  The message is
     * CBC-chained through the platform CBC engine (see the class note) and the
     * final masked block is one ECB call.
     */
    public short mac(byte[] key, short keyOff, short keyLen,
                     byte[] msg, short msgOff, short msgLen,
                     byte[] out, short outOff) {
        start(key, keyOff, keyLen);
        return finish(msg, msgOff, msgLen, out, outOff);
    }

    /**
     * One-shot CMAC of an already block-aligned message.  CMAC adds no padding
     * to a block-aligned message, so this is the same computation as
     * {@link #mac}.
     */
    public short macAligned(byte[] key, short keyOff, short keyLen,
                            byte[] msg, short msgOff, short msgLen,
                            byte[] out, short outOff) {
        if ((msgLen & (short) 0x000F) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        return mac(key, keyOff, keyLen, msg, msgOff, msgLen, out, outOff);
    }

    /**
     * CBC-chains the whole message and applies the final-block mask.  The last
     * complete block is masked with K1 (aligned message) or the padded tail with
     * K2 (M2 padding), matching EMV v4.4 Book 2 §A1.2.2 / NIST SP 800-38B.
     */
    private short finish(byte[] msg, short msgOff, short msgLen,
                         byte[] out, short outOff) {
        short full = (short) (msgLen / BLOCK);
        short rem = (short) (msgLen % BLOCK);
        if (rem == 0 && msgLen > 0) {
            // The last complete block is the final block (mask K1, no padding).
            short blocks = (short) (full - 1);
            cbcChain(msg, msgOff, (short) (blocks * BLOCK));
            short last = (short) (msgOff + blocks * BLOCK);
            for (short i = 0; i < BLOCK; i++) {
                pending[i] = (byte) (msg[(short) (last + i)] ^ k1[i] ^ state[i]);
            }
        } else {
            // CBC the complete blocks, then mask the 0x80-padded tail with K2.
            cbcChain(msg, msgOff, (short) (full * BLOCK));
            short tail = (short) (msgOff + full * BLOCK);
            for (short i = 0; i < rem; i++) {
                pending[i] = msg[(short) (tail + i)];
            }
            pending[rem] = (byte) 0x80;
            for (short i = (short) (rem + 1); i < BLOCK; i++) {
                pending[i] = (byte) 0x00;
            }
            for (short i = 0; i < BLOCK; i++) {
                pending[i] ^= (byte) (k2[i] ^ state[i]);
            }
        }
        ecb128.init(key128, Cipher.MODE_ENCRYPT);
        ecb128.doFinal(pending, (short) 0, BLOCK, out, outOff);
        return BLOCK;
    }

    /**
     * CBC-encrypts msg[off..off+len) (a multiple of 16), updating the chaining
     * value {@link #state}.  The ciphertext is written to the staging buffer and
     * discarded except for the last block; longer messages are processed in
     * {@link #STAGING}-byte chunks, each re-keyed with the running chaining
     * value as IV.
     */
    private void cbcChain(byte[] msg, short off, short len) {
        short done = 0;
        while (done < len) {
            short chunk = (short) (len - done);
            if (chunk > STAGING) {
                chunk = STAGING;
            }
            cbc128.init(key128, Cipher.MODE_ENCRYPT, state, (short) 0, BLOCK);
            short produced = cbc128.doFinal(msg, (short) (off + done), chunk,
                    cbcOut, (short) 0);
            Util.arrayCopyNonAtomic(cbcOut, (short) (produced - BLOCK), state,
                    (short) 0, BLOCK);
            done = (short) (done + chunk);
        }
    }

    public void update(byte[] msg, short msgOff, short msgLen) {
        short p = msgOff;
        short end = (short) (msgOff + msgLen);
        while (p < end) {
            if (pendingLength == BLOCK) {
                flush();
            }
            pending[pendingLength] = msg[p];
            pendingLength++;
            p++;
        }
    }

    /** CBC-encrypts one full buffered block into the chaining value. */
    private void flush() {
        for (short i = 0; i < BLOCK; i++) {
            pending[i] ^= state[i];
        }
        ecb128.doFinal(pending, (short) 0, BLOCK, state, (short) 0);
        pendingLength = 0;
    }

    public short doFinal(byte[] out, short outOff) {
        if (pendingLength == BLOCK) {
            // No padding was added: mask the last block with K1.
            for (short i = 0; i < BLOCK; i++) {
                pending[i] ^= (byte) (k1[i] ^ state[i]);
            }
        } else {
            // Pad with 0x80 then 00 to the block boundary and mask with K2.
            pending[pendingLength] = (byte) 0x80;
            for (short i = (short) (pendingLength + 1); i < BLOCK; i++) {
                pending[i] = (byte) 0x00;
            }
            for (short i = 0; i < BLOCK; i++) {
                pending[i] ^= (byte) (k2[i] ^ state[i]);
            }
        }
        ecb128.doFinal(pending, (short) 0, BLOCK, out, outOff);
        pendingLength = 0;
        return BLOCK;
    }

    /**
     * Zeroizes the session-derived material: the CMAC subkeys L/K1/K2 and the
     * AES session key.  EMV v4.4 Book 2 §A1.2.2 requires all intermediate
     * values of the MAC to be kept secret; without this they would stay in
     * persistent memory between transactions.  The next {@link #start} reloads
     * a session key, so clearing is safe at a session boundary.
     */
    public void zeroize() {
        if (!keyLoaded) {
            // Nothing but zeros was ever derived, so the fills below would only
            // rewrite the same values and cost EEPROM write cycles.  Guards the
            // package-shared engine: a SELECT after a session that used another
            // profile must not re-zero an already-clean engine.
            return;
        }
        Util.arrayFillNonAtomic(l, (short) 0, BLOCK, (byte) 0);
        Util.arrayFillNonAtomic(k1, (short) 0, BLOCK, (byte) 0);
        Util.arrayFillNonAtomic(k2, (short) 0, BLOCK, (byte) 0);
        Util.arrayFillNonAtomic(loadedKey, (short) 0, BLOCK, (byte) 0);
        if (key128.isInitialized()) {
            key128.clearKey();
        }
        keyLoaded = false;
        pendingLength = 0;
    }

    /** True while a session key is loaded (observability for tests). */
    public boolean isInitialized() {
        return key128.isInitialized();
    }

    /** k := in << 1, then xor C when the most significant bit of in was set. */
    private static void shiftLeft(byte[] in, byte[] k) {
        byte carry = 0;
        for (short i = (short) (BLOCK - 1); i >= 0; i--) {
            byte b = in[i];
            k[i] = (byte) ((b << 1) | carry);
            carry = (byte) ((b >> 7) & 0x01);
        }
        if ((in[0] & 0x80) != 0) {
            k[(short) (BLOCK - 1)] ^= CMAC_C_LOW;
        }
    }
}
