package card42.common;

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
 * The streaming form buffers the last block so doFinal can apply the K1/K2
 * mask; the MAC therefore covers a message fed in several segments (the AC
 * input) and an already aligned message (Format 1 secure messaging, which adds
 * no padding).  doFinal returns the full 16-byte block; the caller truncates it
 * to s.
 *
 * The jcsl AES doFinal does not tolerate aliased input and output buffers
 * (docs/specs/common/cryptography.md §4.1), so the chaining value and the XOR result
 * are kept in separate blocks.
 *
 * @author card42
 */

public final class AesCmac implements MacAlgorithm {

    private static final short BLOCK = (short) 16;
    /** C = 0^16 with the least significant bits set to 10000111b (EMV v4.4 Book 2 §A1.2.2). */
    private static final byte CMAC_C_LOW = (byte) 0x87;

    private final Cipher ecb128;
    private final AESKey key128;

    private final byte[] zero = new byte[BLOCK];
    private final byte[] l = new byte[BLOCK];
    private final byte[] k1 = new byte[BLOCK];
    private final byte[] k2 = new byte[BLOCK];

    /** Last loaded 16-byte key, so setKey and the subkey derivation run once. */
    private final byte[] loadedKey = new byte[BLOCK];
    private boolean keyLoaded;

    /** Transient working blocks, allocated once with the object (install time). */
    private final byte[] state;
    private final byte[] pending;
    private short pendingLength;

    public AesCmac() {
        ecb128 = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        key128 = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
                KeyBuilder.LENGTH_AES_128, false);
        // Allocated at construction so no command path performs a transient
        // allocation; a card without transient budget falls back to EEPROM
        // instead of failing the install (docs/specs/common/risks.md §2).
        state = TransientBuffers.makeByteArray(BLOCK);
        pending = TransientBuffers.makeByteArray(BLOCK);
    }

    public void start(byte[] key, short keyOff, short keyLen) {
        if (keyLen != 16) {
            // Only AES-128 is available on the simulator (docs/specs/common/cryptography.md §1).
            ISOException.throwIt((short) 0x6700);
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
        for (short i = 0; i < BLOCK; i++) {
            if (loadedKey[i] != key[(short) (keyOff + i)]) {
                return false;
            }
        }
        return true;
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

    public short mac(byte[] key, short keyOff, short keyLen,
                     byte[] msg, short msgOff, short msgLen,
                     byte[] out, short outOff) {
        start(key, keyOff, keyLen);
        update(msg, msgOff, msgLen);
        return doFinal(out, outOff);
    }

    public short macAligned(byte[] key, short keyOff, short keyLen,
                            byte[] msg, short msgOff, short msgLen,
                            byte[] out, short outOff) {
        if ((msgLen & (short) 0x000F) != 0) {
            ISOException.throwIt((short) 0x6700);
        }
        // CMAC adds no padding to an aligned message, so the one-shot MAC is
        // already the aligned form.
        return mac(key, keyOff, keyLen, msg, msgOff, msgLen, out, outOff);
    }

    /**
     * Zeroizes the session-derived material: the CMAC subkeys L/K1/K2 and the
     * AES session key.  EMV v4.4 Book 2 §A1.2.2 requires all intermediate
     * values of the MAC to be kept secret; without this they would stay in
     * persistent memory between transactions.  The next {@link #start} reloads
     * a session key, so clearing is safe at a session boundary.
     */
    public void zeroize() {
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
