package card42.common;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/* ISO/IEC 9797-1 MAC algorithm 3 with padding method 2 (the ANSI X9.19 retail
 * MAC), used by the ARPC Method 2 verification and the secure-messaging MAC
 * (EMV v4.4 Book 2 §8.2, §9.2).
 *
 * The algorithm is
 *
 *     H_k   := single-DES-CBC-MAC(K1, M2-pad(MSG))
 *     MAC   := DES_enc(K1, DES_dec(K2, H_k))
 *
 * where K1/K2 are the left/right halves of the 16-byte session key.
 *
 * The CBC part is computed with the platform MAC engine when available:
 * {@code Signature.ALG_DES_MAC8_ISO9797_M2} for the padded one-shot/streaming
 * form and {@code ALG_DES_MAC8_NOPAD} for the already block-aligned form.  This
 * lets a real card finish the whole CBC-MAC in one call instead of a Java
 * bytecode loop that drives the cipher block by block; on a J3R180 that loop
 * dominated every secure-messaging APDU.  When the platform does not implement
 * those algorithms (the Java Card Development Kit Simulator rejects the MAC
 * signatures), the original manual construction is used instead, so the same
 * source runs on the simulator and on a real card.
 *
 * The final DES_dec(K2)/DES_enc(K1) transformation is always two single-DES ECB
 * operations (it is not the EDE/EDE construction of the full 3DES key).
 *
 * @author card42
 */

public class RetailMac implements MacAlgorithm {

    private final DESKey cbcKey;
    private final DESKey finalKey;
    private final Cipher des;
    private final byte[] block;

    /** Platform CBC-MAC over an M2-padded message, or null when unavailable. */
    private Signature cbcM2;
    /** Platform raw CBC-MAC over a block-aligned message, or null. */
    private Signature cbcNoPad;
    /** True once the platform MAC algorithms were probed. */
    private boolean nativeTried;

    /** Last loaded 16-byte key, so setKey runs once per session. */
    private final byte[] loadedKey = new byte[16];
    private boolean keyLoaded;

    /** Bytes currently buffered by the streaming CBC part (0..7). */
    private short pending;

    public RetailMac() {
        cbcKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
                KeyBuilder.LENGTH_DES, false);
        finalKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
                KeyBuilder.LENGTH_DES, false);
        des = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
        block = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        pending = 0;
    }

    /**
     * Probes the platform MAC engine once, on first use so instances that never
     * MAC do not pay for the extra objects.  A platform without the ISO 9797-1
     * MAC signatures (the simulator) leaves both null and forces the manual
     * path (docs/specs/common/cryptography.md §4).
     */
    private void ensureNative() {
        if (nativeTried) {
            return;
        }
        nativeTried = true;
        try {
            cbcM2 = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2, false);
        } catch (CryptoException e) {
            cbcM2 = null;
        }
        try {
            cbcNoPad = Signature.getInstance(Signature.ALG_DES_MAC8_NOPAD, false);
        } catch (CryptoException e) {
            cbcNoPad = null;
        }
    }

    /** Loads K1/K2 once per session key (the key is stable within a session). */
    private void setKeyOnce(byte[] key, short keyOff) {
        if (keyLoaded) {
            boolean same = true;
            for (short i = 0; i < (short) 16; i++) {
                if (loadedKey[i] != key[(short) (keyOff + i)]) {
                    same = false;
                    break;
                }
            }
            if (same) {
                return;
            }
        }
        cbcKey.setKey(key, keyOff);
        finalKey.setKey(key, (short) (keyOff + 8));
        Util.arrayCopyNonAtomic(key, keyOff, loadedKey, (short) 0, (short) 16);
        keyLoaded = true;
    }

    /**
     * Computes the full 8-byte algorithm 3 MAC of msg under the 16-byte key
     * (K1 || K2), writing it to out/outOff.  The message is padded with ISO/IEC
     * 9797-1 padding method 2 (80 then 00) before the CBC part.
     */
    public short mac(byte[] key, short keyOff, short keyLen, byte[] msg, short msgOff,
                     short msgLen, byte[] out, short outOff) {
        start(key, keyOff, keyLen);
        update(msg, msgOff, msgLen);
        return doFinal(out, outOff);
    }

    /**
     * Starts a streaming algorithm 3 MAC under the 16-byte key (K1 || K2).
     * The message is fed with update() in as many segments as needed and the
     * MAC is produced by doFinal(), which applies ISO/IEC 9797-1 padding
     * method 2.  This lets the Application Cryptogram MAC cover a message that
     * is spread over several buffers without a large scratch array
     * (EMV v4.4 Book 2 §8.1.2).
     */
    public void start(byte[] key, short keyOff, short keyLen) {
        if (keyLen != 16) {
            ISOException.throwIt((short) 0x6700);
        }
        ensureNative();
        setKeyOnce(key, keyOff);
        pending = 0;
        if (cbcM2 != null) {
            cbcM2.init(cbcKey, Signature.MODE_SIGN);
            return;
        }
        Util.arrayFillNonAtomic(block, (short) 0, (short) 8, (byte) 0);
        des.init(cbcKey, Cipher.MODE_ENCRYPT);
    }

    /** Feeds one segment of the message into the streaming CBC part. */
    public void update(byte[] msg, short msgOff, short msgLen) {
        if (cbcM2 != null) {
            cbcM2.update(msg, msgOff, msgLen);
            return;
        }
        short p = msgOff;
        short end = (short) (msgOff + msgLen);
        while (p < end) {
            block[pending] ^= msg[p];
            pending++;
            p++;
            if (pending == 8) {
                des.doFinal(block, (short) 0, (short) 8, block, (short) 0);
                pending = 0;
            }
        }
    }

    /**
     * Finishes a streaming MAC: pads the last block with method 2 (a mandatory
     * 0x80 then 0x00 to the block boundary, adding a full block when the
     * message was already aligned), applies the final DES_dec(K2)/DES_enc(K1)
     * transformation and writes the 8-byte MAC to out/outOff.
     */
    public short doFinal(byte[] out, short outOff) {
        if (cbcM2 != null) {
            // The native M2 signature applies method-2 padding itself; an empty
            // trailing segment finalizes the data fed by update().
            cbcM2.sign(out, outOff, (short) 0, block, (short) 0);
            pending = 0;
            return finalTransform(out, outOff);
        }
        // XOR the method-2 padding (0x80 then 00 to the block boundary) into
        // the CBC chaining block.  The bytes past `pending` still hold the
        // previous ciphertext block, which is exactly the CBC chaining value
        // for the trailing zero pad bytes; when no full block preceded them
        // they are zero, as required (EMV v4.4 Book 2 Annex A1.2.1).
        block[pending] ^= (byte) 0x80;
        des.doFinal(block, (short) 0, (short) 8, block, (short) 0);
        pending = 0;
        return finalTransform(out, outOff);
    }

    /**
     * Computes the full 8-byte algorithm 3 MAC of an already block-aligned
     * message (a multiple of 8 bytes) without adding any further padding.  This
     * is what EMV Format 1 secure messaging needs: the caller has already
     * applied the ISO/IEC 7816-4 padding (EMV v4.4 Book 2 Annex D2.3.1), so the padding
     * of the MAC algorithm's first step must be omitted (EMV v4.4 Book 2 section 9.2.3).
     */
    public short macAligned(byte[] key, short keyOff, short keyLen, byte[] msg,
                            short msgOff, short msgLen, byte[] out, short outOff) {
        if (keyLen != 16) {
            ISOException.throwIt((short) 0x6700);
        }
        if ((msgLen & (short) 0x0007) != 0) {
            ISOException.throwIt((short) 0x6700);
        }
        ensureNative();
        setKeyOnce(key, keyOff);

        if (cbcNoPad != null && msgLen > 0) {
            // The platform raw CBC-MAC (no padding); the message is aligned.
            cbcNoPad.init(cbcKey, Signature.MODE_SIGN);
            cbcNoPad.sign(msg, msgOff, msgLen, block, (short) 0);
            return finalTransform(out, outOff);
        }

        // Manual single-DES CBC over the aligned message (the ISO9797_M2
        // signature would add a full 80 00.. block to an aligned message).
        Util.arrayFillNonAtomic(block, (short) 0, (short) 8, (byte) 0);
        des.init(cbcKey, Cipher.MODE_ENCRYPT);
        short p = msgOff;
        short end = (short) (msgOff + msgLen);
        while (p < end) {
            for (short i = 0; i < 8; i++) {
                block[i] ^= msg[(short) (p + i)];
            }
            des.doFinal(block, (short) 0, (short) 8, block, (short) 0);
            p += 8;
        }

        return finalTransform(out, outOff);
    }

    /** The final DES_dec(K2)/DES_enc(K1) transformation of algorithm 3. */
    private short finalTransform(byte[] out, short outOff) {
        des.init(finalKey, Cipher.MODE_DECRYPT);
        des.doFinal(block, (short) 0, (short) 8, block, (short) 0);
        des.init(cbcKey, Cipher.MODE_ENCRYPT);
        des.doFinal(block, (short) 0, (short) 8, out, outOff);
        return (short) 8;
    }

    /**
     * Zeroizes the session-derived K1/K2 DES keys and the working block.
     * EMV v4.4 Book 2 §A1.2.2 requires the intermediate values of the MAC to be
     * kept secret; without this they would stay in persistent memory between
     * transactions.  The next {@link #start} reloads a session key, so clearing
     * is safe at a session boundary.
     */
    public void zeroize() {
        if (cbcKey.isInitialized()) {
            cbcKey.clearKey();
        }
        if (finalKey.isInitialized()) {
            finalKey.clearKey();
        }
        Util.arrayFillNonAtomic(loadedKey, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(block, (short) 0, (short) 8, (byte) 0);
        keyLoaded = false;
        pending = 0;
    }

    /** True while a session key is loaded (observability for tests). */
    public boolean isInitialized() {
        return cbcKey.isInitialized() || finalKey.isInitialized();
    }
}
