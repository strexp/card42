package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/* Card-side EMV secure messaging (EMV v4.4 Book 2 §9.2/§9.3).
 *
 * card42 implements the CCD convention: every secured command is Format 1 (the low
 * nibble of CLA is 'C'), its data field is a BER-TLV sequence whose last object
 * is the MAC (tag '8E', 4-8 bytes).  The MAC is computed with the MAC Session
 * Key over
 *
 *     ICV || CLA || INS || P1 || P2 || <the command data objects>
 *
 * where ICV is the MAC chaining value: for the first script command the
 * Application Cryptogram of the first GENERATE AC (8 bytes, right-padded with
 * zeros to the block size for AES), and for every later command the full MAC of
 * the previous one (EMV v4.4 Book 2 section 9.2.3.1).  The MAC itself follows the
 * Cryptogram Version of the profile: ISO/IEC 9797-1 Algorithm 3 with 3DES for
 * CV '5' and Algorithm 5 (CMAC) with AES for CV '6' (EMV v4.4 Book 2 Annex A1.2, §9.2.3).
 *
 * The MAC and Encipherment Session Keys are derived from the independent MAC
 * and Encipherment Master Keys (EMV CPS v2.0 Annex A DGI '8000') with the same session-key
 * function used by the Application Cryptogram (EMV v4.4 Book 2 Annex A1.3.1).
 *
 * The encipherment key decrypts the Format 1 confidentiality object (tag '87',
 * value = padding indicator '01' || cryptogram) used by PIN CHANGE/UNBLOCK.
 *
 * @author card42
 */

public class SecureMessaging implements ISO7816 {

    /** Longest secured command data field handled (post-issuance commands). */
    private static final short SCRATCH_SIZE = (short) 64;
    /** Larger MAC input buffer needed by the 16-byte AES block size
     * (EMV v4.4 Book 2 Annex A1.2.2). */
    private static final short SCRATCH_SIZE_AES = (short) 96;

    private final EMVProtocolState protocolState;
    private final CryptoProfile profile;

    private final DESKey macMasterKey;
    private final DESKey encMasterKey;
    private final DESKey encSessionKey;
    private final AESKey macMasterAes;
    private final AESKey encMasterAes;
    private final AESKey encSessionAes;

    private boolean hasMacMasterKey;
    private boolean hasEncMasterKey;

    /* The MAC/ENC session-key bytes, the ICV and the derived-AC marker are
     * allocated together on first use while the applet is selected, so an
     * instance that never uses secure messaging does not spend the shared
     * transient budget (docs/specs/common/cryptography.md §9).  The derivation object
     * is shared with EMVCrypto, whose AC path always needs it. */
    private final SessionKey derivation;
    private byte[] macSessionKeyBytes;
    private byte[] encSessionKeyBytes;

    /** First AC the session keys were derived for; CLEAR_ON_DESELECT. */
    private byte[] derivedAc;
    /** True once prepare() has derived the session keys for derivedAc. */
    private boolean derived;

    /** MAC chaining value (EMV v4.4 Book 2 section 9.2.3.1); up to 16 bytes for AES. */
    private byte[] scriptIcv;
    private boolean icvInitialised;

    /** Set after a MAC failure; later commands are refused with 6985. */
    private boolean scriptFailed;

    /**
     * Persistent CVR byte 4 b4 'Issuer Script Processing Failed'
     * (EMV v4.4 Book 3 §9.2.3.2): set as soon as a command with secure
     * messaging fails and reported in every GENERATE AC until the card's reset
     * conditions are met.  Unlike {@link #scriptFailed} it survives the session
     * and per-transaction resets, so a failure of a tag '72' script (processed
     * after the final AC) is still reported in the next transaction's first AC.
     */
    private boolean scriptFailedPersistent;

    /** Successfully unwrapped secure-messaging commands (CVR byte 4 b8-b5). */
    private short scriptCommands;

    private final RetailMac retailMac;
    private final AesCmac aesCmac;
    private final Cipher desCbc;
    private final Cipher aesCbc128;

    public SecureMessaging(EMVProtocolState protocolState, CryptoProfile profile,
            RetailMac retailMac, AesCmac aesCmac, SessionKey derivation) {
        this.protocolState = protocolState;
        this.profile = profile;
        this.retailMac = retailMac;
        this.aesCmac = aesCmac;
        this.derivation = derivation;

        macMasterKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
                KeyBuilder.LENGTH_DES3_2KEY, false);
        encMasterKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
                KeyBuilder.LENGTH_DES3_2KEY, false);
        encSessionKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
                KeyBuilder.LENGTH_DES3_2KEY, false);

        macMasterAes = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
                KeyBuilder.LENGTH_AES_128, false);
        encMasterAes = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
                KeyBuilder.LENGTH_AES_128, false);
        encSessionAes = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
                KeyBuilder.LENGTH_AES_128, false);

        // The key/ICV buffers are allocated on first use (see
        // ensureKeyBuffers), while the applet is selected: a CV '5' instance
        // that never runs secure messaging never needs them.
        derived = false;

        desCbc = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        aesCbc128 = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    }

    /** True once a MAC master key has been personalized. */
    public boolean hasMacKey() {
        return hasMacMasterKey;
    }

    /** Number of successfully processed secure-messaging commands (0-15). */
    public short getScriptCommandsProcessed() {
        return scriptCommands;
    }

    /**
     * Resets the per-transaction issuer-script state at the start of a new
     * session.  The script counter feeds CVR byte 4 b8-b5, which the card
     * reports in the first GENERATE AC of a transaction; without this reset a
     * transaction that ran no script would still report the previous
     * transaction's count (EMV v4.4 Book 3 §9.2.3.2).  {@code scriptFailed} is
     * per-transaction as well and is cleared here so the new transaction does
     * not start in the failed state.
     */
    public void startNewTransaction() {
        scriptCommands = 0;
        scriptFailed = false;
    }

    /**
     * Zeroizes the session-derived secure-messaging material: the Encipherment
     * Session Key objects, the MAC/ENC session-key bytes, the MAC chaining
     * value and the derived-AC marker.  The master keys persist.  EMV v4.4
     * Book 2 §A1.2.2 requires the intermediate values of the MAC to be kept
     * secret; the next {@link #prepare} re-derives the session keys.
     */
    public void zeroizeSessionKeys() {
        if (encSessionKey.isInitialized()) {
            encSessionKey.clearKey();
        }
        if (encSessionAes.isInitialized()) {
            encSessionAes.clearKey();
        }
        if (macSessionKeyBytes != null) {
            Util.arrayFillNonAtomic(macSessionKeyBytes, (short) 0, (short) 16, (byte) 0);
            Util.arrayFillNonAtomic(encSessionKeyBytes, (short) 0, (short) 16, (byte) 0);
            Util.arrayFillNonAtomic(scriptIcv, (short) 0, (short) 16, (byte) 0);
            Util.arrayFillNonAtomic(derivedAc, (short) 0, (short) 8, (byte) 0);
        }
        derived = false;
        icvInitialised = false;
    }

    /**
     * True while the persistent 'Issuer Script Processing Failed' bit (CVR
     * byte 4 b4) is set, i.e. since the last secure-messaging failure until the
     * card's reset conditions (EMV v4.4 Book 3 §9.2.3.2).
     */
    public boolean isScriptFailedPersistent() {
        return scriptFailedPersistent;
    }

    /** Clears the persistent 'Issuer Script Processing Failed' bit. */
    public void clearScriptFailedPersistent() {
        scriptFailedPersistent = false;
    }

    /**
     * Allocates the session-key / ICV buffers on first use, while the applet is
     * selected.  This must not happen in the key setters: personalization runs
     * in processData with the applet deselected, where CLEAR_ON_DESELECT
     * allocation is not available (docs/specs/common/risks.md).  CLEAR_ON_DESELECT
     * arrays live for the whole package context, so an instance that never uses
     * secure messaging never spends this budget (docs/specs/common/cryptography.md §9).
     */
    private void ensureKeyBuffers() {
        if (macSessionKeyBytes == null) {
            macSessionKeyBytes = JCSystem.makeTransientByteArray((short) 16,
                    JCSystem.CLEAR_ON_DESELECT);
            encSessionKeyBytes = JCSystem.makeTransientByteArray((short) 16,
                    JCSystem.CLEAR_ON_DESELECT);
            scriptIcv = JCSystem.makeTransientByteArray((short) 16,
                    JCSystem.CLEAR_ON_DESELECT);
            derivedAc = JCSystem.makeTransientByteArray((short) 8,
                    JCSystem.CLEAR_ON_DESELECT);
        }
    }

    /** Stores the MAC master key of EMV CPS v2.0 Annex A DGI '8000' (16 bytes). */
    public void setMacMasterKey(byte[] buf, short off, short len) {
        if (profile.isAes()) {
            if (len != 16) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            macMasterAes.setKey(buf, off);
        } else {
            if (len != 16) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            macMasterKey.setKey(buf, off);
        }
        hasMacMasterKey = true;
    }

    /** Stores the encipherment master key of EMV CPS v2.0 Annex A DGI '8000' (16 bytes). */
    public void setEncMasterKey(byte[] buf, short off, short len) {
        if (profile.isAes()) {
            if (len != 16) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            encMasterAes.setKey(buf, off);
        } else {
            if (len != 16) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            encMasterKey.setKey(buf, off);
        }
        hasEncMasterKey = true;
    }

    /**
     * Prepares the session keys for the transaction's first Application
     * Cryptogram and restarts the MAC chain when the transaction changed
     * (EMV v4.4 Book 2 §A1.3.1: the secure-messaging diversification
     * value is the first AC, not the ATC).  The MAC and
     * Encipherment Session Keys therefore become available only after the
     * first GENERATE AC of the transaction.
     */
    public void prepare(byte[] ac, short off) {
        ensureKeyBuffers();
        // derivedAc is this session's Application Cryptogram, not a long-term
        // secret, so the short-circuiting Util.arrayCompare is fine here
        // (docs/specs/common/cryptography.md §9).
        if (derived && Util.arrayCompare(derivedAc, (short) 0, ac, off, (short) 8) == 0) {
            return;
        }
        short keyLength = profile.getKeyLength();
        if (profile.isAes()) {
            // R = first AC || 00 x8 (the AES block size is 16).  scriptIcv is
            // reused as the R buffer: it is (re)initialised in unwrap().
            Util.arrayCopyNonAtomic(ac, off, scriptIcv, (short) 0, (short) 8);
            Util.arrayFillNonAtomic(scriptIcv, (short) 8, (short) 8, (byte) 0);
            derivation.deriveAes(macMasterAes, keyLength, scriptIcv, (short) 0,
                    macSessionKeyBytes, (short) 0);
            if (hasEncMasterKey) {
                derivation.deriveAes(encMasterAes, keyLength, scriptIcv, (short) 0,
                        encSessionKeyBytes, (short) 0);
                encSessionAes.setKey(encSessionKeyBytes, (short) 0);
            }
        } else {
            derivation.derive(macMasterKey, ac, off, macSessionKeyBytes, (short) 0);
            if (hasEncMasterKey) {
                derivation.derive(encMasterKey, ac, off, encSessionKeyBytes, (short) 0);
                encSessionKey.setKey(encSessionKeyBytes, (short) 0);
            }
        }
        Util.arrayCopyNonAtomic(ac, off, derivedAc, (short) 0, (short) 8);
        derived = true;
        icvInitialised = false;
        scriptFailed = false;
        scriptCommands = 0;
    }

    /**
     * Builds the Format 1 message to protect (EMV v4.4 Book 2 section 9.2.3 and Annex
     * D2.3.1): the block-size ICV, the padded command header
     * {@code CLA INS P1 P2 80 00 ...}, and then every data object except the
     * MAC, each padded on the right with {@code 80} followed by the smallest
     * number of {@code 00} bytes that makes it a multiple of the block size.
     *
     * The result is always a multiple of the block size, so the MAC is computed
     * over it without the ISO/IEC 9797-1 padding step (see macAligned).
     * Returns the number of bytes written to out/outOff.  Throws 6A80 on a
     * malformed data field.
     *
     * Exposed (public static, no crypto state) so the EMV v4.4 Book 2 Annex D2.3.1 spec vector
     * can be checked by a pure-JVM unit test (docs/specs/common/toolchain.md §6).
     */
    public static short format1MacInput(byte[] apdu, short dataOff, short dataLen,
                                        byte[] icv, byte[] out, short outOff) {
        return format1MacInput(apdu, dataOff, dataLen, icv, (short) 8, (short) 8,
                out, outOff);
    }

    /** Format 1 MAC input for an explicit ICV length and block size (8 or 16). */
    public static short format1MacInput(byte[] apdu, short dataOff, short dataLen,
                                        byte[] icv, short icvLength, short blockSize,
                                        byte[] out, short outOff) {
        Util.arrayCopyNonAtomic(icv, (short) 0, out, outOff, icvLength);
        Util.arrayCopyNonAtomic(apdu, (short) 0, out, (short) (outOff + icvLength),
                (short) 4);
        short p = (short) (outOff + icvLength + 4);
        // ISO/IEC 7816-4 padding of the header to the block size.
        out[p] = (byte) 0x80;
        p++;
        while ((short) (p - outOff) % blockSize != 0) {
            out[p] = (byte) 0x00;
            p++;
        }

        short pos = dataOff;
        short end = (short) (dataOff + dataLen);
        while (pos < end) {
            short tag = Tlv.getTag(apdu, pos);
            short tagLen = Tlv.tagLength(apdu, pos);
            short lenOff = (short) (pos + tagLen);
            if (lenOff >= end) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            short lenField = Tlv.lengthFieldLength(apdu, lenOff);
            if (lenField == 0 || (short) (lenOff + lenField) > end) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            short valueLen = Tlv.getLength(apdu, lenOff);
            short valueOff = (short) (lenOff + lenField);
            short objectEnd = (short) (valueOff + valueLen);
            if (objectEnd > end) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            if (tag == TlvTags.TAG_SM_MAC) {
                // The MAC is the last object of a Format 1 data field and is
                // not part of the message it authenticates.
                if (objectEnd != end) {
                    ISOException.throwIt(SW_WRONG_DATA);
                }
            } else {
                short copyLen = (short) (objectEnd - pos);
                if ((short) (p + copyLen + blockSize) > out.length) {
                    ISOException.throwIt(SW_WRONG_LENGTH);
                }
                Util.arrayCopyNonAtomic(apdu, pos, out, p, copyLen);
                p += copyLen;
                // ISO/IEC 7816-4 padding: a mandatory 80 then 00 to the next
                // multiple of the block size (EMV v4.4 Book 2 Annex D2.3.1).
                out[p] = (byte) 0x80;
                p++;
                while ((short) (p - outOff) % blockSize != 0) {
                    out[p] = (byte) 0x00;
                    p++;
                }
            }
            pos = objectEnd;
        }
        return (short) (p - outOff);
    }

    /**
     * Verifies and unwraps one Format 1 secured command, returning the length
     * of the plaintext command data written to out/outOff (0 when the command
     * has no data).  Throws 6A80 on a MAC failure (and remembers it, so later
     * commands are refused with 6985) and 6985 when no MAC key is available.
     *
     * apdu[0..3] is the command header (CLA INS P1 P2); the data field starts
     * at dataOff.  arqc is the first AC used as the initial chaining value.
     */
    public short unwrap(byte[] apdu, short dataOff, short dataLen, byte[] arqc,
                        byte[] out, short outOff) {
        if (!hasMacMasterKey) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        ensureKeyBuffers();
        if (scriptFailed) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED); // 6985
        }
        short blockSize = profile.isAes() ? (short) 16 : (short) 8;
        short keyLength = profile.getKeyLength();
        if (!icvInitialised) {
            // The ICV is the first AC, right-padded with zeros to the block
            // size for AES (EMV v4.4 Book 2 section 9.2.3.1).
            Util.arrayCopyNonAtomic(arqc, (short) 0, scriptIcv, (short) 0, (short) 8);
            if (blockSize == 16) {
                Util.arrayFillNonAtomic(scriptIcv, (short) 8, (short) 8, (byte) 0);
            }
            icvInitialised = true;
        }

        // Message to protect: ICV || padded header || padded data objects
        // (EMV v4.4 Book 2 Annex D2.3.1).  This validates the data field too.
        // The MAC input is a large scratch that is never live at the same time
        // as the other work-scratch users (offline-PIN recovery, DDA/CDA
        // message, ARPC), so it shares the one transient buffer
        // (docs/specs/common/risks.md, docs/specs/common/cryptography.md §9).
        byte[] scratch = protocolState.getWorkScratch(
                profile.isAes() ? SCRATCH_SIZE_AES : SCRATCH_SIZE);
        short macInputLength = format1MacInput(apdu, dataOff, dataLen,
                scriptIcv, blockSize, blockSize, scratch, (short) 0);

        // Locate the MAC and the (single) plaintext / confidentiality object.
        short pos = dataOff;
        short end = (short) (dataOff + dataLen);
        short macOff = -1;
        short macLen = 0;
        short plainOff = -1;
        short plainLen = 0;
        short encOff = -1;
        short encLen = 0;
        while (pos < end) {
            short tag = Tlv.getTag(apdu, pos);
            short tagLen = Tlv.tagLength(apdu, pos);
            short lenOff = (short) (pos + tagLen);
            short lenField = Tlv.lengthFieldLength(apdu, lenOff);
            short valueLen = Tlv.getLength(apdu, lenOff);
            short valueOff = (short) (lenOff + lenField);
            short objectEnd = (short) (valueOff + valueLen);
            if (tag == TlvTags.TAG_SM_MAC) {
                macOff = valueOff;
                macLen = valueLen;
            } else if (tag == TlvTags.TAG_SM_PLAINTEXT) {
                plainOff = valueOff;
                plainLen = valueLen;
            } else if (tag == TlvTags.TAG_SM_ENCIPHERED) {
                encOff = valueOff;
                encLen = valueLen;
            }
            pos = objectEnd;
        }

        if (macOff < 0 || macLen < 4 || macLen > 8) {
            ISOException.throwIt(SW_WRONG_DATA);
        }

        // The MAC is written over scriptIcv: the ICV has already been copied
        // into the MAC input, so the buffer is free until it is chained below.
        if (profile.isAes()) {
            aesCmac.macAligned(macSessionKeyBytes, (short) 0, keyLength,
                    scratch, (short) 0, macInputLength, scriptIcv, (short) 0);
        } else {
            retailMac.macAligned(macSessionKeyBytes, (short) 0, keyLength,
                    scratch, (short) 0, macInputLength, scriptIcv, (short) 0);
        }
        if (!ConstantTime.equals(scriptIcv, (short) 0, apdu, macOff, macLen)) {
            // A failed MAC kills the secure-messaging session: remember it and
            // clear the derived key material (EMV v4.4 Book 2 §9.2,
            // docs/specs/common/cryptography.md §9).
            scriptFailed = true;
            // The failure is also reported in the CVR until reset
            // (EMV v4.4 Book 3 §9.2.3.2).
            scriptFailedPersistent = true;
            Util.arrayFillNonAtomic(macSessionKeyBytes, (short) 0,
                    (short) macSessionKeyBytes.length, (byte) 0);
            Util.arrayFillNonAtomic(encSessionKeyBytes, (short) 0,
                    (short) encSessionKeyBytes.length, (byte) 0);
            Util.arrayFillNonAtomic(scriptIcv, (short) 0,
                    (short) scriptIcv.length, (byte) 0);
            ISOException.throwIt(SW_WRONG_DATA); // 6A80
        }

        // The full MAC is already in scriptIcv: that is the next ICV
        // (EMV v4.4 Book 2 section 9.2.3.1).  Only the first blockSize bytes are used.
        if (scriptCommands < (short) 15) {
            // CVR byte 4 b8-b5 counts the successful secured commands
            // (EMV v4.4 Book 3 Annex C §C9).
            scriptCommands++;
        }

        if (plainOff >= 0) {
            Util.arrayCopyNonAtomic(apdu, plainOff, out, outOff, plainLen);
            return plainLen;
        }
        if (encOff >= 0) {
            return decrypt(apdu, encOff, encLen, out, outOff);
        }
        return 0;
    }

    /**
     * Decrypts a Format 1 confidentiality object: the first byte is the padding
     * indicator ('01'), the rest is a CBC cryptogram whose plaintext was
     * padded according to ISO/IEC 7816-4 before encipherment (EMV v4.4 Book 2 Annex
     * A1.1/D2.2).  The padding is stripped again here: a mandatory '80' byte
     * followed by zero or more '00' bytes (always at least one block).
     */
    private short decrypt(byte[] in, short off, short len,
                          byte[] out, short outOff) {
        if (!hasEncMasterKey || len < 2) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        }
        if (in[off] != TlvTags.SM_PADDING_INDICATOR) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        try {
            Cipher cipher;
            if (profile.isAes()) {
                cipher = aesCbc128;
                cipher.init(encSessionAes, Cipher.MODE_DECRYPT);
            } else {
                cipher = desCbc;
                cipher.init(encSessionKey, Cipher.MODE_DECRYPT);
            }
            short n = cipher.doFinal(in, (short) (off + 1), (short) (len - 1),
                    out, outOff);
            // Strip the ISO 7816-4 padding: the last non-zero byte must be the
            // 0x80 marker added before encipherment.
            short i = (short) (outOff + n);
            while (i > outOff && out[(short) (i - 1)] == 0) {
                i--;
            }
            if (i <= outOff || out[(short) (i - 1)] != (byte) 0x80) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            return (short) (i - 1 - outOff);
        } catch (ISOException e) {
            throw e;
        } catch (Exception e) {
            ISOException.throwIt(SW_WRONG_DATA);
            return 0;
        }
    }
}
