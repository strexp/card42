package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* One transparent LDS2 elementary file (Doc 9303-10 §3.8/§3.9).
 *
 * A file identifier, a current capacity, a current length and an optional
 * "activated" flag used by the Additional Biometrics EF.  Writing is refused
 * once the file is activated (Doc 9303-10 §3.8.2).
 *
 * There is no fixed per-file size baked in: the capacity grows on demand up to
 * the protocol maximum {@link EmrtdTags#MAX_EF_BYTES}.  Personalization sizes
 * it from the DGI length; a runtime UPDATE BINARY may carry the optional File
 * Size DO {@code 'C0'} (Doc 9303-10 §3.8.1) or simply grow as it writes.
 *
 * The paged backing store lives in {@link PagedFile}, so a large biometric
 * record costs only the bytes it uses and never needs one contiguous EEPROM
 * array.
 *
 * @author card42
 */

public final class Lds2TransparentFile extends PagedFile {

    /** False for EF.Biometrics (FIDs 0201-0240), whose Short EF Identifier is N/A. */
    private final boolean sfiAddressable;
    private boolean activated;
    /** True once any write has been applied; the first UPDATE BINARY must use offset 0. */
    private boolean written;

    public Lds2TransparentFile(short fid) {
        this(fid, true);
    }

    public Lds2TransparentFile(short fid, boolean sfiAddressable) {
        super(fid);
        this.sfiAddressable = sfiAddressable;
        this.activated = false;
    }

    public boolean isSfiAddressable() {
        return sfiAddressable;
    }

    public boolean isActivated() {
        return activated;
    }

    /** True once any UPDATE BINARY / personalization write has been applied. */
    public boolean isWritten() {
        return written;
    }

    /**
     * Grows the file and its page table to hold at least {@code needed} bytes,
     * in one step.  Bounded by {@link EmrtdTags#MAX_EF_BYTES}; a larger value is
     * refused with 6A84.  Called at the start of a DGI, and from UPDATE BINARY
     * when the optional File Size DO {@code 'C0'} is present.
     */
    public void ensureCapacity(short needed) {
        ensureCapacity(needed, ISO7816.SW_FILE_FULL);
    }

    /** Marks the file read-only (Additional Biometrics ACTIVATE, §3.8.2). */
    public void activate() {
        activated = true;
    }

    /** Starts a fresh write; pages allocated by an earlier write are reused. */
    public void beginSet() {
        requireWritable();
        resetLength();
    }

    /** Replaces the content; refuses a write on an activated file. */
    public void set(byte[] src, short off, short len) {
        requireWritable();
        if (len < 0 || len > EmrtdTags.MAX_EF_BYTES) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        resetLength();
        if (len > 0) {
            ensureCapacity(len);
            appendRaw(src, off, len);
            written = true;
        }
    }

    /** Appends a chunk (personalization may split a large file). */
    public void append(byte[] src, short off, short len) {
        requireWritable();
        short total = (short) (getLength() + len);
        // A sum past 32767 wraps negative (the 15-bit protocol maximum).
        if (len < 0 || total < 0) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        if (len == 0) {
            return;
        }
        ensureCapacity(total);
        appendRaw(src, off, len);
        written = true;
    }

    /** Writes src at an absolute offset, extending the file when needed. */
    public void update(short offset, byte[] src, short off, short len) {
        requireWritable();
        if (offset < 0 || len < 0) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        short end = (short) (offset + len);
        if (end < 0) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        if (len == 0) {
            written = true;
            return;
        }
        ensureCapacity(end);
        if (offset > getLength()) {
            // The bytes before the write offset were never written; keep them
            // zero like the previous exact-size scheme (new pages are zeroed).
            clearRange(getLength(), offset);
        }
        writeAt(offset, src, off, len);
        if (end > getLength()) {
            setLength(end);
        }
        written = true;
    }

    private void requireWritable() {
        if (activated) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }
}
