package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

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
 * Like {@link LdsFile} the content is paged (256-byte pages, allocated on
 * first use), so a large biometric record costs only the bytes it uses and
 * never needs one contiguous EEPROM array.
 *
 * @author card42
 */

public final class Lds2TransparentFile {

    /** Bytes per backing page: a power of two so the index/offset are shifts. */
    private static final short PAGE = (short) 256;
    private static final short PAGE_SHIFT = (short) 8;
    private static final short PAGE_MASK = (short) 0xFF;

    private final short fid;
    /** Current upper bound (grows on demand, never shrinks); not a fixed budget. */
    private short capacity;
    /** False for EF.Biometrics (FIDs 0201-0240), whose Short EF Identifier is N/A. */
    private final boolean sfiAddressable;
    /** The page array; each element is a 256-byte {@code byte[]} (Java Card has
     * no multidimensional arrays, so the pages are held as {@code Object} refs). */
    private Object[] pages;
    private short length;
    private boolean activated;
    /** True once any write has been applied; the first UPDATE BINARY must use offset 0. */
    private boolean written;

    public Lds2TransparentFile(short fid) {
        this(fid, true);
    }

    public Lds2TransparentFile(short fid, boolean sfiAddressable) {
        this.fid = fid;
        this.capacity = 0;
        this.sfiAddressable = sfiAddressable;
        this.pages = null;
        this.length = 0;
        this.activated = false;
    }

    public short getFid() {
        return fid;
    }

    public boolean isSfiAddressable() {
        return sfiAddressable;
    }

    public short getLength() {
        return length;
    }

    /** The current capacity: the high-water mark reached so far, not a budget. */
    public short getCapacity() {
        return capacity;
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
        if (needed < 0 || needed > EmrtdTags.MAX_EF_BYTES) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        if (needed <= capacity) {
            return;
        }
        capacity = needed;
        growPages();
    }

    /** Marks the file read-only (Additional Biometrics ACTIVATE, §3.8.2). */
    public void activate() {
        activated = true;
    }

    /** Starts a fresh write; previously allocated pages are kept for reuse. */
    public void beginSet() {
        requireWritable();
        length = 0;
    }

    /** Replaces the content; refuses a write on an activated file. */
    public void set(byte[] src, short off, short len) {
        requireWritable();
        if (len < 0 || len > EmrtdTags.MAX_EF_BYTES) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        length = 0;
        if (len > 0) {
            ensureCapacity(len);
            appendRaw(src, off, len);
            written = true;
        }
    }

    /** Appends a chunk (personalization may split a large file). */
    public void append(byte[] src, short off, short len) {
        requireWritable();
        short total = (short) (length + len);
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
        if (offset > length) {
            // The bytes before the write offset were never written; keep them
            // zero like the previous exact-size scheme (new pages are zeroed).
            clearRange(length, offset);
        }
        writeAt(offset, src, off, len);
        if (end > length) {
            length = end;
        }
        written = true;
    }

    /** Reads [off, off+len) into out; refuses a range past the file end. */
    public short read(short off, short len, byte[] out, short outOff) {
        if (off < 0 || len < 0 || off > length || len > (short) (length - off)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short p = 0;
        while (p < len) {
            short pageIndex = (short) (off >> PAGE_SHIFT);
            short pageOff = (short) (off & PAGE_MASK);
            byte[] page = (byte[]) pages[pageIndex];
            short room = (short) (PAGE - pageOff);
            short n = (short) (len - p);
            if (n > room) {
                n = room;
            }
            Util.arrayCopyNonAtomic(page, pageOff, out, (short) (outOff + p), n);
            off = (short) (off + n);
            p = (short) (p + n);
        }
        return len;
    }

    private void requireWritable() {
        if (activated) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /** Appends at the current end (bounds already checked by the caller). */
    private void appendRaw(byte[] src, short off, short len) {
        writeAt(length, src, off, len);
        length = (short) (length + len);
    }

    /** Copies len bytes to an absolute offset. */
    private void writeAt(short offset, byte[] src, short off, short len) {
        short p = 0;
        while (p < len) {
            short pageIndex = (short) (offset >> PAGE_SHIFT);
            short pageOff = (short) (offset & PAGE_MASK);
            byte[] page = page(pageIndex);
            short room = (short) (PAGE - pageOff);
            short n = (short) (len - p);
            if (n > room) {
                n = room;
            }
            Util.arrayCopyNonAtomic(src, (short) (off + p), page, pageOff, n);
            offset = (short) (offset + n);
            p = (short) (p + n);
        }
    }

    /** Zeroes [from, to) (an UPDATE BINARY gap). */
    private void clearRange(short from, short to) {
        short at = from;
        while (at < to) {
            short pageIndex = (short) (at >> PAGE_SHIFT);
            short pageOff = (short) (at & PAGE_MASK);
            byte[] page = page(pageIndex);
            short room = (short) (PAGE - pageOff);
            short n = (short) (to - at);
            if (n > room) {
                n = room;
            }
            Util.arrayFillNonAtomic(page, pageOff, n, (byte) 0);
            at = (short) (at + n);
        }
    }

    /** The page at {@code index}, allocated on first use. */
    private byte[] page(short index) {
        if (pages == null || index >= pages.length) {
            growPages();
        }
        byte[] p = (byte[]) pages[index];
        if (p == null) {
            p = new byte[PAGE];
            pages[index] = p;
        }
        return p;
    }

    /**
     * Resizes the page table to cover the current capacity.  Java Card's
     * classic API has no {@code Object[]} bulk copy, so the references are
     * copied by hand; the old table is dropped and its reclamation requested.
     */
    private void growPages() {
        short want = (short) (capacity >> PAGE_SHIFT);
        if ((capacity & PAGE_MASK) != 0) {
            want = (short) (want + 1);
        }
        if (pages == null) {
            pages = new Object[want];
            return;
        }
        if (want <= pages.length) {
            return;
        }
        Object[] bigger = new Object[want];
        for (short i = 0; i < pages.length; i++) {
            bigger[i] = pages[i];
        }
        pages = bigger;
        try {
            // Best effort: the platform may refuse (or ignore) reclamation
            // inside the Security Domain's STORE DATA transaction.
            JCSystem.requestObjectDeletion();
        } catch (RuntimeException e) {
            // Keep the old table's bytes at worst; the new table is usable.
        }
    }
}
