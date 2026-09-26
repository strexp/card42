package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* One transparent LDS2 elementary file (Doc 9303-10 §3.8/§3.9).
 *
 * A file identifier, a personalization capacity, a current length and an
 * optional "activated" flag used by the Additional Biometrics EF.  Writing is
 * refused once the file is activated (Doc 9303-10 §3.8.2).
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
    private final short capacity;
    private final short pageCount;
    /** False for EF.Biometrics (FIDs 0201-0240), whose Short EF Identifier is N/A. */
    private final boolean sfiAddressable;
    /** The page array; each element is a 256-byte {@code byte[]} (Java Card has
     * no multidimensional arrays, so the pages are held as {@code Object} refs). */
    private Object[] pages;
    private short length;
    private boolean activated;
    /** True once any write has been applied; the first UPDATE BINARY must use offset 0. */
    private boolean written;

    public Lds2TransparentFile(short fid, short capacity) {
        this(fid, capacity, true);
    }

    public Lds2TransparentFile(short fid, short capacity, boolean sfiAddressable) {
        this.fid = fid;
        this.capacity = capacity;
        short pageCount = (short) (capacity >> PAGE_SHIFT);
        if ((capacity & PAGE_MASK) != 0) {
            pageCount = (short) (pageCount + 1);
        }
        this.pageCount = pageCount;
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

    public boolean isActivated() {
        return activated;
    }

    /** True once any UPDATE BINARY / personalization write has been applied. */
    public boolean isWritten() {
        return written;
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
        if (len < 0 || len > capacity) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        length = 0;
        if (len > 0) {
            appendRaw(src, off, len);
            written = true;
        }
    }

    /** Appends a chunk (personalization may split a large file). */
    public void append(byte[] src, short off, short len) {
        requireWritable();
        if (len < 0 || length > capacity || len > (short) (capacity - length)) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        if (len == 0) {
            return;
        }
        appendRaw(src, off, len);
        written = true;
    }

    /** Writes src at an absolute offset, extending the file when needed. */
    public void update(short offset, byte[] src, short off, short len) {
        requireWritable();
        if (offset < 0 || len < 0 || offset > capacity || len > (short) (capacity - offset)) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        if (len == 0) {
            written = true;
            return;
        }
        if (offset > length) {
            // The bytes before the write offset were never written; keep them
            // zero like the previous exact-size scheme (new pages are zeroed).
            clearRange(length, offset);
        }
        writeAt(offset, src, off, len);
        short end = (short) (offset + len);
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
        if (pages == null) {
            pages = new Object[pageCount];
        }
        byte[] p = (byte[]) pages[index];
        if (p == null) {
            p = new byte[PAGE];
            pages[index] = p;
        }
        return p;
    }
}
