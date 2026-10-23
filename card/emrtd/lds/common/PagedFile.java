package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/* The paged 256-byte backing store shared by the LDS1 ({@link LdsFile}) and
 * LDS2 ({@link Lds2TransparentFile}) transparent elementary files.
 *
 * The page table is allocated on demand, one 256-byte page at a time, so a
 * large DG2 or biometric EF never needs one contiguous array.  This base class
 * owns only the existing fields and low-level page read/write helpers; the
 * LDS1/LDS2-specific rules (error status, activation, written flag) stay in
 * the subclasses.  Moving these fields/methods here is heap-neutral: the
 * number of objects and arrays is unchanged.
 *
 * @author card42
 */

public abstract class PagedFile {

    /** Bytes per backing page: a power of two so the index/offset are shifts. */
    static final short PAGE = (short) 256;
    static final short PAGE_SHIFT = (short) 8;
    static final short PAGE_MASK = (short) 0xFF;

    private final short fid;
    /** Current upper bound (grows on demand, never shrinks); not a fixed budget. */
    private short capacity;
    /** The page array; each element is a 256-byte {@code byte[]}. */
    private Object[] pages;
    private short length;

    protected PagedFile(short fid) {
        this.fid = fid;
        this.capacity = 0;
        this.pages = null;
        this.length = 0;
    }

    public final short getFid() {
        return fid;
    }

    public final short getLength() {
        return length;
    }

    /** The current capacity: the high-water mark reached so far, not a budget. */
    public final short getCapacity() {
        return capacity;
    }

    /**
     * Grows the file and its page table to hold at least {@code needed} bytes,
     * in one step.  Bounded by {@link EmrtdTags#MAX_EF_BYTES}; a larger value is
     * refused with {@code overflowSw}.
     */
    protected final void ensureCapacity(short needed, short overflowSw) {
        if (needed < 0 || needed > EmrtdTags.MAX_EF_BYTES) {
            ISOException.throwIt(overflowSw);
        }
        if (needed <= capacity) {
            return;
        }
        capacity = needed;
        growPages();
    }

    /** Reads [off, off+len) into out; refuses a range past the file end. */
    public final short read(short off, short len, byte[] out, short outOff) {
        if (off < 0 || len < 0 || off > length || len > (short) (length - off)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short p = 0;
        while (p < len) {
            short pageIndex = (short) (off >> PAGE_SHIFT);
            short pageOff = (short) (off & PAGE_MASK);
            byte[] page = page(pageIndex);
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

    /** Drops the logical length without releasing the allocated pages. */
    protected final void resetLength() {
        length = 0;
    }

    /** Sets the logical length after a bounded write. */
    protected final void setLength(short value) {
        length = value;
    }

    /** Appends at the current end (bounds already checked by the caller). */
    protected final void appendRaw(byte[] src, short off, short len) {
        writeAt(length, src, off, len);
        length = (short) (length + len);
    }

    /** Copies len bytes to an absolute offset. */
    protected final void writeAt(short offset, byte[] src, short off, short len) {
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
    protected final void clearRange(short from, short to) {
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
