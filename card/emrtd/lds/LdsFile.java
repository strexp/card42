package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* One transparent LDS1 elementary file (ICAO Doc 9303-10 §5).
 *
 * The file has a file identifier, a personalization capacity and a current
 * length.  Personalization writes it whole (or in chunks); READ BINARY serves
 * an arbitrary [offset, offset+len) window.  The capacity is the maximum size
 * the personalizer may store; a larger write is refused with 6700.
 *
 * The backing store is paged: the content lives in fixed 256-byte pages,
 * allocated on first use and reused across writes.  This replaces the earlier
 * exact-size "grow a byte[] and copy the old content" scheme, which for a
 * multi-kilobyte DG2 (large face image) meant an O(n^2) EEPROM copy sequence
 * and, at the last growth step, two full copies live at once.  Pages keep the
 * peak allocation at one page and never demand one large contiguous array, so
 * a larger file costs only the bytes it actually uses and survives a
 * fragmented heap (docs/specs/common/risks.md §2).
 *
 * @author card42
 */

public final class LdsFile {

    /** Bytes per backing page: a power of two so the index/offset are shifts. */
    private static final short PAGE = (short) 256;
    private static final short PAGE_SHIFT = (short) 8;
    private static final short PAGE_MASK = (short) 0xFF;

    private final short fid;
    private final short capacity;
    private final short pageCount;
    /** The page array; each element is a 256-byte {@code byte[]} (Java Card has
     * no multidimensional arrays, so the pages are held as {@code Object} refs). */
    private Object[] pages;
    private short length;

    public LdsFile(short fid, short capacity) {
        this.fid = fid;
        this.capacity = capacity;
        short pageCount = (short) (capacity >> PAGE_SHIFT);
        if ((capacity & PAGE_MASK) != 0) {
            pageCount = (short) (pageCount + 1);
        }
        this.pageCount = pageCount;
        this.pages = null;
        this.length = 0;
    }

    public short getFid() {
        return fid;
    }

    public short getLength() {
        return length;
    }

    /** The personalization budget (upper bound), not the allocated size. */
    public short getCapacity() {
        return capacity;
    }

    /**
     * Starts a fresh write.  The length drops to zero but the already
     * allocated pages are kept and reused, so a re-personalization does not
     * re-allocate (and does not grow the transaction journal).
     */
    public void beginSet() {
        length = 0;
    }

    /** Replaces the file content; refuses data longer than the capacity. */
    public void set(byte[] src, short off, short len) {
        if (len < 0 || len > capacity) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        beginSet();
        if (len > 0) {
            append(src, off, len);
        }
    }

    /** Appends a chunk (personalization may split a large file). */
    public void append(byte[] src, short off, short len) {
        if (len < 0 || length > capacity || len > (short) (capacity - length)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short p = 0;
        while (p < len) {
            short pageIndex = (short) (length >> PAGE_SHIFT);
            short pageOff = (short) (length & PAGE_MASK);
            byte[] page = page(pageIndex);
            short room = (short) (PAGE - pageOff);
            short n = (short) (len - p);
            if (n > room) {
                n = room;
            }
            Util.arrayCopyNonAtomic(src, (short) (off + p), page, pageOff, n);
            length = (short) (length + n);
            p = (short) (p + n);
        }
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
