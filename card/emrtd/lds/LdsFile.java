package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/* One transparent LDS1 elementary file (ICAO Doc 9303-10 §5).
 *
 * The file has a file identifier, a current capacity and a current length.
 * Personalization writes it whole (or in chunks); READ BINARY serves an
 * arbitrary [offset, offset+len) window.
 *
 * There is no fixed per-file size baked in: the capacity grows on demand up to
 * the protocol maximum {@link EmrtdTags#MAX_EF_BYTES} (15-bit READ BINARY
 * offset / DGI length).  The DGI header carries the value length before the
 * bytes arrive, so the streaming personalizer calls {@link #ensureCapacity}
 * once with the final size and the backing store is laid out in one step
 * instead of growing page by page.
 *
 * The backing store is paged: the content lives in fixed 256-byte pages,
 * allocated on first use and reused across writes.  This replaces the earlier
 * exact-size "grow a byte[] and copy the old content" scheme, which for a
 * multi-kilobyte DG2 (large face image) meant an O(n^2) EEPROM copy sequence
 * and, at the last growth step, two full copies live at once.  Pages keep the
 * peak allocation at one page and never demand one large contiguous array, so a
 * larger file costs only the bytes it actually uses and survives a fragmented
 * heap (docs/specs/common/risks.md §2).
 *
 * @author card42
 */

public final class LdsFile {

    /** Bytes per backing page: a power of two so the index/offset are shifts. */
    private static final short PAGE = (short) 256;
    private static final short PAGE_SHIFT = (short) 8;
    private static final short PAGE_MASK = (short) 0xFF;

    private final short fid;
    /** Current upper bound (grows on demand, never shrinks); not a fixed budget. */
    private short capacity;
    /** The page array; each element is a 256-byte {@code byte[]} (Java Card has
     * no multidimensional arrays, so the pages are held as {@code Object} refs). */
    private Object[] pages;
    private short length;

    public LdsFile(short fid) {
        this.fid = fid;
        this.capacity = 0;
        this.pages = null;
        this.length = 0;
    }

    public short getFid() {
        return fid;
    }

    public short getLength() {
        return length;
    }

    /** The current capacity: the high-water mark reached so far, not a budget. */
    public short getCapacity() {
        return capacity;
    }

    /**
     * Grows the file and its page table to hold at least {@code needed} bytes,
     * in one step.  Bounded by {@link EmrtdTags#MAX_EF_BYTES}; a larger value is
     * refused with 6700.  Called at the start of a DGI so a multi-kilobyte value
     * allocates its final page table once rather than page by page.
     */
    public void ensureCapacity(short needed) {
        if (needed < 0 || needed > EmrtdTags.MAX_EF_BYTES) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (needed <= capacity) {
            return;
        }
        capacity = needed;
        growPages();
    }

    /**
     * Starts a fresh write.  The length drops to zero but the already
     * allocated pages are kept and reused, so a re-personalization does not
     * re-allocate (and does not grow the transaction journal).
     */
    public void beginSet() {
        length = 0;
    }

    /** Replaces the file content; grows the store to fit. */
    public void set(byte[] src, short off, short len) {
        if (len < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        beginSet();
        if (len > 0) {
            append(src, off, len);
        }
    }

    /** Appends a chunk (personalization may split a large file). */
    public void append(byte[] src, short off, short len) {
        short total = (short) (length + len);
        // A sum past 32767 wraps negative (the 15-bit protocol maximum).
        if (len < 0 || total < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        ensureCapacity(total);
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
     * copied by hand; the old table is dropped and its reclamation requested
     * (Java Card does not collect it on its own).
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
