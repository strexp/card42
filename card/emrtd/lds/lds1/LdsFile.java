package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

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
 * The paged backing store lives in {@link PagedFile}; this class adds only the
 * LDS1-specific write rules.
 *
 * @author card42
 */

public final class LdsFile extends PagedFile {

    public LdsFile(short fid) {
        super(fid);
    }

    /**
     * Grows the file and its page table to hold at least {@code needed} bytes,
     * in one step.  Bounded by {@link EmrtdTags#MAX_EF_BYTES}; a larger value is
     * refused with 6700.  Called at the start of a DGI so a multi-kilobyte value
     * allocates its final page table once rather than page by page.
     */
    public void ensureCapacity(short needed) {
        ensureCapacity(needed, ISO7816.SW_WRONG_LENGTH);
    }

    /**
     * Starts a fresh write.  The length drops to zero but the already
     * allocated pages are kept and reused, so a re-personalization does not
     * re-allocate (and does not grow the transaction journal).
     */
    public void beginSet() {
        resetLength();
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
        short total = (short) (getLength() + len);
        // A sum past 32767 wraps negative (the 15-bit protocol maximum).
        if (len < 0 || total < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        ensureCapacity(total);
        appendRaw(src, off, len);
    }
}
