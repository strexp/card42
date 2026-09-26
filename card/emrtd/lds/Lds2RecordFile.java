package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* One linear LDS2 elementary file with variable-size records (Doc 9303-10
 * §3.7): EF.EntryRecords, EF.ExitRecords, EF.VisaRecords and EF.Certificates.
 *
 * Records are numbered sequentially from one in append order.  The storage is
 * a flat byte pool plus parallel offset/length arrays, so a record is a window
 * of the pool and no per-record object is allocated.  APPEND RECORD appends at
 * the end; READ RECORD serves one record or all records from a starting number.
 *
 * @author card42
 */

public final class Lds2RecordFile {

    private final short fid;
    private final byte[] pool;
    private final short[] offsets;
    private final short[] lengths;
    private final short maxRecordLength;
    private short count;
    private short used;
    /** The "current record" referenced by P1='00' (Doc 9303-10 §3.7.2 Table 11). */
    private short currentRecord;
    /**
     * A record being streamed by {@link #beginRecord()}.  The pool bytes are
     * written as the chunks arrive, but {@link #used} / {@link #count} only
     * advance in {@link #endRecord()}, so a stream that fails part way leaves
     * the file unchanged (a personalization sequence the SD rolls back must not
     * leave a half record behind).
     */
    private boolean pendingRecord;
    private short pendingStart;
    private short pendingLength;

    public Lds2RecordFile(short fid, short capacity, short maxRecords, short maxRecordLength) {
        this.fid = fid;
        this.pool = new byte[capacity];
        this.offsets = new short[maxRecords];
        this.lengths = new short[maxRecords];
        this.maxRecordLength = maxRecordLength;
        this.count = 0;
        this.used = 0;
        this.currentRecord = 1;
    }

    public short getFid() {
        return fid;
    }

    public short recordCount() {
        return count;
    }

    public short totalBytes() {
        return used;
    }

    /** The current record number, defaulting to 1 after SELECT. */
    public short currentRecord() {
        return currentRecord;
    }

    public short remainingRecords() {
        short byCount = (short) (offsets.length - count);
        // The remaining capacity is also bounded by the byte pool, assuming
        // every remaining record reaches the maximum size (Doc 9303-10 §3.8.3).
        short recordSize = maxRecordLength;
        if (recordSize == 0) {
            recordSize = (short) 1;
        }
        short free = (short) (pool.length - used);
        short bySpace = (short) (free / recordSize);
        return byCount < bySpace ? byCount : bySpace;
    }

    /** The length of record number {@code number} (1-based), or 0 when absent. */
    public short recordLength(short number) {
        if (number < 1 || number > count) {
            return 0;
        }
        return lengths[(short) (number - 1)];
    }

    /** Appends a record and returns its 1-based record number. */
    public short append(byte[] src, short off, short len) {
        beginRecord();
        appendChunk(src, off, len);
        endRecord();
        return count;
    }

    /**
     * Starts a record whose bytes arrive in chunks ({@link #appendChunk}).
     * Used by the streaming personalization path so a record larger than one
     * STORE DATA block never needs a whole-record buffer.
     */
    public void beginRecord() {
        pendingStart = used;
        pendingLength = 0;
        pendingRecord = true;
    }

    /** Appends the next chunk of the record started by {@link #beginRecord()}. */
    public void appendChunk(byte[] src, short off, short len) {
        if (!pendingRecord || len < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (pendingLength > maxRecordLength
                || len > (short) (maxRecordLength - pendingLength)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); // 6700
        }
        short newLength = (short) (pendingLength + len);
        if (count >= offsets.length || (short) (used + newLength) > pool.length) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL); // 6A84
        }
        Util.arrayCopyNonAtomic(src, off, pool, (short) (pendingStart + pendingLength), len);
        pendingLength = newLength;
    }

    /** Commits the record started by {@link #beginRecord()}. */
    public void endRecord() {
        if (!pendingRecord) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offsets[count] = pendingStart;
        lengths[count] = pendingLength;
        used = (short) (pendingStart + pendingLength);
        count++;
        pendingRecord = false;
    }

    /** Reads record {@code number} (1-based) into out, at most maxLen bytes. */
    public short readRecord(short number, byte[] out, short outOff, short maxLen) {
        if (number < 1 || number > count) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND); // 6A83
        }
        currentRecord = number;
        short len = lengths[(short) (number - 1)];
        short n = len < maxLen ? len : maxLen;
        Util.arrayCopyNonAtomic(pool, offsets[(short) (number - 1)], out, outOff, n);
        return n;
    }

    /**
     * Reads all records from {@code from} (1-based) to the last, concatenated
     * into out, stopping at maxLen.  Returns the number of bytes written.
     */
    public short readRecords(short from, byte[] out, short outOff, short maxLen) {
        if (from < 1 || from > count) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
        short written = 0;
        for (short n = from; n <= count && written < maxLen; n++) {
            short len = lengths[(short) (n - 1)];
            short take = (short) (len < (short) (maxLen - written) ? len : (short) (maxLen - written));
            Util.arrayCopyNonAtomic(pool, offsets[(short) (n - 1)], out, (short) (outOff + written), take);
            written += take;
            currentRecord = n;
        }
        return written;
    }

    /** True when the record {@code number} contains {@code needle} at any offset. */
    public boolean search(short number, byte[] needle, short needleOff, short needleLen,
                          short windowOffset, short windowLen) {
        if (number < 1 || number > count || needleLen == 0) {
            return false;
        }
        short len = lengths[(short) (number - 1)];
        short from = windowOffset;
        short to = windowLen == 0 ? len : (short) (windowOffset + windowLen);
        if (to > len) {
            to = len;
        }
        for (short p = from; (short) (p + needleLen) <= to; p++) {
            if (Util.arrayCompare(pool, (short) (offsets[(short) (number - 1)] + p),
                    needle, needleOff, needleLen) == 0) {
                return true;
            }
        }
        return false;
    }
}
