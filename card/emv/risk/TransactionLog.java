package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/* The card transaction log (EMV v4.4 Book 3 Annex D4).
 *
 * The log is a cyclic file: record #1 is the most recent transaction, record #2
 * the one before it, and so on.  It is located by the Log Entry data element
 * (tag 9F4D) placed in the FCI, which carries the SFI (11-30) and the maximum
 * number of records; the records themselves are read with READ RECORD and are
 * the plain concatenation of the values named by the Log Format (tag 9F4F, read
 * with GET DATA).  A log record must not be listed in the AFL and must not be
 * wrapped in a '70' template.
 *
 * Engineering notes:
 *
 *   - The file is index-free: there is no single "write pointer" cell that
 *     would be rewritten on every transaction.  Each slot carries its own
 *     16-bit sequence number and a one-byte checksum, both stored beside the
 *     record.  The next record is written into the slot with the smallest
 *     sequence (the oldest) and gets max(sequence)+1, so the newest record is
 *     the slot with the largest sequence.
 *   - A record and its sequence/checksum are committed in a single JCSystem
 *     transaction, so a torn write cannot leave a half-written entry.
 *   - The log is persistent and, per EMV v4.4 Book 3 Annex D4, stays readable while the
 *     application is blocked (the invalidated / APPLICATION BLOCK state); it is
 *     only refused when the whole card is CARD BLOCKed.
 *
 * @author card42
 */

public class TransactionLog implements ISO7816 {

    /** SFI of the cyclic log file; EMV v4.4 Book 3 Annex D4 requires 11..30. */
    public static final short SFI = (short) 0x0F; // 15

    /** Maximum number of records the file can hold (the Log Entry count). */
    public static final short CAPACITY = (short) 8;

    /** Largest log record the fixed slots can hold. */
    private static final short MAX_RECORD = (short) 32;

    /** Highest sequence before the ring is renumbered to avoid overflow
     * (EMV v4.4 Book 3 Annex D4). */
    private static final short MAX_SEQUENCE = (short) 0x7FFE;

    /** Record slots: CAPACITY records of MAX_RECORD bytes each. */
    private final byte[] records = new byte[(short) (CAPACITY * MAX_RECORD)];

    /** Per-slot sequence number; 0 marks an empty slot (EMV v4.4 Book 3 Annex D4). */
    private final short[] sequence = new short[CAPACITY];

    /** Per-slot XOR checksum over the record bytes. */
    private final byte[] checksum = new byte[CAPACITY];

    /** Log Format definition (tag+length entries) and its encoded length. */
    private final byte[] format = new byte[(short) 32];
    private short formatLength;

    /** Total value length of the format, i.e. the length of one record. */
    private short recordLength;

    /** Reused DOL cursor so writing a record allocates nothing. */
    private final DolReader dol = new DolReader();

    public TransactionLog() {
        setFormat(Defaults.LOG_FORMAT, (short) 0, (short) Defaults.LOG_FORMAT.length);
    }

    /**
     * Sets the log format (the value of EMV CPS v2.0 Annex A DGI '3000' tag 9F4F) and derives the
     * record length from it.  A malformed or oversized format is rejected with
     * 6A80 so a bad personalization cannot corrupt the log.
     */
    public void setFormat(byte[] buf, short off, short len) {
        if (len <= 0) {
            return; // no personalized format: keep the default
        }
        if (len > format.length) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short total = dol.reset(buf, off, len).totalDataLength();
        if (total <= 0 || total > MAX_RECORD) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        Util.arrayCopyNonAtomic(buf, off, format, (short) 0, len);
        formatLength = len;
        recordLength = total;
    }

    public short getSfi() {
        return SFI;
    }

    public byte[] getFormat() {
        return format;
    }

    public short getFormatLength() {
        return formatLength;
    }

    public short getRecordLength() {
        return recordLength;
    }

    public short getCapacity() {
        return CAPACITY;
    }

    /** Number of records currently stored. */
    public short count() {
        short n = 0;
        for (short i = 0; i < CAPACITY; i++) {
            if (sequence[i] != 0) {
                n++;
            }
        }
        return n;
    }

    /**
     * Builds one log record for the finalized transaction and stores it as the
     * newest entry.  terminalData/terminalLength are the first GENERATE AC's
     * CDOL1 data, from which the terminal-sourced log fields are taken; the
     * card-sourced fields (ATC, CID, IAD) come from the state / static data.
     */
    public void write(byte cid, EMVProtocolState state, EMVStaticData data,
                      byte[] terminalData, short terminalLength) {
        // The newest sequence, and the oldest slot to overwrite (EMV v4.4 Book 3 Annex D4).
        short max = 0;
        for (short i = 0; i < CAPACITY; i++) {
            if (sequence[i] > max) {
                max = sequence[i];
            }
        }
        if (max >= MAX_SEQUENCE) {
            // Renumber the live slots consecutively 1..n, preserving their
            // order, so the ring stays consistent: the oldest live record gets
            // sequence 1 and the newest sequence n, and readRecord() can still
            // order all of them (EMV v4.4 Book 3 Annex D4).
            short next = 1;
            short last = 0;
            for (short rank = 0; rank < CAPACITY; rank++) {
                short best = -1;
                short bestSeq = (short) (MAX_SEQUENCE + 1);
                for (short i = 0; i < CAPACITY; i++) {
                    short seq = sequence[i];
                    if (seq > last && seq < bestSeq) {
                        bestSeq = seq;
                        best = i;
                    }
                }
                if (best < 0) {
                    break;
                }
                sequence[best] = next;
                last = bestSeq;
                next++;
            }
            max = (short) (next - 1);
        }
        short target = 0;
        short oldest = MAX_SEQUENCE;
        for (short i = 0; i < CAPACITY; i++) {
            if (sequence[i] < oldest) {
                oldest = sequence[i];
                target = i;
            }
        }

        short base = (short) (target * MAX_RECORD);
        JCSystem.beginTransaction();
        short p = base;
        DolReader reader = dol.reset(format, (short) 0, formatLength);
        while (reader.hasNext()) {
            reader.next();
            short tag = reader.tag();
            short len = reader.valueLength();
            // Each field is stored byte by byte and only where the stored value
            // differs: the previous blanket zero-fill wrote every byte of the
            // record on each transaction, and a same-value byte may still cost
            // an EEPROM programming cycle.
            if (tag == TlvTags.TAG_ATC) {
                // 2-byte big-endian ATC (EMV v4.4 Book 3 Annex D4).
                short atc = state.getATC();
                storeByte(records, p, len, (short) 0, (byte) (atc >> 8));
                storeByte(records, p, len, (short) 1, (byte) atc);
                storeZero(records, p, (short) 2, len);
            } else if (tag == TlvTags.TAG_CID) {
                storeByte(records, p, len, (short) 0, cid);
                storeZero(records, p, (short) 1, len);
            } else if (tag == TlvTags.TAG_IAD) {
                short n = data.getIadLength() < len ? data.getIadLength() : len;
                storeBytes(records, p, len, data.getIad(), (short) 0, n);
            } else {
                short off = data.getCDOL1ValueOffset(tag);
                short l = data.getCDOL1ValueLength(tag);
                if (off >= 0 && l > 0 && (short) (off + l) <= terminalLength) {
                    short n = l < len ? l : len;
                    storeBytes(records, p, len, terminalData, off, n);
                } else {
                    // No value for this tag: the field stays zero.
                    storeZero(records, p, (short) 0, len);
                }
            }
            p += len;
        }
        byte sum = 0;
        for (short k = 0; k < recordLength; k++) {
            sum ^= records[(short) (base + k)];
        }
        sequence[target] = (short) (max + 1);
        checksum[target] = sum;
        JCSystem.commitTransaction();
    }

    /**
     * Stores the byte at {@code records[p + k]} of a {@code len}-byte DOL field
     * when, and only when, it differs from what is already there; k beyond the
     * field is ignored.
     */
    private static void storeByte(byte[] records, short p, short len, short k, byte value) {
        if (k >= len) {
            return;
        }
        short idx = (short) (p + k);
        if (records[idx] != value) {
            records[idx] = value;
        }
    }

    /**
     * Zero-fills {@code records[p + from .. p + len)} for the bytes a field
     * value does not cover, writing only the bytes that are not zero yet.
     */
    private static void storeZero(byte[] records, short p, short from, short len) {
        for (short k = from; k < len; k++) {
            short idx = (short) (p + k);
            if (records[idx] != 0) {
                records[idx] = 0;
            }
        }
    }

    /**
     * Fills the {@code len}-byte DOL field at {@code records[p]} with the first
     * {@code n} bytes of {@code src[srcOff..)} followed by zero padding,
     * writing only the bytes whose value differs, since a same-value byte may
     * still cost an EEPROM programming cycle.
     */
    private static void storeBytes(byte[] records, short p, short len,
            byte[] src, short srcOff, short n) {
        for (short k = 0; k < len; k++) {
            byte want = k < n ? src[(short) (srcOff + k)] : (byte) 0;
            short idx = (short) (p + k);
            if (records[idx] != want) {
                records[idx] = want;
            }
        }
    }

    /**
     * Copies the rec-th newest record into out/outOff and returns its length, or
     * -1 when there is no such record (a missing record, reported as 6A83 by
     * the caller).  A slot whose checksum does not match is treated as empty.
     */
    public short readRecord(short rec, byte[] out, short outOff) {
        if (rec < 1 || rec > count()) {
            return -1;
        }
        short currentMax = (short) (MAX_SEQUENCE + 1);
        short slot = -1;
        for (short k = 0; k < rec; k++) {
            short best = -1;
            short bestSeq = -1;
            for (short i = 0; i < CAPACITY; i++) {
                short seq = sequence[i];
                if (seq != 0 && seq < currentMax && seq > bestSeq) {
                    bestSeq = seq;
                    best = i;
                }
            }
            if (best < 0) {
                return -1;
            }
            currentMax = bestSeq;
            slot = best;
        }

        short base = (short) (slot * MAX_RECORD);
        byte sum = 0;
        for (short k = 0; k < recordLength; k++) {
            sum ^= records[(short) (base + k)];
        }
        if (sum != checksum[slot]) {
            return -1;
        }
        Util.arrayCopyNonAtomic(records, base, out, outOff, recordLength);
        return recordLength;
    }
}
