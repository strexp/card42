package card42.emv;

import card42.common.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* The record table of a payment instance (docs/specs/common/architecture.md §2).
 *
 * Extracted from EMVStaticData so the record storage and lookup are separate
 * from the FCI / GPO / field assembly.  A variable-length store backed by one
 * shared byte pool replaced the fixed 4x128 table, so a single
 * record may be much larger than 128 bytes (a 2048-bit certificate plus its
 * BER wrapper is ~300 bytes) and the total is only limited by the pool.
 *
 * The key is (SFI<<8)|record; 0 marks a free slot.  A record is stored verbatim
 * and, when read back, its 70 template length is normalised by the caller
 * (docs/specs/emv/personalization.md §3).
 *
 * Replacing a record reuses the old space when the new value fits; otherwise
 * the old space is abandoned and the pool is compacted on demand.  This keeps
 * the common "store once" personalization path allocation-free while still
 * handling a larger replacement.
 *
 * @author card42
 */

public class RecordStore implements ISO7816 {

    /** Maximum number of records one payment instance can hold. */
    private static final short MAX_RECORDS = (short) 8;

    /**
     * Size of the shared record pool.  Large enough for a single ~300 byte
     * record (a 2048-bit certificate and its BER wrapper) plus the smaller
     * records of the same instance (docs/specs/common/architecture.md §2, docs/specs/common/risks.md).
     */
    private static final short POOL_SIZE = (short) 1024;

    private final short[] keys = new short[MAX_RECORDS];
    private final short[] offsets = new short[MAX_RECORDS];
    private final short[] lengths = new short[MAX_RECORDS];
    private final boolean[] moved = new boolean[MAX_RECORDS];
    private final byte[] pool = new byte[POOL_SIZE];
    private short poolUsed;

    public RecordStore() {
    }

    /** Stores or replaces the record for key; throws 6A80 when it cannot fit. */
    public void put(short key, byte[] buf, short off, short len) {
        if (len < 0 || len > POOL_SIZE) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        short slot = find(key);
        if (slot >= 0) {
            if (len <= lengths[slot]) {
                // Fits in the space already allocated for this record.
                Util.arrayCopyNonAtomic(buf, off, pool, offsets[slot], len);
                lengths[slot] = len;
                return;
            }
            // Larger replacement: drop the old copy and append the new one.
            keys[slot] = 0;
            lengths[slot] = 0;
        }
        short at = allocate(len);
        slot = find(key);
        if (slot < 0) {
            slot = freeSlot();
            if (slot < 0) {
                ISOException.throwIt(SW_WRONG_DATA); // table full
            }
        }
        keys[slot] = key;
        offsets[slot] = at;
        lengths[slot] = len;
        Util.arrayCopyNonAtomic(buf, off, pool, at, len);
    }

    /**
     * Copies the record for key into dst at dstOff and returns its length, or
     * -1 when no record is stored for that key.
     */
    public short copyIfPresent(short key, byte[] dst, short dstOff) {
        short slot = find(key);
        if (slot < 0) {
            return -1;
        }
        short len = lengths[slot];
        Util.arrayCopyNonAtomic(pool, offsets[slot], dst, dstOff, len);
        return len;
    }

    /** Length of the record for key, or -1 when it is not stored. */
    public short lengthOf(short key) {
        short slot = find(key);
        return slot < 0 ? (short) -1 : lengths[slot];
    }

    /** Offset of the record for key in {@link #pool()}, or -1 when it is not stored. */
    public short offsetOf(short key) {
        short slot = find(key);
        return slot < 0 ? (short) -1 : offsets[slot];
    }

    /**
     * The persistent record pool.  A caller that has checked the record is
     * already a normalized '70' template can serve it directly from here with
     * {@code APDU.sendBytesLong} instead of copying it into the transient
     * response buffer (EMV v4.4 Book 3 §7.1).
     */
    public byte[] pool() {
        return pool;
    }

    /** Reserves len bytes in the pool, compacting first when necessary. */
    private short allocate(short len) {
        if ((short) (poolUsed + len) > POOL_SIZE) {
            compact();
        }
        if ((short) (poolUsed + len) > POOL_SIZE) {
            ISOException.throwIt(SW_WRONG_DATA); // pool full
        }
        short at = poolUsed;
        poolUsed += len;
        return at;
    }

    /**
     * Packs the live records to the front of the pool in ascending physical
     * order.  Records are disjoint and the destinations never run past the
     * source of a record that has not been moved yet, so no live record is
     * clobbered (docs/specs/common/architecture.md §2).
     */
    private void compact() {
        short remaining = 0;
        for (short i = 0; i < MAX_RECORDS; i++) {
            moved[i] = false;
            if (keys[i] != 0) {
                remaining++;
            }
        }
        short write = 0;
        while (remaining > 0) {
            // Pick the not-yet-moved record with the smallest source offset.
            short best = -1;
            for (short i = 0; i < MAX_RECORDS; i++) {
                if (keys[i] != 0 && !moved[i]
                        && (best < 0 || offsets[i] < offsets[best])) {
                    best = i;
                }
            }
            moved[best] = true;
            short len = lengths[best];
            if (offsets[best] != write) {
                // arrayCopy behaves like memmove when src/dst overlap.
                Util.arrayCopyNonAtomic(pool, offsets[best], pool, write, len);
                offsets[best] = write;
            }
            write += len;
            remaining--;
        }
        poolUsed = write;
    }

    private short find(short key) {
        for (short i = 0; i < MAX_RECORDS; i++) {
            if (keys[i] == key) {
                return i;
            }
        }
        return -1;
    }

    private short freeSlot() {
        for (short i = 0; i < MAX_RECORDS; i++) {
            if (keys[i] == 0) {
                return i;
            }
        }
        return -1;
    }
}
