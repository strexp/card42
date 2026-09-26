package card42.emv;

import card42.common.*;

import javacard.framework.ISOException;
import javacard.framework.Util;

/* Keyed store for the personalized directory records of DirectoryApplet
 * (EMV v4.4 Book 1 §12.2.3).
 *
 * The directory file may live at any SFI 1-10 and hold more than one record, so
 * the records are keyed by DGI (SFI<<8)|record instead of a single override
 * buffer.  The store is deliberately small: a directory file holds a handful of
 * short 70 { 61 { ... } } records.  A record is stored verbatim and served
 * straight from the pool.
 *
 * Extracted from DirectoryApplet so the keyed storage can be unit-tested on the
 * pure JVM.
 *
 * @author card42
 */

public class DirectoryRecords {

	/** Maximum number of records one directory file can hold. */
	private static final short MAX_RECORDS = (short) 4;

	/** Shared record pool: four short directory records fit comfortably. */
	private static final short POOL_SIZE = (short) 256;

	private final short[] keys = new short[MAX_RECORDS];
	private final short[] offsets = new short[MAX_RECORDS];
	private final short[] lengths = new short[MAX_RECORDS];
	private final byte[] pool = new byte[POOL_SIZE];
	private short poolUsed;

	public DirectoryRecords() {
	}

	/**
	 * Stores or replaces the record for key = (SFI<<8)|record.  A replacement
	 * that fits reuses the old pool space; otherwise the record is appended.
	 * Throws 6A80 when the record table or the pool is full.
	 */
	public void put(short key, byte[] buf, short off, short len) {
		if (key == (short) 0) {
			ISOException.throwIt((short) 0x6A80);
		}
		short slot = find(key);
		if (slot >= 0 && len <= lengths[slot]) {
			Util.arrayCopyNonAtomic(buf, off, pool, offsets[slot], len);
			lengths[slot] = len;
			return;
		}
		if (slot < 0) {
			for (short i = 0; i < MAX_RECORDS; i++) {
				if (keys[i] == (short) 0) {
					slot = i;
					break;
				}
			}
		}
		if (slot < 0 || (short) (poolUsed + len) > POOL_SIZE) {
			ISOException.throwIt((short) 0x6A80);
		}
		keys[slot] = key;
		offsets[slot] = poolUsed;
		lengths[slot] = len;
		Util.arrayCopyNonAtomic(buf, off, pool, poolUsed, len);
		poolUsed += len;
	}

	/** The offset of the record for key in {@link #pool()}, or -1. */
	public short offsetOf(short key) {
		short slot = find(key);
		return slot < 0 ? (short) -1 : offsets[slot];
	}

	/** The length of the record for key, or -1. */
	public short lengthOf(short key) {
		short slot = find(key);
		return slot < 0 ? (short) -1 : lengths[slot];
	}

	/** The backing pool; a record is served from offsetOf(key)/lengthOf(key). */
	public byte[] pool() {
		return pool;
	}

	/** Removes every record (personalization reset). */
	public void reset() {
		for (short i = 0; i < MAX_RECORDS; i++) {
			keys[i] = 0;
			lengths[i] = 0;
		}
		poolUsed = 0;
	}

	/** The slot of the record stored for key, or -1. */
	private short find(short key) {
		for (short i = 0; i < MAX_RECORDS; i++) {
			if (keys[i] == key) {
				return i;
			}
		}
		return (short) -1;
	}
}
