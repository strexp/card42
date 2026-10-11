package card42.emv;

/* Keyed store for the personalized directory records of DirectoryApplet
 * (EMV v4.4 Book 1 §12.2.3).
 *
 * The directory file may live at any SFI 1-10 and hold more than one record, so
 * the records are keyed by DGI (SFI<<8)|record instead of a single override
 * buffer.  The store is deliberately small: a directory file holds a handful of
 * short 70 { 61 { ... } } records.  A record is stored verbatim and served
 * straight from the pool.
 *
 * The keyed storage, lookup and record replacement are the shared
 * {@link RecordStore} logic; this class only fixes the small directory sizes
 * (4 records in a 256-byte pool).
 *
 * @author card42
 */

public class DirectoryRecords extends RecordStore {

    public DirectoryRecords() {
        super((short) 4, (short) 256);
    }
}
