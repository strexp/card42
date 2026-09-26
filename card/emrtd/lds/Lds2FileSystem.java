package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* The elementary-file set of one LDS2 application DF (Doc 9303-10 §5).
 *
 * Each LDS2 application (Travel Records, Visa Records, Additional Biometrics)
 * owns its own DF with a small set of transparent EFs (for Additional
 * Biometrics, the biometric EFs) and record EFs (EF.Certificates plus the
 * travel/visa record files).  SELECT FILE addresses any of them by FID;
 * READ BINARY serves the selected transparent EF and READ RECORD the selected
 * record EF.  EF.CardAccess/EF.CardSecurity are master-file files, not part of
 * a DF: they live in {@link LdsMfStore} and are shared by every application.
 *
 * The capacities are the personalization budgets; a write past them is refused
 * with 6A84.
 *
 * @author card42
 */

public final class Lds2FileSystem {

    /** Additional Biometrics transparent EF (Doc 9303-10 §5.3.3, FID 0201). */
    public static final short FID_BIOMETRIC = EmrtdTags.FID_BIOMETRICS;

    private final Lds2TransparentFile[] transparent;
    private final Lds2RecordFile[] records;
    private Lds2TransparentFile selectedTransparent;
    private Lds2RecordFile selectedRecord;

    private Lds2FileSystem(Lds2TransparentFile[] transparent, Lds2RecordFile[] records) {
        this.transparent = transparent;
        this.records = records;
        this.selectedTransparent = null;
        this.selectedRecord = null;
    }

    /** Travel Records DF: EF.Certificates, EF.EntryRecords, EF.ExitRecords. */
    public static Lds2FileSystem travel() {
        return new Lds2FileSystem(
                new Lds2TransparentFile[0],
                new Lds2RecordFile[] {
                    new Lds2RecordFile(EmrtdTags.FID_CERTIFICATES, (short) 1024, (short) 254, (short) 900),
                    new Lds2RecordFile(EmrtdTags.FID_RECORDS, (short) 1024, (short) 254, (short) 256),
                    new Lds2RecordFile(EmrtdTags.FID_EXIT_RECORDS, (short) 1024, (short) 254, (short) 256) });
    }

    /** Visa Records DF: EF.Certificates, EF.VisaRecords (0103, Doc 9303-10 §5.2). */
    public static Lds2FileSystem visa() {
        return new Lds2FileSystem(
                new Lds2TransparentFile[0],
                new Lds2RecordFile[] {
                    new Lds2RecordFile(EmrtdTags.FID_CERTIFICATES, (short) 1024, (short) 254, (short) 900),
                    new Lds2RecordFile(EmrtdTags.FID_VISA_RECORDS, (short) 1024, (short) 254, (short) 256) });
    }

    /**
     * Additional Biometrics DF: EF.Certificates (MANDATORY, 64 records,
     * Doc 9303-10 §5.3.2) and EF.Biometrics1-64 (FIDs 0201-0240, Short EF
     * Identifier N/A, §5.3.3).  Each biometric EF is lazy and modelled
     * separately, matching the FID range.
     */
    public static Lds2FileSystem biometrics() {
        Lds2TransparentFile[] files = new Lds2TransparentFile[64];
        for (short i = 0; i < (short) 64; i++) {
            files[i] = new Lds2TransparentFile(
                    (short) (EmrtdTags.FID_BIOMETRICS + i), (short) 1024, false);
        }
        return new Lds2FileSystem(files,
                new Lds2RecordFile[] {
                    new Lds2RecordFile(EmrtdTags.FID_CERTIFICATES, (short) 1024, (short) 64, (short) 900) });
    }

    /** Selects a transparent or record EF by FID; 6A82 when unknown. */
    public void select(short fid) {
        for (short i = 0; i < transparent.length; i++) {
            if (transparent[i].getFid() == fid) {
                selectedTransparent = transparent[i];
                selectedRecord = null;
                return;
            }
        }
        for (short i = 0; i < records.length; i++) {
            if (records[i].getFid() == fid) {
                selectedRecord = records[i];
                selectedTransparent = null;
                return;
            }
        }
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    public Lds2TransparentFile getSelectedTransparent() {
        return selectedTransparent;
    }

    public Lds2RecordFile getSelectedRecord() {
        return selectedRecord;
    }

    /** The transparent EF with the given FID, or null. */
    public Lds2TransparentFile transparent(short fid) {
        for (short i = 0; i < transparent.length; i++) {
            if (transparent[i].getFid() == fid) {
                return transparent[i];
            }
        }
        return null;
    }

    /** The record EF with the given FID, or null. */
    public Lds2RecordFile record(short fid) {
        for (short i = 0; i < records.length; i++) {
            if (records[i].getFid() == fid) {
                return records[i];
            }
        }
        return null;
    }

    /**
     * The record EF with the given short EF identifier, or null.  LDS2 file
     * identifiers are {@code 0x01 || SFI} (Doc 9303-10 §5.1), so the SFI is the
     * low byte of the FID.
     */
    public Lds2RecordFile recordBySfi(short sfi) {
        for (short i = 0; i < records.length; i++) {
            if ((short) (records[i].getFid() & 0x1F) == sfi) {
                return records[i];
            }
        }
        return null;
    }

    /** The transparent EF with the given short EF identifier, or null. */
    public Lds2TransparentFile transparentBySfi(short sfi) {
        for (short i = 0; i < transparent.length; i++) {
            // EF.Biometrics has no Short EF Identifier (Doc 9303-10 §5.3.3).
            if (transparent[i].isSfiAddressable()
                    && (short) (transparent[i].getFid() & 0x1F) == sfi) {
                return transparent[i];
            }
        }
        return null;
    }

    /** Makes a record EF the current one (FMM side effect). */
    public void selectRecord(Lds2RecordFile file) {
        selectedRecord = file;
        selectedTransparent = null;
    }

    /** Makes a transparent EF the current one. */
    public void selectTransparent(Lds2TransparentFile file) {
        selectedTransparent = file;
        selectedRecord = null;
    }

    /** Clears the current EF selection (an MF file became the current EF). */
    public void clearSelection() {
        selectedTransparent = null;
        selectedRecord = null;
    }
}
