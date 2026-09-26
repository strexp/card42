package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* LDS2 personalization: applies the DGI sequence to an LDS2 file system
 * (Doc 9303-10 §5).
 *
 * The DGI number is the target file identifier for transparent EFs
 * (EF.CardAccess 011C, EF.CardSecurity 011D, Additional Biometrics 0101) and
 * {@code 0x7000 | FID} for an appended record of a record EF
 * (EF.Certificates 011A, EF.EntryRecords/VisaRecords 0101, EF.ExitRecords 0102).
 * The positive {@code 0x7000} marker keeps the DGI a positive short, which the
 * Java Card converter handles without sign-extension surprises.
 *
 * The project DGIs FF03 (Chip Authentication static P-256 scalar) and FF04
 * (PACE key seed) carry the key material that makes the Chip Authentication /
 * PACE advertised by the LDS2 EF.CardAccess usable.
 *
 * Values are streamed in across the STORE DATA blocks ({@link DgiStream}):
 * transparent files append into their paged store and records append straight
 * into the record pool, so no value is buffered whole.
 *
 * @author card42
 */

public final class Lds2Perso extends DgiStream.Sink {

    /** Bits marking a DGI as "append one record" rather than "set a transparent EF". */
    private static final short DGI_RECORD = (short) 0x7000;
    private static final short DGI_RECORD_MASK = (short) 0x7000;
    private static final short DGI_RECORD_FID_MASK = (short) 0x0FFF;

    /** Largest key-DGI value: the 32-byte CA scalar (PACE seed is 20). */
    private static final short SCRATCH_SIZE = (short) 64;

    private static final byte MODE_NONE = 0;
    private static final byte MODE_MF = 1;
    private static final byte MODE_RECORD = 2;
    private static final byte MODE_TRANSPARENT = 3;
    private static final byte MODE_CA = 4;
    private static final byte MODE_PACE = 5;

    private final Lds2FileSystem files;
    private final ChipAuth chipAuth;
    private final PaceSeedSink pace;
    private final DgiStream stream;

    private final byte[] scratch = new byte[SCRATCH_SIZE];
    private short scratchLen;
    private byte mode;
    private Lds2TransparentFile currentFile;
    private Lds2RecordFile currentRecord;

    public Lds2Perso(Lds2FileSystem files, ChipAuth chipAuth, PaceSeedSink pace) {
        this.files = files;
        this.chipAuth = chipAuth;
        this.pace = pace;
        this.stream = new DgiStream(this);
    }

    /** Starts a new personalization sequence (the LDS2 files persist). */
    public void reset() {
        stream.reset();
    }

    /** Feeds one STORE DATA payload (may span several DGIs). */
    public void feed(byte[] buf, short off, short len) {
        stream.feed(buf, off, len);
    }

    /** Applies the completion checks after the last STORE DATA block. */
    public void finish() {
        stream.finish();
    }

    /** Applies a complete DGI sequence in one call (unit tests / callers). */
    public void apply(byte[] buf, short off, short len) {
        stream.reset();
        stream.feed(buf, off, len);
        stream.finish();
    }

    // --- DgiStream.Sink ------------------------------------------------------

    public void onReset() {
        mode = MODE_NONE;
        scratchLen = 0;
        currentFile = null;
        currentRecord = null;
    }

    public void onBeginDgi(short dgi) {
        scratchLen = 0;
        if (dgi == EmrtdTags.DGI_CA_KEY) {
            mode = MODE_CA;
        } else if (dgi == EmrtdTags.DGI_PACE_SEED) {
            mode = MODE_PACE;
        } else if ((dgi & DGI_RECORD_MASK) == DGI_RECORD) {
            short fid = (short) (dgi & DGI_RECORD_FID_MASK);
            Lds2RecordFile file = files.record(fid);
            if (file == null) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            mode = MODE_RECORD;
            currentRecord = file;
            file.beginRecord();
        } else if (dgi == EmrtdTags.FID_CARD_ACCESS
                || dgi == EmrtdTags.FID_CARD_SECURITY) {
            // Master-file files, shared by every application (Doc 9303-10
            // §3.11.3/§3.11.4).
            mode = MODE_MF;
            currentFile = LdsMfStore.file(dgi);
            currentFile.beginSet();
        } else {
            Lds2TransparentFile file = files.transparent(dgi);
            if (file == null) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            mode = MODE_TRANSPARENT;
            currentFile = file;
            file.beginSet();
        }
    }

    public void onData(byte[] buf, short off, short len) {
        if (mode == MODE_RECORD) {
            currentRecord.appendChunk(buf, off, len);
        } else if (mode == MODE_MF || mode == MODE_TRANSPARENT) {
            currentFile.append(buf, off, len);
        } else {
            if (scratchLen > SCRATCH_SIZE || len > (short) (SCRATCH_SIZE - scratchLen)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            Util.arrayCopyNonAtomic(buf, off, scratch, scratchLen, len);
            scratchLen = (short) (scratchLen + len);
        }
    }

    public void onEndDgi() {
        if (mode == MODE_CA) {
            chipAuth.setPrivateKey(scratch, (short) 0, scratchLen);
        } else if (mode == MODE_PACE) {
            pace.setSeed(scratch, (short) 0, scratchLen);
        } else if (mode == MODE_RECORD) {
            currentRecord.endRecord();
        }
        mode = MODE_NONE;
        scratchLen = 0;
    }

    // onFinish is the Sink no-op: the LDS2 files carry no COM-style index.
}
