package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* The LDS1 elementary-file set of one eMRTD application (ICAO Doc 9303-10 §5).
 *
 * The file system is flat: DG1..DG16, EF.SOD, EF.COM and EF.CVCA are addressed
 * by FID with SELECT FILE (P1=02, P2=0C) and read with READ BINARY.  Only one
 * EF is selected at a time; READ BINARY always reads the selected file.
 *
 * The capacities are the personalization budgets; a file only occupies the
 * bytes actually written (the backing pages are allocated on first use), so an
 * unused or small EF costs almost nothing.  A larger DG2 is bounded by
 * {@link #DG2_CAPACITY}; a write past a capacity is refused at personalization
 * time.
 *
 * @author card42
 */

public final class LdsFileSystem {

    /**
     * DG2 (encoded face) personalization capacity.  The face image is the only
     * LDS1 file that is realistically large (Doc 9303-10 §4.7.2, Doc 9303-5); it
     * is streamed into a paged store, so this is a budget, not an allocation.
     * The 15-bit READ BINARY offset bounds any EF at 32767.
     */
    public static final short DG2_CAPACITY = (short) 16384;

    /**
     * EF.SOD personalization capacity.  EF.SOD embeds the Document Signer
     * certificate (and its chain), so a larger DSC certificate can push the
     * file well past the original 2048-byte budget; it is paged, so this is an
     * upper bound that costs nothing until written.
     */
    public static final short SOD_CAPACITY = (short) 4096;

    private final LdsFile[] files;
    private LdsFile selected;

    public LdsFileSystem() {
        files = new LdsFile[] {
                new LdsFile(EmrtdTags.FID_DG1, (short) 128),
                new LdsFile(EmrtdTags.FID_DG2, DG2_CAPACITY),
                new LdsFile(EmrtdTags.FID_DG3, (short) 256),
                new LdsFile(EmrtdTags.FID_DG4, (short) 256),
                new LdsFile(EmrtdTags.FID_DG5, (short) 256),
                new LdsFile(EmrtdTags.FID_DG6, (short) 256),
                new LdsFile(EmrtdTags.FID_DG7, (short) 256),
                new LdsFile(EmrtdTags.FID_DG8, (short) 256),
                new LdsFile(EmrtdTags.FID_DG9, (short) 256),
                new LdsFile(EmrtdTags.FID_DG10, (short) 256),
                new LdsFile(EmrtdTags.FID_DG11, (short) 256),
                new LdsFile(EmrtdTags.FID_DG12, (short) 256),
                new LdsFile(EmrtdTags.FID_DG13, (short) 256),
                new LdsFile(EmrtdTags.FID_DG14, (short) 256),
                new LdsFile(EmrtdTags.FID_DG15, (short) 512),
                new LdsFile(EmrtdTags.FID_DG16, (short) 256),
                new LdsFile(EmrtdTags.FID_CARD_ACCESS, (short) 256),
                new LdsFile(EmrtdTags.FID_SOD, SOD_CAPACITY),
                new LdsFile(EmrtdTags.FID_COM, (short) 64),
        };
        selected = null;
    }

    /** Selects the EF with the given FID; 6A82 when it is not an LDS1 file. */
    public void select(short fid) {
        for (short i = 0; i < files.length; i++) {
            if (files[i].getFid() == fid) {
                selected = files[i];
                return;
            }
        }
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    /**
     * Selects the master file (ISO/IEC 7816-4 §7.1.1): the LDS1 file set is
     * flat, so this only clears the current EF.  It lets a reader read
     * EF.CardAccess at the MF level (Doc 9303-10 §3.11.3) before selecting the
     * eMRTD application: {@code SELECT MF} succeeds and the following
     * {@code SELECT 011C} selects EF.CardAccess as usual.
     */
    public void selectMf() {
        selected = null;
    }

    /** The currently selected EF, or null when none was selected. */
    public LdsFile getSelected() {
        return selected;
    }

    /** The EF with the given FID, or null. */
    public LdsFile get(short fid) {
        for (short i = 0; i < files.length; i++) {
            if (files[i].getFid() == fid) {
                return files[i];
            }
        }
        return null;
    }

    /**
     * The EF with the given short EF identifier, or null.  LDS1 file
     * identifiers are {@code 0x01 || SFI} (Doc 9303-10 §4.7), so the SFI is the
     * low 5 bits of the FID.  Used by the short-EF-identifier READ BINARY form.
     */
    public LdsFile getBySfi(short sfi) {
        for (short i = 0; i < files.length; i++) {
            if ((short) (files[i].getFid() & EmrtdTags.SFI_MASK) == sfi) {
                return files[i];
            }
        }
        return null;
    }

    /**
     * Selects the EF with the given short EF identifier and makes it the current
     * EF (ISO/IEC 7816-4 §6.1.2: a READ BINARY with a valid SFI sets that file
     * as current).  Returns the EF, or null when the SFI is unknown.
     */
    public LdsFile selectBySfi(short sfi) {
        LdsFile file = getBySfi(sfi);
        if (file != null) {
            selected = file;
        }
        return file;
    }
}
