package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/* The LDS1 elementary-file set of one eMRTD application (ICAO Doc 9303-10 §5).
 *
 * The file system is flat: DG1..DG16, EF.SOD, EF.COM and EF.CVCA are addressed
 * by FID with SELECT FILE (P1=02, P2=0C) and read with READ BINARY.  Only one
 * EF is selected at a time; READ BINARY always reads the selected file.
 *
 * The files carry no fixed per-file budget: each grows on demand up to the
 * protocol maximum {@link EmrtdTags#MAX_EF_BYTES} and only occupies the bytes
 * actually written (the backing pages are allocated on first use), so an unused
 * or small EF costs nothing.  The streaming personalizer declares each file's
 * final size from its DGI length before the value arrives (docs/specs/emrtd/
 * emrtd.md §2/§8).
 *
 * @author card42
 */

public final class LdsFileSystem {

    private final LdsFile[] files;
    private LdsFile selected;

    public LdsFileSystem() {
        files = new LdsFile[] {
                new LdsFile(EmrtdTags.FID_DG1),
                new LdsFile(EmrtdTags.FID_DG2),
                new LdsFile(EmrtdTags.FID_DG3),
                new LdsFile(EmrtdTags.FID_DG4),
                new LdsFile(EmrtdTags.FID_DG5),
                new LdsFile(EmrtdTags.FID_DG6),
                new LdsFile(EmrtdTags.FID_DG7),
                new LdsFile(EmrtdTags.FID_DG8),
                new LdsFile(EmrtdTags.FID_DG9),
                new LdsFile(EmrtdTags.FID_DG10),
                new LdsFile(EmrtdTags.FID_DG11),
                new LdsFile(EmrtdTags.FID_DG12),
                new LdsFile(EmrtdTags.FID_DG13),
                new LdsFile(EmrtdTags.FID_DG14),
                new LdsFile(EmrtdTags.FID_DG15),
                new LdsFile(EmrtdTags.FID_DG16),
                new LdsFile(EmrtdTags.FID_CARD_ACCESS),
                new LdsFile(EmrtdTags.FID_SOD),
                new LdsFile(EmrtdTags.FID_COM),
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
