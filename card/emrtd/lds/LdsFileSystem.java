package card42.emrtd;

import card42.common.TransientBuffers;

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

    /**
     * SFI (0-31) to {@code files} index plus one, or 0 when the SFI is not an
     * LDS1 file.  Built once from the file table so the short-EF-identifier
     * READ BINARY hot path (the mandatory eMRTD form) is an O(1) lookup instead
     * of a linear scan of all 19 files (docs/specs/common/risks.md §2).
     */
    private final short[] bySfi;

    /**
     * Index of the current EF plus one (0 = no current EF).  RAM (transient
     * CLEAR_ON_DESELECT) so a READ BINARY that switches EF does not write
     * EEPROM; the platform clears it when the applet context is deselected, so
     * the current EF does not leak into the next session.
     */
    private final short[] selection;

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
                new LdsFile(EmrtdTags.FID_CVCA),
                new LdsFile(EmrtdTags.FID_SOD),
                new LdsFile(EmrtdTags.FID_COM),
        };
        bySfi = new short[32];
        for (short i = 0; i < files.length; i++) {
            bySfi[(short) (files[i].getFid() & EmrtdTags.SFI_MASK)] = (short) (i + 1);
        }
        selection = TransientBuffers.makeShortArray((short) 1);
    }

    /** Selects the EF with the given FID; 6A82 when it is not an LDS1 file. */
    public void select(short fid) {
        for (short i = 0; i < files.length; i++) {
            if (files[i].getFid() == fid) {
                selection[0] = (short) (i + 1);
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
        selection[0] = 0;
    }

    /** The currently selected EF, or null when none was selected. */
    public LdsFile getSelected() {
        short v = selection[0];
        return v == 0 ? null : files[(short) (v - 1)];
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
        short v = sfiLookup(sfi);
        return v == 0 ? null : files[(short) (v - 1)];
    }

    /**
     * Selects the EF with the given short EF identifier and makes it the current
     * EF (ISO/IEC 7816-4 §6.1.2: a READ BINARY with a valid SFI sets that file
     * as current).  Returns the EF, or null when the SFI is unknown.
     */
    public LdsFile selectBySfi(short sfi) {
        short v = sfiLookup(sfi);
        if (v == 0) {
            return null;
        }
        selection[0] = v;
        return files[(short) (v - 1)];
    }

    /** The SFI table entry (files index plus one), or 0 for an out-of-range SFI. */
    private short sfiLookup(short sfi) {
        if ((sfi & ~EmrtdTags.SFI_MASK) != 0) {
            return 0;
        }
        return bySfi[sfi];
    }
}
