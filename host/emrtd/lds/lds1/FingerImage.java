package card42.host.emrtd.lds.lds1;

import card42.host.emrtd.lds.common.Cbeff;
import card42.host.emrtd.lds.common.ImageData;
import card42.host.emrtd.lds.common.LdsBytes;

/**
 * One finger record from DG3 (ICAO Doc 9303-10 §4.7.3).
 *
 * <p>Most documents carry an ISO/IEC 19794-4 finger image record; the parser
 * also accepts an ISO/IEC 19794-2 minutiae record, in which case the image is
 * null and the complete record is kept in {@link #raw} (minutiae semantics
 * are not interpreted).  Positions follow the ISO/IEC 19794-4 code: 1-5 right
 * thumb to little finger, 6-10 left thumb to little finger.
 */
public final class FingerImage {

    /** The CBEFF header of the enclosing template, or null. */
    public final Cbeff cbeff;
    /** "FIR" (image), "FMR" (minutiae) or "UNKNOWN". */
    public final String recordFormat;
    /** ISO/IEC 19794-4 finger position, or -1 when unknown. */
    public final int position;
    public final int viewCount;
    public final int viewNumber;
    /** ISO 19794-4 quality, or -1. */
    public final int quality;
    /** ISO 19794-4 impression type, or -1. */
    public final int impressionType;
    /** The encoded image, or null for a minutiae record. */
    public final ImageData image;
    /** The complete ISO record or finger block that produced this entry. */
    public final byte[] raw;

    FingerImage(Cbeff cbeff, String recordFormat, int position, int viewCount,
                int viewNumber, int quality, int impressionType, ImageData image,
                byte[] raw) {
        this.cbeff = cbeff;
        this.recordFormat = recordFormat;
        this.position = position;
        this.viewCount = viewCount;
        this.viewNumber = viewNumber;
        this.quality = quality;
        this.impressionType = impressionType;
        this.image = image;
        this.raw = LdsBytes.copy(raw);
    }

    /** A display name for the ISO/IEC 19794-4 finger position code. */
    public static String positionName(int position) {
        switch (position) {
        case 1:
            return "right thumb";
        case 2:
            return "right index";
        case 3:
            return "right middle";
        case 4:
            return "right ring";
        case 5:
            return "right little";
        case 6:
            return "left thumb";
        case 7:
            return "left index";
        case 8:
            return "left middle";
        case 9:
            return "left ring";
        case 10:
            return "left little";
        default:
            return "unknown";
        }
    }
}
