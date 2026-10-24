package card42.host.emrtd.lds.lds1;

import card42.host.emrtd.lds.common.Cbeff;
import card42.host.emrtd.lds.common.ImageData;
import card42.host.emrtd.lds.common.LdsBytes;

/**
 * One iris image from DG4 (ICAO Doc 9303-10 §4.7.4, ISO/IEC 19794-6).
 *
 * <p>The eye position comes from the ISO 19794-6 biometric subtype: 0
 * undefined, 1 right, 2 left.  The encoded image is kept as-is; JPEG-LS and
 * JPEG 2000 are not decoded by card42.
 */
public final class IrisImage {

    /** The CBEFF header of the enclosing template, or null. */
    public final Cbeff cbeff;
    /** ISO 19794-6 subtype: 0 undefined, 1 right eye, 2 left eye. */
    public final int eyePosition;
    public final int imageNumber;
    public final int quality;
    public final int rotationAngle;
    public final int rotationAngleUncertainty;
    public final ImageData image;
    /** The ISO 19794-6 image block that produced this entry. */
    public final byte[] raw;

    IrisImage(Cbeff cbeff, int eyePosition, int imageNumber, int quality,
              int rotationAngle, int rotationAngleUncertainty, ImageData image, byte[] raw) {
        this.cbeff = cbeff;
        this.eyePosition = eyePosition;
        this.imageNumber = imageNumber;
        this.quality = quality;
        this.rotationAngle = rotationAngle;
        this.rotationAngleUncertainty = rotationAngleUncertainty;
        this.image = image;
        this.raw = LdsBytes.copy(raw);
    }

    /** A display name for the ISO/IEC 19794-6 eye position. */
    public static String eyeName(int eyePosition) {
        switch (eyePosition) {
        case 1:
            return "right";
        case 2:
            return "left";
        default:
            return "unknown";
        }
    }
}
