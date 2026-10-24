package card42.host.emrtd.lds.lds1;

import card42.host.emrtd.lds.common.Cbeff;
import card42.host.emrtd.lds.common.ImageData;
import card42.host.emrtd.lds.common.LdsBytes;

/**
 * One facial image from DG2 (ICAO Doc 9303-10 §4.7.2, ISO/IEC 19794-5).
 *
 * <p>It pairs the CBEFF header of the enclosing {@code 7F60} template with the
 * fields of one ISO/IEC 19794-5 facial record data block: the number of
 * feature points, the image information (type, size, colour space, quality)
 * and the encoded image.  {@code raw} is the complete ISO record that carried
 * this face, so an unknown extension can still be shown.
 */
public final class FaceImage {

    /** The CBEFF header of the enclosing biometric template, or null. */
    public final Cbeff cbeff;
    public final int featurePointCount;
    /** ISO 19794-5 face image type (0 = basic). */
    public final int faceImageType;
    /** ISO 19794-5 image data type (0 = JPEG, 1 = JPEG 2000). */
    public final int imageDataType;
    public final ImageData image;
    /** The ISO/IEC 19794-5 record that contained this facial image. */
    public final byte[] raw;

    FaceImage(Cbeff cbeff, int featurePointCount, int faceImageType, int imageDataType,
              ImageData image, byte[] raw) {
        this.cbeff = cbeff;
        this.featurePointCount = featurePointCount;
        this.faceImageType = faceImageType;
        this.imageDataType = imageDataType;
        this.image = image;
        this.raw = LdsBytes.copy(raw);
    }
}
