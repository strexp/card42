package card42.host.emrtd.lds.common;

/**
 * An image carried by a data group: the encoded bytes plus the metadata from
 * the surrounding ISO/IEC 19794 record.  The bytes are <em>not</em> decoded;
 * that remains the caller's choice (JPEG/JPEG2000/PNG/WSQ decoders are not a
 * card42 dependency).
 */
public final class ImageData {

    /** Encoded image formats found in eMRTD data groups. */
    public enum Format {
        JPEG,
        JPEG2000,
        PNG,
        /** Wavelet Scalar Quantization (fingerprint images); kept raw. */
        WSQ,
        /** JPEG-LS (ISO 19794-6 iris images); kept raw. */
        JPEG_LS,
        /** Raw grayscale/RGB pixels or an unrecognised encoding. */
        UNKNOWN;

        /** A stable lower-case name for reports and JSON. */
        public String id() {
            return name().toLowerCase(java.util.Locale.ROOT);
        }
    }

    public final byte[] bytes;
    public final Format format;
    /** Pixel width, or 0 when the record does not carry it. */
    public final int width;
    /** Pixel height, or 0 when the record does not carry it. */
    public final int height;
    /** ISO 19794 colour space code, or -1 when unknown. */
    public final int colorSpace;
    /** ISO 19794 quality value, or -1 when unknown. */
    public final int quality;

    public ImageData(byte[] bytes, Format format, int width, int height,
                     int colorSpace, int quality) {
        this.bytes = bytes == null ? new byte[0] : bytes;
        this.format = format == null ? Format.UNKNOWN : format;
        this.width = width;
        this.height = height;
        this.colorSpace = colorSpace;
        this.quality = quality;
    }

    /** Builds an image whose format is sniffed from the bytes. */
    public static ImageData of(byte[] bytes, int width, int height,
                               int colorSpace, int quality) {
        return new ImageData(bytes, sniff(bytes), width, height, colorSpace, quality);
    }

    /**
     * The encoded format by its signature: JPEG, JPEG 2000 (JP2 container or
     * codestream), PNG, WSQ or JPEG-LS.  This is a fallback for records that
     * omit the format field; it never replaces an explicit format code.
     */
    public static Format sniff(byte[] bytes) {
        if (bytes == null || bytes.length < 4) {
            return Format.UNKNOWN;
        }
        int b0 = bytes[0] & 0xFF;
        int b1 = bytes[1] & 0xFF;
        int b2 = bytes[2] & 0xFF;
        int b3 = bytes[3] & 0xFF;
        if (b0 == 0xFF && b1 == 0xD8 && b2 == 0xFF) {
            // JPEG-LS uses SOF55 (FF F7) instead of the JPEG SOF markers.
            return b3 == 0xF7 ? Format.JPEG_LS : Format.JPEG;
        }
        if (b0 == 0x00 && b1 == 0x00 && b2 == 0x00 && b3 == 0x0C
                && bytes.length >= 8 && (bytes[4] & 0xFF) == 0x6A
                && (bytes[5] & 0xFF) == 0x50) {
            return Format.JPEG2000; // JP2 signature box 'jP  '
        }
        if (b0 == 0xFF && b1 == 0x4F && b2 == 0xFF && b3 == 0x51) {
            return Format.JPEG2000; // raw codestream SOC
        }
        if (b0 == 0x89 && b1 == 0x50 && b2 == 0x4E && b3 == 0x47) {
            return Format.PNG;
        }
        if (b0 == 0xFF && b1 == 0xA0) {
            return Format.WSQ; // SOI of a WSQ stream
        }
        return Format.UNKNOWN;
    }

    /** The format for an ISO/IEC 19794-5 image data type code. */
    public static Format faceFormat(int dataType) {
        switch (dataType) {
        case 0x00:
            return Format.JPEG;
        case 0x01:
            return Format.JPEG2000;
        default:
            return Format.UNKNOWN;
        }
    }

    /** The format for an ISO/IEC 19794-4 compression algorithm code. */
    public static Format fingerFormat(int algorithm) {
        switch (algorithm) {
        case 0:
        case 1:
            return Format.UNKNOWN; // uncompressed samples
        case 2:
            return Format.WSQ;
        case 3:
            return Format.JPEG;
        case 4:
            return Format.JPEG2000;
        case 5:
            return Format.PNG;
        default:
            return Format.UNKNOWN;
        }
    }

    /** The format for an ISO/IEC 19794-6 iris image format code. */
    public static Format irisFormat(int imageFormat) {
        switch (imageFormat) {
        case 2:
        case 4:
            return Format.UNKNOWN; // raw mono/RGB
        case 6:
        case 8:
            return Format.JPEG;
        case 10:
        case 12:
            return Format.JPEG_LS;
        case 14:
        case 16:
            return Format.JPEG2000;
        default:
            return Format.UNKNOWN;
        }
    }

    public int length() {
        return bytes.length;
    }

    @Override
    public String toString() {
        return format.id() + " " + (width > 0 ? width + "x" + height : "?")
                + " " + bytes.length + " B";
    }
}
