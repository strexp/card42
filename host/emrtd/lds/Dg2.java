package card42.host.emrtd.lds;

import card42.host.common.codec.Tags;

/**
 * Data group 2: the encoded face (ICAO Doc 9303-10 §4.7.2, Doc 9303-5).  DG2 =
 * {@code 75 { 7F61 { 7F60 { CBEFF ... image } } } }; this parser extracts the
 * raw JPEG or JPEG2000 image from the biometric data block (H1.2).
 */
public final class Dg2 {

    /** The raw image bytes (JPEG or JPEG2000), or null when not found. */
    public final byte[] image;

    private Dg2(byte[] image) {
        this.image = image;
    }

    public static Dg2 parse(byte[] dg2) {
        byte[] bdb = Tags.find(dg2, 0x7F60);
        return new Dg2(bdb == null ? null : extractImage(bdb));
    }

    /**
     * Finds the image inside the CBEFF biometric data block by its signature:
     * JPEG 2000 ({@code FF 4F FF 51}) or JPEG ({@code FF D8 FF}).
     */
    static byte[] extractImage(byte[] bdb) {
        for (int i = 0; i + 3 < bdb.length; i++) {
            int b0 = bdb[i] & 0xFF;
            int b1 = bdb[i + 1] & 0xFF;
            int b2 = bdb[i + 2] & 0xFF;
            int b3 = bdb[i + 3] & 0xFF;
            boolean jp2 = b0 == 0xFF && b1 == 0x4F && b2 == 0xFF && b3 == 0x51;
            boolean jpeg = b0 == 0xFF && b1 == 0xD8 && b2 == 0xFF;
            if (jp2 || jpeg) {
                return java.util.Arrays.copyOfRange(bdb, i, bdb.length);
            }
        }
        return null;
    }
}
