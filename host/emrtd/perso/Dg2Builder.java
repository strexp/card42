package card42.host.emrtd.perso;

import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.MemoryCacheImageOutputStream;

import card42.host.common.codec.TlvWriter;

/**
 * Builds EF.DG2, the encoded face, for eMRTD personalization
 * (ICAO Doc 9303-10 §4.7.2, ISO/IEC 19794-5).
 *
 * <p>The structure is the CBEFF/ISO 7816-11 one an inspection system expects:
 *
 * <pre>
 *   75 { 7F61 { 02 01 01, 7F60 { A1 { 81,82,87,88 }, 5F2E ISO-19794-5 } } }
 * </pre>
 *
 * <p>The biometric data block is a Basic Facial Image Record: the 14-byte
 * Facial Record Header, one Facial Record Data Block (the 16-byte facial
 * information, no feature points, the 12-byte image information) and the raw
 * JPEG.  This is the structure a conformant CBEFF/ISO 19794 decoder consumes, so
 * an external inspection system can parse the personalized card.
 *
 * <p>The portrait is a required input image ({@link #DEFAULT_PORTRAIT} by
 * default, or a caller-supplied file): it is cropped to the portrait aspect
 * ratio {@link #PORTRAIT_WIDTH}:{@link #PORTRAIT_HEIGHT} and scaled so its
 * longest side is {@link #MAX_SIDE} pixels, then encoded as JPEG.  There is no
 * generated placeholder; a missing or unreadable image is an error.  The card
 * stores the result in a paged EEPROM file and the personalization path streams
 * the DGI value into it ({@code DgiStream} / {@code LdsPerso}).
 */
public final class Dg2Builder {

    /** The default portrait input image (relative to the repository root). */
    public static final String DEFAULT_PORTRAIT = "perso/emrtd/portrait.png";

    /**
     * The portrait aspect ratio the input image is cropped to: 4:5, carried as
     * width/height in the ISO/IEC 19794-5 record.
     */
    public static final int PORTRAIT_WIDTH = 4;
    public static final int PORTRAIT_HEIGHT = 5;

    /** The scaled portrait's longest side, in pixels. */
    public static final int MAX_SIDE = 512;

    private static final float JPEG_QUALITY = 0.7f;

    private static final int FORMAT_IDENTIFIER = 0x46414300; // 'F' 'A' 'C' 0x00
    private static final int VERSION_NUMBER = 0x30313000;    // '0' '1' '0' 0x00

    private Dg2Builder() {
    }

    /** DG2 for a JPEG image of the given pixel size. */
    public static byte[] build(byte[] jpeg, int width, int height) {
        byte[] faceInfo = faceInfo(jpeg, width, height);

        // Standard Biometric Header (ISO 7816-11): facial features, ISO 19794-5.
        ByteArrayOutputStream bht = new ByteArrayOutputStream();
        TlvWriter.writeTlv(bht, 0x81, new byte[] { 0x02 });       // biometric type
        TlvWriter.writeTlv(bht, 0x82, new byte[] { 0x00 });       // subtype none
        TlvWriter.writeTlv(bht, 0x87, new byte[] { 0x01, 0x01 }); // format owner JTC1 SC37
        TlvWriter.writeTlv(bht, 0x88, new byte[] { 0x00, 0x08 }); // format type ISO 19794 face

        // Biometric Information Template: BHT + biometric data block.
        ByteArrayOutputStream bit = new ByteArrayOutputStream();
        TlvWriter.writeTlv(bit, 0xA1, bht.toByteArray());
        TlvWriter.writeTlv(bit, 0x5F2E, faceInfo);

        // Biometric Information Group Template: count + the one template.
        ByteArrayOutputStream group = new ByteArrayOutputStream();
        TlvWriter.writeTlv(group, 0x02, new byte[] { 0x01 });
        TlvWriter.writeTlv(group, 0x7F60, bit.toByteArray());

        ByteArrayOutputStream dg2 = new ByteArrayOutputStream();
        ByteArrayOutputStream bitGroup = new ByteArrayOutputStream();
        TlvWriter.writeTlv(bitGroup, 0x7F61, group.toByteArray());
        TlvWriter.writeTlv(dg2, 0x75, bitGroup.toByteArray());
        return dg2.toByteArray();
    }

    /** The complete DG2 built from a portrait input image. */
    public static byte[] buildFromImage(File image) throws IOException {
        BufferedImage face = portrait(image);
        return build(encodeJpeg(face), face.getWidth(), face.getHeight());
    }

    /**
     * The input image as a portrait: cropped to
     * {@link #PORTRAIT_WIDTH}:{@link #PORTRAIT_HEIGHT} and scaled so its longest
     * side is {@link #MAX_SIDE}.  Any alpha is composited onto white.
     */
    public static BufferedImage portrait(File image) throws IOException {
        BufferedImage source = ImageIO.read(image);
        if (source == null) {
            throw new IOException("unsupported portrait image: " + image);
        }
        return scaleToMaxSide(cropToPortrait(source), MAX_SIDE);
    }

    /** The portrait JPEG that {@link #buildFromImage} embeds. */
    public static byte[] faceJpeg(File image) throws IOException {
        return encodeJpeg(portrait(image));
    }

    /** Largest centred crop of {@code source} whose ratio is the portrait ratio. */
    private static BufferedImage cropToPortrait(BufferedImage source) {
        int width = source.getWidth();
        int height = source.getHeight();
        BufferedImage rgb = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = rgb.createGraphics();
        g.drawImage(source, 0, 0, null);
        g.dispose();

        double targetHeight = (double) width * PORTRAIT_HEIGHT / PORTRAIT_WIDTH;
        if (targetHeight <= height) {
            int cropped = (int) targetHeight;
            return rgb.getSubimage(0, (height - cropped) / 2, width, cropped);
        }
        int croppedWidth = (int) ((double) height * PORTRAIT_WIDTH / PORTRAIT_HEIGHT);
        return rgb.getSubimage((width - croppedWidth) / 2, 0, croppedWidth, height);
    }

    /** Scales the image down so its longest side is {@code maxSide} (no upscaling). */
    private static BufferedImage scaleToMaxSide(BufferedImage image, int maxSide) {
        int width = image.getWidth();
        int height = image.getHeight();
        int longest = width > height ? width : height;
        if (longest <= maxSide) {
            return image;
        }
        double scale = (double) maxSide / longest;
        int scaledWidth = (int) Math.round(width * scale);
        int scaledHeight = (int) Math.round(height * scale);
        BufferedImage scaled = new BufferedImage(scaledWidth, scaledHeight,
                BufferedImage.TYPE_INT_RGB);
        Graphics2D g = scaled.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
                RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        g.drawImage(image, 0, 0, scaledWidth, scaledHeight, null);
        g.dispose();
        return scaled;
    }

    /** JPEG-encodes an image at the portrait quality. */
    private static byte[] encodeJpeg(BufferedImage image) throws IOException {
        ImageWriter writer = ImageIO.getImageWritersByFormatName("jpeg").next();
        ImageWriteParam params = writer.getDefaultWriteParam();
        params.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
        params.setCompressionQuality(JPEG_QUALITY);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writer.setOutput(new MemoryCacheImageOutputStream(out));
        writer.write(null, new IIOImage(image, null, null), params);
        writer.dispose();
        return out.toByteArray();
    }

    /**
     * The ISO/IEC 19794-5 Basic Facial Image Record: Facial Record Header,
     * one Facial Record Data Block and the JPEG.
     */
    private static byte[] faceInfo(byte[] jpeg, int width, int height) {
        ByteArrayOutputStream facial = new ByteArrayOutputStream();
        writeShort(facial, 0);        // number of feature points
        facial.write(0x00);           // gender: unspecified
        facial.write(0x00);           // eye colour: unspecified
        facial.write(0x00);           // hair colour: unspecified
        facial.write(0x00);           // feature mask (3 bytes)
        facial.write(0x00);
        facial.write(0x00);
        writeShort(facial, 0);        // expression
        facial.write(0x00);           // pose angle (3 bytes)
        facial.write(0x00);
        facial.write(0x00);
        facial.write(0x00);           // pose angle uncertainty (3 bytes)
        facial.write(0x00);
        facial.write(0x00);
        facial.write(0x00);           // face image type: basic
        facial.write(0x00);           // image data type: JPEG
        writeShort(facial, width);
        writeShort(facial, height);
        facial.write(0x00);           // colour space: unspecified
        facial.write(0x00);           // source type: unspecified
        writeShort(facial, 0);        // device type
        writeShort(facial, 0);        // quality
        facial.write(jpeg, 0, jpeg.length);
        byte[] facialData = facial.toByteArray();

        // The Facial Record Data Block length includes its own 4-byte field.
        ByteArrayOutputStream faceImage = new ByteArrayOutputStream();
        writeInt(faceImage, 4 + facialData.length);
        faceImage.write(facialData, 0, facialData.length);
        byte[] faceImageBlock = faceImage.toByteArray();

        ByteArrayOutputStream record = new ByteArrayOutputStream();
        writeInt(record, FORMAT_IDENTIFIER);
        writeInt(record, VERSION_NUMBER);
        writeInt(record, 14 + faceImageBlock.length); // whole record length
        writeShort(record, 1);                        // one facial record data block
        record.write(faceImageBlock, 0, faceImageBlock.length);
        return record.toByteArray();
    }

    private static void writeShort(ByteArrayOutputStream out, int value) {
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write((value >> 24) & 0xFF);
        out.write((value >> 16) & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }
}
