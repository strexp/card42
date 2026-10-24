package card42.host.emrtd.perso;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import card42.host.common.codec.TlvWriter;

/**
 * Builds the biometric data groups that card42 personalizes for the
 * demonstration document: DG3 (finger images, ISO/IEC 19794-4), DG4 (iris
 * images, ISO/IEC 19794-6), DG5/DG7 (displayed portrait/signature) and DG16
 * (persons to notify).  DG2 is built by {@link Dg2Builder}.
 *
 * <p>The records are deliberately minimal but follow the standard layout
 * (and the CBEFF {@code A1} header), so the host parsers and an external
 * inspection system read the same structure the sample card advertises.  The
 * image bytes are caller-supplied; no image decoding happens here.
 */
public final class BiometricRecordBuilder {

    /** CBEFF biometric type: fingerprint (ISO/IEC 7816-11). */
    public static final int TYPE_FINGERPRINT = 0x08;
    /** CBEFF biometric type: facial features. */
    public static final int TYPE_FACE = 0x02;
    /** CBEFF biometric type: iris. */
    public static final int TYPE_IRIS = 0x10;

    /** CBEFF format owner: JTC1 SC37. */
    public static final int OWNER_JTC1_SC37 = 0x0101;
    /** CBEFF format type: ISO/IEC 19794-4 finger image. */
    public static final int FORMAT_FINGER_IMAGE = 0x0007;
    /** CBEFF format type: ISO/IEC 19794-5 face image. */
    public static final int FORMAT_FACE_IMAGE = 0x0008;
    /** CBEFF format type: ISO/IEC 19794-6 iris image. */
    public static final int FORMAT_IRIS_IMAGE = 0x0009;

    /** ISO/IEC 19794-4 compression algorithm: WSQ. */
    public static final int COMPRESSION_WSQ = 2;
    /** ISO/IEC 19794-4 compression algorithm: JPEG. */
    public static final int COMPRESSION_JPEG = 3;
    /** ISO/IEC 19794-4 compression algorithm: JPEG 2000. */
    public static final int COMPRESSION_JPEG2000 = 4;
    /** ISO/IEC 19794-4 compression algorithm: PNG. */
    public static final int COMPRESSION_PNG = 5;

    private BiometricRecordBuilder() {
    }

    /** The CBEFF Biometric Header Template value (type, subtype 0, owner, format). */
    public static byte[] cbeff(int biometricType, int formatOwner, int formatType) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, 0x81, new byte[] { (byte) biometricType });
        TlvWriter.writeTlv(out, 0x82, new byte[] { 0x00 });
        TlvWriter.writeTlv(out, 0x87,
                new byte[] { (byte) (formatOwner >> 8), (byte) formatOwner });
        TlvWriter.writeTlv(out, 0x88,
                new byte[] { (byte) (formatType >> 8), (byte) formatType });
        return out.toByteArray();
    }

    /**
     * An ISO/IEC 19794-4 finger image record with one view.  The general
     * header is 32 bytes and the finger image block 14 bytes plus the image.
     */
    public static byte[] fingerImageRecord(int position, int impressionType,
                                           int width, int height, int compression,
                                           byte[] image) {
        ByteArrayOutputStream block = new ByteArrayOutputStream();
        writeInt(block, 14 + image.length);
        block.write(position & 0xFF);
        block.write(0x01); // number of views
        block.write(0x01); // view number
        block.write(80);   // quality
        block.write(impressionType & 0xFF);
        writeShort(block, width);
        writeShort(block, height);
        block.write(0x00); // reserved
        block.write(image, 0, image.length);
        byte[] fingerBlock = block.toByteArray();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write('F');
        out.write('I');
        out.write('R');
        out.write(0x00);
        out.write('0');
        out.write('1');
        out.write('0');
        out.write(0x00);
        writeLong48(out, 32 + fingerBlock.length);
        writeShort(out, 0);      // capture device id
        writeShort(out, 30);     // acquisition level: 500 ppi
        out.write(0x01);         // one finger view
        out.write(0x01);         // scale units: ppi
        writeShort(out, 500);    // scan resolution horizontal
        writeShort(out, 500);    // scan resolution vertical
        writeShort(out, 500);    // image resolution horizontal
        writeShort(out, 500);    // image resolution vertical
        out.write(8);            // pixel depth
        out.write(compression & 0xFF);
        writeShort(out, 0);      // reserved
        out.write(fingerBlock, 0, fingerBlock.length);
        return out.toByteArray();
    }

    /**
     * An ISO/IEC 19794-6 iris record with one eye and one image.  The header is
     * 45 bytes; the biometric subtype block is 3 bytes and each image block is
     * 11 bytes plus the image.
     */
    public static byte[] irisRecord(int eyePosition, int imageFormat,
                                    int width, int height, byte[] image) {
        ByteArrayOutputStream block = new ByteArrayOutputStream();
        writeShort(block, 1);    // image number
        block.write(80);         // quality
        writeShort(block, 0);    // rotation angle
        writeShort(block, 0);    // rotation uncertainty
        writeInt(block, image.length);
        block.write(image, 0, image.length);
        byte[] imageBlock = block.toByteArray();

        byte[] subtype = new byte[3];
        subtype[0] = (byte) eyePosition;
        subtype[1] = 0x00;
        subtype[2] = 0x01;       // one image

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write('I');
        out.write('I');
        out.write('R');
        out.write(0x00);
        out.write('0');
        out.write('1');
        out.write('0');
        out.write(0x00);
        writeInt(out, 45 + subtype.length + imageBlock.length);
        writeShort(out, 0);      // capture device id
        out.write(0x01);         // one biometric subtype block
        writeShort(out, 45);     // record header length
        writeShort(out, 0);      // image properties
        writeShort(out, 0);      // iris diameter
        writeShort(out, imageFormat);
        writeShort(out, width);
        writeShort(out, height);
        out.write(8);            // intensity depth
        out.write(0);            // image transformation
        out.write(new byte[16], 0, 16); // device unique id
        out.write(subtype, 0, subtype.length);
        out.write(imageBlock, 0, imageBlock.length);
        return out.toByteArray();
    }

    /**
     * A DG3 record: {@code 63 { 7F61 { 02 01 01, 7F60 { A1 BHT, 5F2E record } } }}.
     * The CBEFF header is created with the finger image format type.
     */
    public static byte[] dg3(byte[] fingerRecord) {
        return dgBiometric(0x63, TYPE_FINGERPRINT, FORMAT_FINGER_IMAGE, fingerRecord);
    }

    /** A DG4 record: {@code 76 { 7F61 { 02, 7F60 { A1 BHT, 5F2E iris record } } }}. */
    public static byte[] dg4(byte[] irisRecord) {
        return dgBiometric(0x76, TYPE_IRIS, FORMAT_IRIS_IMAGE, irisRecord);
    }

    private static byte[] dgBiometric(int outerTag, int biometricType, int formatType,
                                      byte[] record) {
        byte[] bht = cbeff(biometricType, OWNER_JTC1_SC37, formatType);
        ByteArrayOutputStream template = new ByteArrayOutputStream();
        TlvWriter.writeTlv(template, 0xA1, bht);
        TlvWriter.writeTlv(template, 0x5F2E, record);

        ByteArrayOutputStream group = new ByteArrayOutputStream();
        TlvWriter.writeTlv(group, 0x02, new byte[] { 0x01 });
        TlvWriter.writeTlv(group, 0x7F60, template.toByteArray());

        ByteArrayOutputStream bit = new ByteArrayOutputStream();
        TlvWriter.writeTlv(bit, 0x7F61, group.toByteArray());

        ByteArrayOutputStream dg = new ByteArrayOutputStream();
        TlvWriter.writeTlv(dg, outerTag, bit.toByteArray());
        return dg.toByteArray();
    }

    /** A DG5 displayed portrait list: {@code 65 { 02 count, 5F40* }}. */
    public static byte[] dg5(byte[]... images) {
        return imageList(0x65, 0x5F40, images);
    }

    /** A DG7 displayed signature list: {@code 67 { 02 count, 5F43* }}. */
    public static byte[] dg7(byte[]... images) {
        return imageList(0x67, 0x5F43, images);
    }

    private static byte[] imageList(int outerTag, int imageTag, byte[]... images) {
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        TlvWriter.writeTlv(inner, 0x02, new byte[] { (byte) images.length });
        for (byte[] image : images) {
            TlvWriter.writeTlv(inner, imageTag, image);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, outerTag, inner.toByteArray());
        return out.toByteArray();
    }

    /**
     * One DG16 person template: {@code Ax { 5F50 date, 5F51 name, 5F52 telephone,
     * 5F53 address }}.  {@code index} 1 produces A1, 2 produces A2, and so on.
     */
    public static byte[] personToNotify(int index, String date, String name,
                                        String telephone, String address) {
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        if (date != null) {
            TlvWriter.writeTlv(inner, 0x5F50, date.getBytes(StandardCharsets.US_ASCII));
        }
        if (name != null) {
            TlvWriter.writeTlv(inner, 0x5F51, name.getBytes(StandardCharsets.UTF_8));
        }
        if (telephone != null) {
            TlvWriter.writeTlv(inner, 0x5F52, telephone.getBytes(StandardCharsets.UTF_8));
        }
        if (address != null) {
            TlvWriter.writeTlv(inner, 0x5F53, address.getBytes(StandardCharsets.UTF_8));
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, 0xA0 + index, inner.toByteArray());
        return out.toByteArray();
    }

    /** A DG16 record: {@code 70 { 02 count, Ax... }}. */
    public static byte[] dg16(List<byte[]> persons) {
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        TlvWriter.writeTlv(inner, 0x02, new byte[] { (byte) persons.size() });
        for (byte[] person : persons) {
            inner.write(person, 0, person.length);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, 0x70, inner.toByteArray());
        return out.toByteArray();
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

    private static void writeLong48(ByteArrayOutputStream out, long value) {
        out.write((int) ((value >> 40) & 0xFF));
        out.write((int) ((value >> 32) & 0xFF));
        out.write((int) ((value >> 24) & 0xFF));
        out.write((int) ((value >> 16) & 0xFF));
        out.write((int) ((value >> 8) & 0xFF));
        out.write((int) (value & 0xFF));
    }
}
