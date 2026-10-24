package card42.host.emrtd.lds.lds1;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import card42.host.emrtd.lds.common.Cbeff;
import card42.host.emrtd.lds.common.ImageData;
import card42.host.emrtd.lds.common.LdsBytes;
import card42.host.emrtd.lds.common.LdsDataGroup;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.LdsTlv;
import card42.host.emrtd.lds.common.ParseStatus;

/**
 * Data group 2: the encoded face (ICAO Doc 9303-10 §4.7.2, Doc 9303-5).
 *
 * <p>DG2 = {@code 75 { 7F61 { 02 count, 7F60 { A1 CBEFF, 5F2E ISO 19794-5 } } }}.
 * The parser walks the declared records, extracts every face and keeps the
 * ISO image length field authoritative — a byte sequence that merely looks
 * like a JPEG inside the metadata is not mistaken for the image.  A legacy
 * BDB without an ISO header still has its image recovered by signature scan
 * and is reported as {@link ParseStatus#PARTIAL}.
 *
 * <p>For compatibility, {@link #image} remains the first face image with the
 * same meaning it always had.
 */
public final class Dg2 implements LdsDataGroup {

    /** The first face image (JPEG or JPEG 2000), or null when not found. */
    public final byte[] image;
    public final List<FaceImage> faces;
    /** The count declared in the {@code 02} template, or -1. */
    public final int declaredCount;
    /** The complete EF bytes, including the outer tag. */
    public final byte[] raw;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    private Dg2(byte[] raw, List<FaceImage> faces, int declaredCount,
                ParseStatus status, List<LdsIssue> issues) {
        this.raw = LdsBytes.copy(raw);
        this.faces = Collections.unmodifiableList(new ArrayList<FaceImage>(faces));
        this.declaredCount = declaredCount;
        this.image = faces.isEmpty() || faces.get(0).image == null
                ? null : faces.get(0).image.bytes.clone();
        this.status = status;
        this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(issues));
    }

    /** Parses a DG2 EF. */
    public static Dg2 parse(byte[] dg2) {
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(dg2, 0x75, 2, issues);
        List<FaceImage> faces = new ArrayList<FaceImage>();
        int declared = -1;
        LdsTlv.Node bodyCount = LdsTlv.first(body, 0x02);
        if (bodyCount != null) {
            declared = LdsBytes.u8(bodyCount.value(), 0);
        }
        int groupCount = 0;
        List<LdsTlv.Node> groups = LdsTlv.all(body, 0x7F61);
        if (!groups.isEmpty()) {
            for (LdsTlv.Node group : groups) {
                List<LdsTlv.Node> children = LdsTlv.childrenOf(group, 2, issues);
                LdsTlv.Node count = LdsTlv.first(children, 0x02);
                if (count != null && declared < 0) {
                    declared = LdsBytes.u8(count.value(), 0);
                }
                for (LdsTlv.Node template : LdsTlv.all(children, 0x7F60)) {
                    groupCount++;
                    parseTemplate(template, faces, issues);
                }
            }
        } else {
            // Some cards omit the 7F61 group template and hang 7F60 directly
            // off DG2; treat that as a partial encoding rather than empty.
            List<LdsTlv.Node> templates = LdsTlv.all(body, 0x7F60);
            if (!templates.isEmpty()) {
                issues.add(LdsIssue.warn(LdsIssue.Code.MISSING_MANDATORY, 2, 0,
                        "DG2 has no 7F61 group template"));
            }
            for (LdsTlv.Node template : templates) {
                groupCount++;
                parseTemplate(template, faces, issues);
            }
        }
        if (declared >= 0 && declared != groupCount) {
            issues.add(LdsIssue.warn(LdsIssue.Code.COUNT_MISMATCH, 2, 0,
                    "DG2 declares " + declared + " biometric template(s), found " + groupCount));
        }
        ParseStatus status;
        if (faces.isEmpty()) {
            if (groupCount > 0) {
                status = ParseStatus.PARTIAL;
                issues.add(LdsIssue.warn(LdsIssue.Code.UNSUPPORTED_LAYOUT, 2, 0,
                        "DG2 template present but no facial image could be decoded"));
            } else {
                status = ParseStatus.INVALID;
                issues.add(LdsIssue.error(LdsIssue.Code.MISSING_MANDATORY, 2, 0,
                        "DG2 has no biometric template"));
            }
        } else {
            status = hasProblems(issues) ? ParseStatus.PARTIAL : ParseStatus.OK;
        }
        return new Dg2(dg2, faces, declared, status, issues);
    }

    private static void parseTemplate(LdsTlv.Node template, List<FaceImage> faces,
                                      List<LdsIssue> issues) {
        List<LdsTlv.Node> children = LdsTlv.childrenOf(template, 2, issues);
        LdsTlv.Node bht = LdsTlv.first(children, 0xA1);
        Cbeff cbeff = bht == null ? null : Cbeff.parse(bht.value(), 2, issues);
        if (bht == null) {
            issues.add(LdsIssue.warn(LdsIssue.Code.MISSING_MANDATORY, 2, template.start,
                    "biometric template has no CBEFF header (A1)"));
        }
        LdsTlv.Node bdb = LdsTlv.first(children, 0x5F2E);
        byte[] record = bdb != null ? bdb.value() : template.value();
        if (record.length == 0) {
            issues.add(LdsIssue.error(LdsIssue.Code.MISSING_MANDATORY, 2, template.start,
                    "biometric template has no data block"));
            return;
        }
        int before = faces.size();
        parseIsoRecord(record, cbeff, faces, issues);
        if (faces.size() == before) {
            // No ISO 19794-5 header: fall back to a signature scan so a legacy
            // or truncated BDB still yields the image, but flag it as partial.
            ImageData legacy = scanImage(record);
            if (legacy != null) {
                faces.add(new FaceImage(cbeff, -1, -1, -1, legacy, record));
                issues.add(LdsIssue.warn(LdsIssue.Code.UNSUPPORTED_LAYOUT, 2, template.start,
                        "facial record has no ISO 19794-5 header; image found by signature"));
            }
        }
    }

    /**
     * Parses an ISO/IEC 19794-5 Basic Facial Image Record:
     * 14-byte header, then per facial record an 8-byte header (record length,
     * feature points, ...), facial information, optional feature points and
     * the 12-byte image information followed by the image data.
     */
    static void parseIsoRecord(byte[] record, Cbeff cbeff, List<FaceImage> faces,
                               List<LdsIssue> issues) {
        if (record.length < 14) {
            issues.add(LdsIssue.error(LdsIssue.Code.BAD_LENGTH, 2, 0,
                    "facial record shorter than the ISO 19794-5 header"));
            return;
        }
        long format = LdsBytes.u32(record, 0);
        long version = LdsBytes.u32(record, 4);
        long declaredLength = LdsBytes.u32(record, 8);
        int count = LdsBytes.u16(record, 12);
        if (format != 0x46414300L) { // 'FAC' 0x00
            issues.add(LdsIssue.warn(LdsIssue.Code.UNKNOWN_FORMAT, 2, 0,
                    "ISO 19794-5 record has an unknown format identifier"));
            return;
        }
        if (version != 0x30313000L) { // '010' 0x00
            issues.add(LdsIssue.warn(LdsIssue.Code.UNKNOWN_FORMAT, 2, 4,
                    "ISO 19794-5 record version is not '010'"));
        }
        if (declaredLength >= 0 && declaredLength != record.length) {
            issues.add(LdsIssue.warn(LdsIssue.Code.BAD_LENGTH, 2, 8,
                    "ISO 19794-5 declared length " + declaredLength
                            + " differs from the " + record.length + " bytes read"));
        }
        if (count <= 0) {
            issues.add(LdsIssue.warn(LdsIssue.Code.COUNT_MISMATCH, 2, 12,
                    "ISO 19794-5 record declares no facial record"));
            return;
        }
        int off = 14;
        for (int i = 0; i < count; i++) {
            if (off + 20 > record.length) {
                issues.add(LdsIssue.error(LdsIssue.Code.TRUNCATED_TLV, 2, off,
                        "facial record header is truncated"));
                return;
            }
            long blockLength = LdsBytes.u32(record, off);
            int featurePoints = LdsBytes.u16(record, off + 4);
            if (blockLength < 20 || blockLength > record.length - off) {
                issues.add(LdsIssue.error(LdsIssue.Code.BAD_LENGTH, 2, off,
                        "facial record block length " + blockLength + " is invalid"));
                return;
            }
            int imageInfo = off + 20 + featurePoints * 8;
            int blockEnd = off + (int) blockLength;
            if (featurePoints < 0 || imageInfo + 12 > blockEnd) {
                issues.add(LdsIssue.error(LdsIssue.Code.BAD_LENGTH, 2, off,
                        "facial image information does not fit the block"));
                return;
            }
            int faceImageType = LdsBytes.u8(record, imageInfo);
            int dataType = LdsBytes.u8(record, imageInfo + 1);
            int width = LdsBytes.u16(record, imageInfo + 2);
            int height = LdsBytes.u16(record, imageInfo + 4);
            int colorSpace = LdsBytes.u8(record, imageInfo + 6);
            int quality = LdsBytes.u16(record, imageInfo + 10);
            ImageData.Format formatByCode = ImageData.faceFormat(dataType);
            int imageStart = imageInfo + 12;
            int imageLength = blockEnd - imageStart;
            if (imageLength < 0) {
                imageLength = 0;
            }
            byte[] bytes = LdsBytes.copy(record, imageStart, imageLength);
            ImageData.Format actual = formatByCode != ImageData.Format.UNKNOWN
                    ? formatByCode : ImageData.sniff(bytes);
            if (actual == ImageData.Format.UNKNOWN) {
                issues.add(LdsIssue.warn(LdsIssue.Code.UNKNOWN_FORMAT, 2, imageStart,
                        "facial image encoding is not recognised"));
            }
            ImageData image = new ImageData(bytes, actual, width, height, colorSpace, quality);
            faces.add(new FaceImage(cbeff, featurePoints, faceImageType, dataType, image, record));
            off = blockEnd;
        }
    }

    /** Finds the first JPEG/JPEG 2000/PNG/WSQ image in a raw BDB. */
    static ImageData scanImage(byte[] bdb) {
        for (int i = 0; i + 3 < bdb.length; i++) {
            int b0 = bdb[i] & 0xFF;
            int b1 = bdb[i + 1] & 0xFF;
            boolean jp2 = b0 == 0xFF && b1 == 0x4F
                    && (bdb[i + 2] & 0xFF) == 0xFF && (bdb[i + 3] & 0xFF) == 0x51;
            boolean jpeg = b0 == 0xFF && b1 == 0xD8 && (bdb[i + 2] & 0xFF) == 0xFF;
            boolean png = b0 == 0x89 && b1 == 0x50
                    && (bdb[i + 2] & 0xFF) == 0x4E && (bdb[i + 3] & 0xFF) == 0x47;
            if (jp2 || jpeg || png) {
                byte[] bytes = java.util.Arrays.copyOfRange(bdb, i, bdb.length);
                return new ImageData(bytes, ImageData.sniff(bytes), 0, 0, -1, -1);
            }
        }
        return null;
    }

    private static boolean hasProblems(List<LdsIssue> issues) {
        for (LdsIssue issue : issues) {
            if (issue.severity != LdsIssue.Severity.INFO) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int dg() {
        return 2;
    }

    @Override
    public byte[] raw() {
        return raw.clone();
    }

    @Override
    public ParseStatus status() {
        return status;
    }

    @Override
    public List<LdsIssue> issues() {
        return issues;
    }
}
