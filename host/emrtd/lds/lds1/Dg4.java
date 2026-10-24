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
 * Data group 4: iris(es) (ICAO Doc 9303-10 §4.7.4).
 *
 * <p>DG4 = {@code 76 { 7F61 { 02 count, 7F60 { A1 CBEFF, 5F2E ISO 19794-6 } } }}.
 * Each iris image carries its ISO subtype (right/left eye), image number,
 * quality and rotation, plus the encoded image bytes.
 */
public final class Dg4 implements LdsDataGroup {

    public final byte[] raw;
    public final List<IrisImage> irises;
    public final int declaredCount;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    private Dg4(byte[] raw, List<IrisImage> irises, int declaredCount,
                ParseStatus status, List<LdsIssue> issues) {
        this.raw = LdsBytes.copy(raw);
        this.irises = Collections.unmodifiableList(new ArrayList<IrisImage>(irises));
        this.declaredCount = declaredCount;
        this.status = status;
        this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(issues));
    }

    /** Parses a DG4 EF. */
    public static Dg4 parse(byte[] dg4) {
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(dg4, 0x76, 4, issues);
        List<IrisImage> irises = new ArrayList<IrisImage>();
        int declared = -1;
        LdsTlv.Node bodyCount = LdsTlv.first(body, 0x02);
        if (bodyCount != null) {
            declared = LdsBytes.u8(bodyCount.value(), 0);
        }
        int templateCount = 0;
        List<LdsTlv.Node> groups = LdsTlv.all(body, 0x7F61);
        for (LdsTlv.Node group : groups) {
            List<LdsTlv.Node> children = LdsTlv.childrenOf(group, 4, issues);
            LdsTlv.Node count = LdsTlv.first(children, 0x02);
            if (count != null && declared < 0) {
                declared = LdsBytes.u8(count.value(), 0);
            }
            for (LdsTlv.Node template : LdsTlv.all(children, 0x7F60)) {
                templateCount++;
                parseTemplate(template, irises, issues);
            }
        }
        if (templateCount == 0) {
            for (LdsTlv.Node template : LdsTlv.all(body, 0x7F60)) {
                templateCount++;
                parseTemplate(template, irises, issues);
            }
            if (templateCount > 0) {
                issues.add(LdsIssue.warn(LdsIssue.Code.MISSING_MANDATORY, 4, 0,
                        "DG4 has no 7F61 group template"));
            }
        }
        if (declared >= 0 && declared != templateCount) {
            issues.add(LdsIssue.warn(LdsIssue.Code.COUNT_MISMATCH, 4, 0,
                    "DG4 declares " + declared + " template(s), found " + templateCount));
        }
        ParseStatus status;
        if (templateCount == 0) {
            status = ParseStatus.INVALID;
            issues.add(LdsIssue.error(LdsIssue.Code.MISSING_MANDATORY, 4, 0,
                    "DG4 has no biometric template"));
        } else if (irises.isEmpty()) {
            status = ParseStatus.PARTIAL;
            issues.add(LdsIssue.warn(LdsIssue.Code.UNSUPPORTED_LAYOUT, 4, 0,
                    "DG4 template present but no iris image could be decoded"));
        } else {
            status = hasProblems(issues) ? ParseStatus.PARTIAL : ParseStatus.OK;
        }
        return new Dg4(dg4, irises, declared, status, issues);
    }

    private static void parseTemplate(LdsTlv.Node template, List<IrisImage> irises,
                                      List<LdsIssue> issues) {
        List<LdsTlv.Node> children = LdsTlv.childrenOf(template, 4, issues);
        LdsTlv.Node bht = LdsTlv.first(children, 0xA1);
        Cbeff cbeff = bht == null ? null : Cbeff.parse(bht.value(), 4, issues);
        if (bht == null) {
            issues.add(LdsIssue.warn(LdsIssue.Code.MISSING_MANDATORY, 4, template.start,
                    "biometric template has no CBEFF header (A1)"));
        }
        LdsTlv.Node bdb = LdsTlv.first(children, 0x5F2E);
        byte[] record = bdb != null ? bdb.value() : template.value();
        if (record.length == 0) {
            issues.add(LdsIssue.error(LdsIssue.Code.MISSING_MANDATORY, 4, template.start,
                    "biometric template has no data block"));
            return;
        }
        if (isIir(record)) {
            parseIso6(record, cbeff, irises, issues);
        } else {
            ImageData legacy = Dg2.scanImage(record);
            if (legacy != null) {
                irises.add(new IrisImage(cbeff, 0, -1, -1, -1, -1, legacy, record));
                issues.add(LdsIssue.warn(LdsIssue.Code.UNSUPPORTED_LAYOUT, 4, template.start,
                        "iris record has no ISO 19794-6 header; image found by signature"));
            } else {
                issues.add(LdsIssue.warn(LdsIssue.Code.UNKNOWN_FORMAT, 4, template.start,
                        "iris record has no ISO 19794-6 header"));
            }
        }
    }

    /**
     * ISO/IEC 19794-6 iris record: 45-byte header, then per biometric subtype
     * block (subtype, count) a series of image blocks (number, quality,
     * rotation, uncertainty, image length, image).
     */
    private static void parseIso6(byte[] record, Cbeff cbeff, List<IrisImage> irises,
                                  List<LdsIssue> issues) {
        if (record.length < 45) {
            issues.add(LdsIssue.error(LdsIssue.Code.BAD_LENGTH, 4, 0,
                    "iris record shorter than the ISO 19794-6 header"));
            return;
        }
        long declaredLength = LdsBytes.u32(record, 8);
        int count = LdsBytes.u8(record, 14);
        int imageFormat = LdsBytes.u16(record, 21);
        int width = LdsBytes.u16(record, 23);
        int height = LdsBytes.u16(record, 25);
        if (declaredLength >= 0 && declaredLength != record.length) {
            issues.add(LdsIssue.warn(LdsIssue.Code.BAD_LENGTH, 4, 8,
                    "ISO 19794-6 declared length " + declaredLength
                            + " differs from the " + record.length + " bytes read"));
        }
        if (count <= 0) {
            issues.add(LdsIssue.warn(LdsIssue.Code.COUNT_MISMATCH, 4, 14,
                    "ISO 19794-6 record declares no iris block"));
            return;
        }
        ImageData.Format format = ImageData.irisFormat(imageFormat);
        int off = 45;
        for (int i = 0; i < count; i++) {
            if (off + 3 > record.length) {
                issues.add(LdsIssue.error(LdsIssue.Code.TRUNCATED_TLV, 4, off,
                        "iris subtype header is truncated"));
                return;
            }
            int eyePosition = LdsBytes.u8(record, off);
            int imageCount = LdsBytes.u16(record, off + 1);
            off += 3;
            for (int j = 0; j < imageCount; j++) {
                if (off + 11 > record.length) {
                    issues.add(LdsIssue.error(LdsIssue.Code.TRUNCATED_TLV, 4, off,
                            "iris image header is truncated"));
                    return;
                }
                int imageNumber = LdsBytes.u16(record, off);
                int quality = LdsBytes.u8(record, off + 2);
                int rotation = (short) LdsBytes.u16(record, off + 3);
                int rotationUncertainty = LdsBytes.u16(record, off + 5);
                long imageLength = LdsBytes.u32(record, off + 7);
                if (imageLength < 0 || imageLength > record.length - off - 11) {
                    issues.add(LdsIssue.error(LdsIssue.Code.BAD_LENGTH, 4, off + 7,
                            "iris image length " + imageLength + " is invalid"));
                    return;
                }
                int imageStart = off + 11;
                byte[] bytes = LdsBytes.copy(record, imageStart, (int) imageLength);
                ImageData.Format actual = format != ImageData.Format.UNKNOWN
                        ? format : ImageData.sniff(bytes);
                if (actual == ImageData.Format.UNKNOWN) {
                    issues.add(LdsIssue.warn(LdsIssue.Code.UNKNOWN_FORMAT, 4, imageStart,
                            "iris image encoding is not recognised"));
                }
                ImageData image = new ImageData(bytes, actual, width, height, -1, quality);
                byte[] block = LdsBytes.copy(record, off, 11 + (int) imageLength);
                irises.add(new IrisImage(cbeff, eyePosition, imageNumber, quality,
                        rotation, rotationUncertainty, image, block));
                off += 11 + (int) imageLength;
            }
        }
    }

    private static boolean isIir(byte[] record) {
        return record.length >= 4 && (record[0] & 0xFF) == 'I' && (record[1] & 0xFF) == 'I'
                && (record[2] & 0xFF) == 'R' && record[3] == 0;
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
        return 4;
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
