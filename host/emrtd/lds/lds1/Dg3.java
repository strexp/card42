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
 * Data group 3: finger(s) (ICAO Doc 9303-10 §4.7.3).
 *
 * <p>DG3 = {@code 63 { 7F61 { 02 count, 7F60 { A1 CBEFF, 5F2E ISO 19794 } } }}.
 * The data block is normally an ISO/IEC 19794-4 finger image record; an
 * ISO/IEC 19794-2 minutiae record is kept raw because its minutiae semantics
 * are outside what an inspection-system field model needs.
 */
public final class Dg3 implements LdsDataGroup {

    public final byte[] raw;
    public final List<FingerImage> fingers;
    public final int declaredCount;
    /** True when at least one record was an ISO/IEC 19794-2 minutiae record. */
    public final boolean hasMinutiaeRecords;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    private Dg3(byte[] raw, List<FingerImage> fingers, int declaredCount,
                boolean hasMinutiaeRecords, ParseStatus status, List<LdsIssue> issues) {
        this.raw = LdsBytes.copy(raw);
        this.fingers = Collections.unmodifiableList(new ArrayList<FingerImage>(fingers));
        this.declaredCount = declaredCount;
        this.hasMinutiaeRecords = hasMinutiaeRecords;
        this.status = status;
        this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(issues));
    }

    /** Parses a DG3 EF. */
    public static Dg3 parse(byte[] dg3) {
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(dg3, 0x63, 3, issues);
        List<FingerImage> fingers = new ArrayList<FingerImage>();
        int declared = -1;
        LdsTlv.Node bodyCount = LdsTlv.first(body, 0x02);
        if (bodyCount != null) {
            declared = LdsBytes.u8(bodyCount.value(), 0);
        }
        int templateCount = 0;
        List<LdsTlv.Node> groups = LdsTlv.all(body, 0x7F61);
        for (LdsTlv.Node group : groups) {
            List<LdsTlv.Node> children = LdsTlv.childrenOf(group, 3, issues);
            LdsTlv.Node count = LdsTlv.first(children, 0x02);
            if (count != null && declared < 0) {
                declared = LdsBytes.u8(count.value(), 0);
            }
            for (LdsTlv.Node template : LdsTlv.all(children, 0x7F60)) {
                templateCount++;
                parseTemplate(template, fingers, issues);
            }
        }
        if (templateCount == 0) {
            for (LdsTlv.Node template : LdsTlv.all(body, 0x7F60)) {
                templateCount++;
                parseTemplate(template, fingers, issues);
            }
            if (templateCount > 0) {
                issues.add(LdsIssue.warn(LdsIssue.Code.MISSING_MANDATORY, 3, 0,
                        "DG3 has no 7F61 group template"));
            }
        }
        if (declared >= 0 && declared != templateCount) {
            issues.add(LdsIssue.warn(LdsIssue.Code.COUNT_MISMATCH, 3, 0,
                    "DG3 declares " + declared + " template(s), found " + templateCount));
        }
        boolean minutiae = false;
        for (FingerImage finger : fingers) {
            minutiae |= "FMR".equals(finger.recordFormat);
        }
        ParseStatus status;
        if (templateCount == 0) {
            status = ParseStatus.INVALID;
            issues.add(LdsIssue.error(LdsIssue.Code.MISSING_MANDATORY, 3, 0,
                    "DG3 has no biometric template"));
        } else if (fingers.isEmpty()) {
            status = ParseStatus.PARTIAL;
        } else {
            status = hasProblems(issues) ? ParseStatus.PARTIAL : ParseStatus.OK;
        }
        return new Dg3(dg3, fingers, declared, minutiae, status, issues);
    }

    private static void parseTemplate(LdsTlv.Node template, List<FingerImage> fingers,
                                      List<LdsIssue> issues) {
        List<LdsTlv.Node> children = LdsTlv.childrenOf(template, 3, issues);
        LdsTlv.Node bht = LdsTlv.first(children, 0xA1);
        Cbeff cbeff = bht == null ? null : Cbeff.parse(bht.value(), 3, issues);
        if (bht == null) {
            issues.add(LdsIssue.warn(LdsIssue.Code.MISSING_MANDATORY, 3, template.start,
                    "biometric template has no CBEFF header (A1)"));
        }
        LdsTlv.Node bdb = LdsTlv.first(children, 0x5F2E);
        byte[] record = bdb != null ? bdb.value() : template.value();
        if (record.length == 0) {
            issues.add(LdsIssue.error(LdsIssue.Code.MISSING_MANDATORY, 3, template.start,
                    "biometric template has no data block"));
            return;
        }
        if (isFormat(record, "FIR")) {
            parseIso4(record, cbeff, fingers, issues);
        } else if (isFormat(record, "FMR")) {
            fingers.add(new FingerImage(cbeff, "FMR", -1, -1, -1, -1, -1, null, record));
            issues.add(LdsIssue.info(LdsIssue.Code.UNKNOWN_FORMAT, 3, template.start,
                    "ISO/IEC 19794-2 minutiae record kept raw"));
        } else {
            fingers.add(new FingerImage(cbeff, "UNKNOWN", -1, -1, -1, -1, -1, null, record));
            issues.add(LdsIssue.warn(LdsIssue.Code.UNKNOWN_FORMAT, 3, template.start,
                    "finger record has no ISO 19794 header"));
        }
    }

    /**
     * ISO/IEC 19794-4 finger image record: 32-byte general header, then one
     * 14-byte finger image header and the image data per view.
     */
    private static void parseIso4(byte[] record, Cbeff cbeff, List<FingerImage> fingers,
                                  List<LdsIssue> issues) {
        if (record.length < 32) {
            issues.add(LdsIssue.error(LdsIssue.Code.BAD_LENGTH, 3, 0,
                    "finger record shorter than the ISO 19794-4 header"));
            return;
        }
        long declaredLength = LdsBytes.u48(record, 8);
        int count = LdsBytes.u8(record, 18);
        int compression = LdsBytes.u8(record, 29);
        if (declaredLength >= 0 && declaredLength != record.length) {
            issues.add(LdsIssue.warn(LdsIssue.Code.BAD_LENGTH, 3, 8,
                    "ISO 19794-4 declared length " + declaredLength
                            + " differs from the " + record.length + " bytes read"));
        }
        if (count <= 0) {
            issues.add(LdsIssue.warn(LdsIssue.Code.COUNT_MISMATCH, 3, 18,
                    "ISO 19794-4 record declares no finger view"));
            return;
        }
        ImageData.Format format = ImageData.fingerFormat(compression);
        int off = 32;
        for (int i = 0; i < count; i++) {
            if (off + 14 > record.length) {
                issues.add(LdsIssue.error(LdsIssue.Code.TRUNCATED_TLV, 3, off,
                        "finger image header is truncated"));
                return;
            }
            long blockLength = LdsBytes.u32(record, off);
            if (blockLength < 14 || blockLength > record.length - off) {
                issues.add(LdsIssue.error(LdsIssue.Code.BAD_LENGTH, 3, off,
                        "finger image block length " + blockLength + " is invalid"));
                return;
            }
            int position = LdsBytes.u8(record, off + 4);
            int viewCount = LdsBytes.u8(record, off + 5);
            int viewNumber = LdsBytes.u8(record, off + 6);
            int quality = LdsBytes.u8(record, off + 7);
            int impressionType = LdsBytes.u8(record, off + 8);
            int width = LdsBytes.u16(record, off + 9);
            int height = LdsBytes.u16(record, off + 11);
            int imageStart = off + 14;
            int imageLength = (int) blockLength - 14;
            byte[] bytes = LdsBytes.copy(record, imageStart, imageLength);
            ImageData.Format actual = format != ImageData.Format.UNKNOWN
                    ? format : ImageData.sniff(bytes);
            if (actual == ImageData.Format.UNKNOWN) {
                issues.add(LdsIssue.warn(LdsIssue.Code.UNKNOWN_FORMAT, 3, imageStart,
                        "finger image encoding is not recognised"));
            }
            ImageData image = new ImageData(bytes, actual, width, height, -1, quality);
            byte[] block = LdsBytes.copy(record, off, (int) blockLength);
            fingers.add(new FingerImage(cbeff, "FIR", position, viewCount, viewNumber,
                    quality, impressionType, image, block));
            off += (int) blockLength;
        }
    }

    private static boolean isFormat(byte[] record, String magic) {
        if (record.length < 4) {
            return false;
        }
        return (record[0] & 0xFF) == magic.charAt(0)
                && (record[1] & 0xFF) == magic.charAt(1)
                && (record[2] & 0xFF) == magic.charAt(2)
                && record[3] == 0;
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
        return 3;
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
