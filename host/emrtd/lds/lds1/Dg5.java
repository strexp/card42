package card42.host.emrtd.lds.lds1;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import card42.host.emrtd.lds.common.ImageData;
import card42.host.emrtd.lds.common.LdsBytes;
import card42.host.emrtd.lds.common.LdsDataGroup;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.LdsTlv;
import card42.host.emrtd.lds.common.ParseStatus;

/**
 * Data group 5: displayed portrait (ICAO Doc 9303-10 §4.7.5).
 *
 * <p>DG5 = {@code 65 { 02 count, 5F40 portrait } }; unlike DG2 it is a plain
 * JFIF image list with no CBEFF or ISO/IEC 19794 header, so the images are
 * sniffed rather than decoded.
 */
public final class Dg5 implements LdsDataGroup {

    public final byte[] raw;
    public final List<ImageData> portraits;
    public final int declaredCount;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    private Dg5(byte[] raw, List<ImageData> portraits, int declaredCount,
                ParseStatus status, List<LdsIssue> issues) {
        this.raw = LdsBytes.copy(raw);
        this.portraits = Collections.unmodifiableList(new ArrayList<ImageData>(portraits));
        this.declaredCount = declaredCount;
        this.status = status;
        this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(issues));
    }

    /** Parses a DG5 EF. */
    public static Dg5 parse(byte[] dg5) {
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(dg5, 0x65, 5, issues);
        List<ImageData> portraits = new ArrayList<ImageData>();
        LdsTlv.Node countNode = LdsTlv.first(body, 0x02);
        int declared = countNode == null ? -1 : LdsBytes.u8(countNode.value(), 0);
        for (LdsTlv.Node node : LdsTlv.all(body, 0x5F40)) {
            byte[] bytes = node.value();
            ImageData.Format format = ImageData.sniff(bytes);
            if (format == ImageData.Format.UNKNOWN) {
                issues.add(LdsIssue.warn(LdsIssue.Code.UNKNOWN_FORMAT, 5, node.start,
                        "displayed portrait encoding is not recognised"));
            }
            portraits.add(new ImageData(bytes, format, 0, 0, -1, -1));
        }
        if (declared >= 0 && declared != portraits.size()) {
            issues.add(LdsIssue.warn(LdsIssue.Code.COUNT_MISMATCH, 5, 0,
                    "DG5 declares " + declared + " portrait(s), found " + portraits.size()));
        }
        ParseStatus status;
        if (body.isEmpty()) {
            status = ParseStatus.INVALID;
            issues.add(LdsIssue.error(LdsIssue.Code.MISSING_MANDATORY, 5, 0,
                    "DG5 has no template"));
        } else if (portraits.isEmpty()) {
            status = ParseStatus.PARTIAL;
            issues.add(LdsIssue.warn(LdsIssue.Code.MISSING_MANDATORY, 5, 0,
                    "DG5 has no displayed portrait (5F40)"));
        } else {
            status = hasProblems(issues) ? ParseStatus.PARTIAL : ParseStatus.OK;
        }
        return new Dg5(dg5, portraits, declared, status, issues);
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
        return 5;
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
