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
 * Data group 7: displayed signature or usual mark (ICAO Doc 9303-10 §4.7.7).
 *
 * <p>DG7 = {@code 67 { 02 count, 5F43 signature } }; like DG5 it carries plain
 * JFIF images without a CBEFF wrapper.
 */
public final class Dg7 implements LdsDataGroup {

    public final byte[] raw;
    public final List<ImageData> signatures;
    public final int declaredCount;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    private Dg7(byte[] raw, List<ImageData> signatures, int declaredCount,
                ParseStatus status, List<LdsIssue> issues) {
        this.raw = LdsBytes.copy(raw);
        this.signatures = Collections.unmodifiableList(new ArrayList<ImageData>(signatures));
        this.declaredCount = declaredCount;
        this.status = status;
        this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(issues));
    }

    /** Parses a DG7 EF. */
    public static Dg7 parse(byte[] dg7) {
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(dg7, 0x67, 7, issues);
        List<ImageData> signatures = new ArrayList<ImageData>();
        LdsTlv.Node countNode = LdsTlv.first(body, 0x02);
        int declared = countNode == null ? -1 : LdsBytes.u8(countNode.value(), 0);
        for (LdsTlv.Node node : LdsTlv.all(body, 0x5F43)) {
            byte[] bytes = node.value();
            ImageData.Format format = ImageData.sniff(bytes);
            if (format == ImageData.Format.UNKNOWN) {
                issues.add(LdsIssue.warn(LdsIssue.Code.UNKNOWN_FORMAT, 7, node.start,
                        "displayed signature encoding is not recognised"));
            }
            signatures.add(new ImageData(bytes, format, 0, 0, -1, -1));
        }
        if (declared >= 0 && declared != signatures.size()) {
            issues.add(LdsIssue.warn(LdsIssue.Code.COUNT_MISMATCH, 7, 0,
                    "DG7 declares " + declared + " signature(s), found " + signatures.size()));
        }
        ParseStatus status;
        if (body.isEmpty()) {
            status = ParseStatus.INVALID;
            issues.add(LdsIssue.error(LdsIssue.Code.MISSING_MANDATORY, 7, 0,
                    "DG7 has no template"));
        } else if (signatures.isEmpty()) {
            status = ParseStatus.PARTIAL;
            issues.add(LdsIssue.warn(LdsIssue.Code.MISSING_MANDATORY, 7, 0,
                    "DG7 has no displayed signature (5F43)"));
        } else {
            status = hasProblems(issues) ? ParseStatus.PARTIAL : ParseStatus.OK;
        }
        return new Dg7(dg7, signatures, declared, status, issues);
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
        return 7;
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
