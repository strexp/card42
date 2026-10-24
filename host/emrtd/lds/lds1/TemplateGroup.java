package card42.host.emrtd.lds.lds1;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.LdsTlv;
import card42.host.emrtd.lds.common.ParseStatus;

/**
 * Shared implementation for DG8/DG9/DG10, whose structures ICAO Doc 9303-10
 * still marks "To Be Defined": the only defined element is the instance count
 * ({@code 02}) followed by proprietary templates.  The templates are kept as
 * complete BER-TLV objects, never interpreted.
 */
final class TemplateGroup {

    static final class Result {
        final List<byte[]> templates;
        final int declaredCount;
        final ParseStatus status;
        final List<LdsIssue> issues;

        Result(List<byte[]> templates, int declaredCount, ParseStatus status,
               List<LdsIssue> issues) {
            this.templates = Collections.unmodifiableList(new ArrayList<byte[]>(templates));
            this.declaredCount = declaredCount;
            this.status = status;
            this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(issues));
        }
    }

    private TemplateGroup() {
    }

    static Result parse(byte[] raw, int dg, int outerTag) {
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(raw, outerTag, dg, issues);
        List<byte[]> templates = new ArrayList<byte[]>();
        int declared = -1;
        LdsTlv.Node countNode = LdsTlv.first(body, 0x02);
        if (countNode != null) {
            byte[] value = countNode.value();
            declared = value.length == 0 ? 0 : (value[0] & 0xFF);
        }
        for (LdsTlv.Node node : body) {
            if (node.tag == 0x02) {
                continue;
            }
            templates.add(node.encoded());
        }
        if (declared >= 0 && declared != templates.size()) {
            issues.add(LdsIssue.warn(LdsIssue.Code.COUNT_MISMATCH, dg, 0,
                    "DG" + dg + " declares " + declared + " template(s), found "
                            + templates.size()));
        }
        issues.add(LdsIssue.info(LdsIssue.Code.UNKNOWN_TAG, dg, 0,
                "DG" + dg + " structure is not defined by Doc 9303-10; templates kept raw"));
        ParseStatus status;
        if (body.isEmpty()) {
            // An empty template group (02 absent, no templates) is valid for
            // the proprietary DG8/DG9/DG10; only a completely empty EF is not.
            if (raw == null || raw.length == 0) {
                status = ParseStatus.INVALID;
            } else {
                status = ParseStatus.OK;
            }
        } else if (hasProblems(issues)) {
            status = ParseStatus.PARTIAL;
        } else {
            status = ParseStatus.OK;
        }
        return new Result(templates, declared, status, issues);
    }

    private static boolean hasProblems(List<LdsIssue> issues) {
        for (LdsIssue issue : issues) {
            if (issue.severity != LdsIssue.Severity.INFO) {
                return true;
            }
        }
        return false;
    }
}
