package card42.host.emrtd.lds.lds1;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import card42.host.emrtd.lds.common.LdsBytes;
import card42.host.emrtd.lds.common.LdsDataGroup;
import card42.host.emrtd.lds.common.LdsDate;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.LdsText;
import card42.host.emrtd.lds.common.LdsTlv;
import card42.host.emrtd.lds.common.ParseStatus;

/**
 * Data group 16: person(s) to notify (ICAO Doc 9303-10 §4.7.16).
 *
 * <p>DG16 = {@code 70 { 02 count, A1 { 5F50, 5F51, 5F52, 5F53 }, A2 { ... } } }.
 * Each {@code Ax} template is one contact; unknown elements are kept raw and
 * the list is never truncated because one contact is malformed.
 */
public final class Dg16 implements LdsDataGroup {

    public final byte[] raw;
    public final List<PersonToNotify> persons;
    public final int declaredCount;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    private Dg16(byte[] raw, List<PersonToNotify> persons, int declaredCount,
                 ParseStatus status, List<LdsIssue> issues) {
        this.raw = LdsBytes.copy(raw);
        this.persons = Collections.unmodifiableList(new ArrayList<PersonToNotify>(persons));
        this.declaredCount = declaredCount;
        this.status = status;
        this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(issues));
    }

    /** Parses a DG16 EF. */
    public static Dg16 parse(byte[] dg16) {
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(dg16, 0x70, 16, issues);
        List<PersonToNotify> persons = new ArrayList<PersonToNotify>();
        LdsTlv.Node countNode = LdsTlv.first(body, 0x02);
        int declared = countNode == null ? -1 : LdsBytes.u8(countNode.value(), 0);
        for (LdsTlv.Node node : body) {
            if (node.tag < 0xA1 || node.tag > 0xAF) {
                if (node.tag != 0x02) {
                    issues.add(LdsIssue.info(LdsIssue.Code.UNKNOWN_TAG, 16, node.start,
                            String.format("unexpected DG16 tag %02X kept raw", node.tag)));
                }
                continue;
            }
            persons.add(parsePerson(node, issues));
        }
        if (declared >= 0 && declared != persons.size()) {
            issues.add(LdsIssue.warn(LdsIssue.Code.COUNT_MISMATCH, 16, 0,
                    "DG16 declares " + declared + " person(s), found " + persons.size()));
        }
        ParseStatus status;
        if (body.isEmpty()) {
            status = ParseStatus.INVALID;
            issues.add(LdsIssue.error(LdsIssue.Code.MISSING_MANDATORY, 16, 0,
                    "DG16 has no template"));
        } else if (persons.isEmpty()) {
            status = ParseStatus.PARTIAL;
            issues.add(LdsIssue.warn(LdsIssue.Code.MISSING_MANDATORY, 16, 0,
                    "DG16 has no person template (A1..An)"));
        } else {
            status = hasProblems(issues) ? ParseStatus.PARTIAL : ParseStatus.OK;
        }
        return new Dg16(dg16, persons, declared, status, issues);
    }

    private static PersonToNotify parsePerson(LdsTlv.Node node, List<LdsIssue> issues) {
        List<LdsTlv.Node> children = LdsTlv.childrenOf(node, 16, issues);
        String dateRaw = null;
        LdsDate date = null;
        String name = null;
        String telephone = null;
        String address = null;
        Map<Integer, byte[]> unknown = new LinkedHashMap<Integer, byte[]>();
        for (LdsTlv.Node child : children) {
            switch (child.tag) {
            case 0x5F50:
                dateRaw = decodeDate(child.value());
                date = LdsDate.yyyymmdd(dateRaw);
                if (!date.valid) {
                    issues.add(LdsIssue.error(LdsIssue.Code.BAD_DATE, 16, child.start,
                            "date data recorded is not a valid YYYYMMDD date"));
                }
                break;
            case 0x5F51:
                name = text(child, "name", issues);
                break;
            case 0x5F52:
                telephone = text(child, "telephone", issues);
                break;
            case 0x5F53:
                address = text(child, "address", issues);
                break;
            default:
                unknown.put(child.tag, child.value());
                issues.add(LdsIssue.info(LdsIssue.Code.UNKNOWN_TAG, 16, child.start,
                        String.format("unknown DG16 tag %02X kept raw", child.tag)));
                break;
            }
        }
        return new PersonToNotify(node.tag, date, dateRaw, name, telephone, address,
                Collections.unmodifiableMap(unknown), node.encoded());
    }

    private static String text(LdsTlv.Node node, String field, List<LdsIssue> issues) {
        LdsText.Decoded decoded = LdsText.utf8OrLatin1(node.value());
        if (decoded.fallback) {
            issues.add(LdsIssue.warn(LdsIssue.Code.BAD_ENCODING, 16, node.start,
                    field + " is not valid UTF-8; ISO-8859-1 used"));
        }
        return decoded.text;
    }

    /** Decodes an 8-byte ASCII or 4-byte BCD date. */
    static String decodeDate(byte[] value) {
        if (value == null) {
            return null;
        }
        if (value.length >= 8 && LdsText.isAscii(value)) {
            return new String(value, 0, 8, java.nio.charset.StandardCharsets.US_ASCII);
        }
        if (value.length == 4) {
            StringBuilder b = new StringBuilder(8);
            for (byte v : value) {
                int hi = (v >> 4) & 0x0F;
                int lo = v & 0x0F;
                if (hi > 9 || lo > 9) {
                    return LdsText.latin1(value);
                }
                b.append((char) ('0' + hi)).append((char) ('0' + lo));
            }
            return b.toString();
        }
        return LdsText.utf8OrLatin1(value).text;
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
        return 16;
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
