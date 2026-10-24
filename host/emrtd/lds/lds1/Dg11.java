package card42.host.emrtd.lds.lds1;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import card42.host.emrtd.lds.common.ImageData;
import card42.host.emrtd.lds.common.LdsBytes;
import card42.host.emrtd.lds.common.LdsDataGroup;
import card42.host.emrtd.lds.common.LdsDate;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.LdsText;
import card42.host.emrtd.lds.common.LdsTlv;
import card42.host.emrtd.lds.common.ParseStatus;

/**
 * Data group 11: additional personal detail(s) (ICAO Doc 9303-10 §4.7.11,
 * Table 71).
 *
 * <p>DG11 = {@code 6B { 5C tag list, 5F0E, A0 { 02, 5F0F... }, 5F10, 5F2B,
 * 5F11, 5F42, 5F12, 5F13, 5F14, 5F15, 5F16, 5F17, 5F18 }}.  All elements are
 * optional; repeated values are kept as lists and unknown or vendor-specific
 * tags are kept raw instead of being dropped.
 */
public final class Dg11 implements LdsDataGroup {

    public final byte[] raw;
    /** The tag list declared by {@code 5C}, in document order. */
    public final List<Integer> declaredTags;
    /** Full name in national characters (5F0E). */
    public final String fullName;
    /** Other names from the A0 template (5F0F), in order. */
    public final List<String> otherNames;
    /** Personal number (5F10). */
    public final String personalNumber;
    /** Full date of birth as printed (5F2B, YYYYMMDD). */
    public final String fullDateOfBirthRaw;
    public final LdsDate fullDateOfBirth;
    public final String placeOfBirth;
    public final String permanentAddress;
    public final String telephone;
    public final String profession;
    public final String title;
    public final String personalSummary;
    /** Proof of citizenship image (5F16). */
    public final ImageData proofOfCitizenship;
    public final String otherValidTdNumbers;
    public final String custodyInformation;
    /** Unknown or vendor-specific elements, by tag. */
    public final Map<Integer, byte[]> unknown;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    private Dg11(byte[] raw, List<Integer> declaredTags, String fullName,
                 List<String> otherNames, String personalNumber,
                 String fullDateOfBirthRaw, LdsDate fullDateOfBirth,
                 String placeOfBirth, String permanentAddress, String telephone,
                 String profession, String title, String personalSummary,
                 ImageData proofOfCitizenship, String otherValidTdNumbers,
                 String custodyInformation, Map<Integer, byte[]> unknown,
                 ParseStatus status, List<LdsIssue> issues) {
        this.raw = LdsBytes.copy(raw);
        this.declaredTags = Collections.unmodifiableList(new ArrayList<Integer>(declaredTags));
        this.fullName = fullName;
        this.otherNames = Collections.unmodifiableList(new ArrayList<String>(otherNames));
        this.personalNumber = personalNumber;
        this.fullDateOfBirthRaw = fullDateOfBirthRaw;
        this.fullDateOfBirth = fullDateOfBirth;
        this.placeOfBirth = placeOfBirth;
        this.permanentAddress = permanentAddress;
        this.telephone = telephone;
        this.profession = profession;
        this.title = title;
        this.personalSummary = personalSummary;
        this.proofOfCitizenship = proofOfCitizenship;
        this.otherValidTdNumbers = otherValidTdNumbers;
        this.custodyInformation = custodyInformation;
        this.unknown = Collections.unmodifiableMap(unknown);
        this.status = status;
        this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(issues));
    }

    /** Parses a DG11 EF. */
    public static Dg11 parse(byte[] dg11) {
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(dg11, 0x6B, 11, issues);
        List<Integer> declaredTags = new ArrayList<Integer>();
        String fullName = null;
        List<String> otherNames = new ArrayList<String>();
        String personalNumber = null;
        String fullDateRaw = null;
        LdsDate fullDate = null;
        String placeOfBirth = null;
        String address = null;
        String telephone = null;
        String profession = null;
        String title = null;
        String summary = null;
        ImageData citizenship = null;
        String otherTd = null;
        String custody = null;
        Map<Integer, byte[]> unknown = new LinkedHashMap<Integer, byte[]>();
        for (LdsTlv.Node node : body) {
            switch (node.tag) {
            case 0x5C:
                declaredTags.addAll(LdsTlv.tagList(node.value()));
                break;
            case 0x5F0E:
                fullName = text(node, "full name", issues);
                break;
            case 0xA0:
                otherNames.addAll(otherNames(node, issues));
                break;
            case 0x5F10:
                personalNumber = text(node, "personal number", issues);
                break;
            case 0x5F2B:
                fullDateRaw = text(node, "full date of birth", issues);
                fullDate = LdsDate.yyyymmdd(fullDateRaw);
                if (!fullDate.valid) {
                    issues.add(LdsIssue.error(LdsIssue.Code.BAD_DATE, 11, node.start,
                            "full date of birth is not a valid YYYYMMDD date"));
                }
                break;
            case 0x5F11:
                placeOfBirth = text(node, "place of birth", issues);
                break;
            case 0x5F42:
                address = text(node, "permanent address", issues);
                break;
            case 0x5F12:
                telephone = text(node, "telephone", issues);
                break;
            case 0x5F13:
                profession = text(node, "profession", issues);
                break;
            case 0x5F14:
                title = text(node, "title", issues);
                break;
            case 0x5F15:
                summary = text(node, "personal summary", issues);
                break;
            case 0x5F16:
                citizenship = ImageData.of(node.value(), 0, 0, -1, -1);
                break;
            case 0x5F17:
                otherTd = text(node, "other valid TD numbers", issues);
                break;
            case 0x5F18:
                custody = text(node, "custody information", issues);
                break;
            default:
                unknown.put(node.tag, node.value());
                issues.add(LdsIssue.info(LdsIssue.Code.UNKNOWN_TAG, 11, node.start,
                        String.format("unknown DG11 tag %02X kept raw", node.tag)));
                break;
            }
        }
        ParseStatus status;
        if (dg11 == null || dg11.length == 0) {
            status = ParseStatus.INVALID;
        } else if (hasProblems(issues)) {
            status = ParseStatus.PARTIAL;
        } else {
            status = ParseStatus.OK;
        }
        return new Dg11(dg11, declaredTags, fullName, otherNames, personalNumber,
                fullDateRaw, fullDate, placeOfBirth, address, telephone, profession,
                title, summary, citizenship, otherTd, custody, unknown, status, issues);
    }

    private static List<String> otherNames(LdsTlv.Node container, List<LdsIssue> issues) {
        List<String> out = new ArrayList<String>();
        for (LdsTlv.Node child : LdsTlv.childrenOf(container, 11, issues)) {
            if (child.tag == 0x5F0F) {
                out.add(text(child, "other name", issues));
            }
        }
        return out;
    }

    private static String text(LdsTlv.Node node, String field, List<LdsIssue> issues) {
        LdsText.Decoded decoded = LdsText.utf8OrLatin1(node.value());
        if (decoded.fallback) {
            issues.add(LdsIssue.warn(LdsIssue.Code.BAD_ENCODING, 11, node.start,
                    field + " is not valid UTF-8; ISO-8859-1 used"));
        }
        return decoded.text;
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
        return 11;
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
