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
 * Data group 12: additional document detail(s) (ICAO Doc 9303-10 §4.7.12,
 * Table 73).
 *
 * <p>DG12 = {@code 6C { 5C tag list, 5F19, 5F26, A0 { 02, 5F1A... }, 5F1B,
 * 5F1C, 5F1D, 5F1E, 5F55, 5F56 }}.  The personalization date/time is accepted
 * in both the ASCII and the BCD encoding the standard allows.
 */
public final class Dg12 implements LdsDataGroup {

    public final byte[] raw;
    public final List<Integer> declaredTags;
    public final String issuingAuthority;
    public final String dateOfIssueRaw;
    public final LdsDate dateOfIssue;
    public final List<String> otherPersons;
    public final String endorsements;
    public final String taxExitRequirements;
    public final ImageData frontImage;
    public final ImageData rearImage;
    /** Date/time of personalization as 14 digits, or the raw text. */
    public final String personalizationDateTime;
    public final LdsDate personalizationDate;
    public final String personalizationSystemSerial;
    public final Map<Integer, byte[]> unknown;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    private Dg12(byte[] raw, List<Integer> declaredTags, String issuingAuthority,
                 String dateOfIssueRaw, LdsDate dateOfIssue, List<String> otherPersons,
                 String endorsements, String taxExitRequirements, ImageData frontImage,
                 ImageData rearImage, String personalizationDateTime,
                 LdsDate personalizationDate, String personalizationSystemSerial,
                 Map<Integer, byte[]> unknown, ParseStatus status, List<LdsIssue> issues) {
        this.raw = LdsBytes.copy(raw);
        this.declaredTags = Collections.unmodifiableList(new ArrayList<Integer>(declaredTags));
        this.issuingAuthority = issuingAuthority;
        this.dateOfIssueRaw = dateOfIssueRaw;
        this.dateOfIssue = dateOfIssue;
        this.otherPersons = Collections.unmodifiableList(new ArrayList<String>(otherPersons));
        this.endorsements = endorsements;
        this.taxExitRequirements = taxExitRequirements;
        this.frontImage = frontImage;
        this.rearImage = rearImage;
        this.personalizationDateTime = personalizationDateTime;
        this.personalizationDate = personalizationDate;
        this.personalizationSystemSerial = personalizationSystemSerial;
        this.unknown = Collections.unmodifiableMap(unknown);
        this.status = status;
        this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(issues));
    }

    /** Parses a DG12 EF. */
    public static Dg12 parse(byte[] dg12) {
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(dg12, 0x6C, 12, issues);
        List<Integer> declaredTags = new ArrayList<Integer>();
        String authority = null;
        String issueRaw = null;
        LdsDate issueDate = null;
        List<String> otherPersons = new ArrayList<String>();
        String endorsements = null;
        String tax = null;
        ImageData front = null;
        ImageData rear = null;
        String personalization = null;
        LdsDate personalizationDate = null;
        String serial = null;
        Map<Integer, byte[]> unknown = new LinkedHashMap<Integer, byte[]>();
        for (LdsTlv.Node node : body) {
            switch (node.tag) {
            case 0x5C:
                declaredTags.addAll(LdsTlv.tagList(node.value()));
                break;
            case 0x5F19:
                authority = text(node, "issuing authority", issues);
                break;
            case 0x5F26:
                issueRaw = text(node, "date of issue", issues);
                issueDate = LdsDate.yyyymmdd(issueRaw);
                if (!issueDate.valid) {
                    issues.add(LdsIssue.error(LdsIssue.Code.BAD_DATE, 12, node.start,
                            "date of issue is not a valid YYYYMMDD date"));
                }
                break;
            case 0xA0:
                otherPersons.addAll(otherPersons(node, issues));
                break;
            case 0x5F1B:
                endorsements = text(node, "endorsements", issues);
                break;
            case 0x5F1C:
                tax = text(node, "tax/exit requirements", issues);
                break;
            case 0x5F1D:
                front = ImageData.of(node.value(), 0, 0, -1, -1);
                break;
            case 0x5F1E:
                rear = ImageData.of(node.value(), 0, 0, -1, -1);
                break;
            case 0x5F55:
                personalization = decodeDateTime(node.value());
                personalizationDate = LdsDate.yyyymmddhhmmss(personalization);
                if (!personalizationDate.valid) {
                    issues.add(LdsIssue.error(LdsIssue.Code.BAD_DATE, 12, node.start,
                            "personalization date/time is not valid"));
                }
                break;
            case 0x5F56:
                serial = text(node, "personalization system serial", issues);
                break;
            default:
                unknown.put(node.tag, node.value());
                issues.add(LdsIssue.info(LdsIssue.Code.UNKNOWN_TAG, 12, node.start,
                        String.format("unknown DG12 tag %02X kept raw", node.tag)));
                break;
            }
        }
        ParseStatus status;
        if (dg12 == null || dg12.length == 0) {
            status = ParseStatus.INVALID;
        } else if (hasProblems(issues)) {
            status = ParseStatus.PARTIAL;
        } else {
            status = ParseStatus.OK;
        }
        return new Dg12(dg12, declaredTags, authority, issueRaw, issueDate, otherPersons,
                endorsements, tax, front, rear, personalization, personalizationDate,
                serial, unknown, status, issues);
    }

    private static List<String> otherPersons(LdsTlv.Node container, List<LdsIssue> issues) {
        List<String> out = new ArrayList<String>();
        for (LdsTlv.Node child : LdsTlv.childrenOf(container, 12, issues)) {
            if (child.tag == 0x5F1A) {
                out.add(text(child, "other person", issues));
            }
        }
        return out;
    }

    /**
     * Decodes {@code 5F55}: 14 ASCII digits (YYYYMMDDhhmmss) or, as Doc
     * 9303-10 §4.7.12 allows, 7 bytes of BCD.
     */
    static String decodeDateTime(byte[] value) {
        if (value == null) {
            return null;
        }
        if (value.length >= 14 && LdsText.isAscii(value)) {
            return new String(value, 0, 14, java.nio.charset.StandardCharsets.US_ASCII);
        }
        if (value.length == 7) {
            StringBuilder b = new StringBuilder(14);
            for (byte v : value) {
                int hi = (v >> 4) & 0x0F;
                int lo = v & 0x0F;
                if (hi > 9 || lo > 9) {
                    return LdsText.utf8OrLatin1(value).text;
                }
                b.append((char) ('0' + hi)).append((char) ('0' + lo));
            }
            return b.toString();
        }
        return LdsText.utf8OrLatin1(value).text;
    }

    private static String text(LdsTlv.Node node, String field, List<LdsIssue> issues) {
        LdsText.Decoded decoded = LdsText.utf8OrLatin1(node.value());
        if (decoded.fallback) {
            issues.add(LdsIssue.warn(LdsIssue.Code.BAD_ENCODING, 12, node.start,
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
        return 12;
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
