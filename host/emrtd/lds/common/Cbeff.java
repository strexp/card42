package card42.host.emrtd.lds.common;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The CBEFF Biometric Header Template of a biometric data group
 * (ICAO Doc 9303-10 §4.7.2–§4.7.4, ISO/IEC 7816-11).
 *
 * <p>It is the value of the {@code A1} template: 80 header version,
 * 81 biometric type, 82 subtype, 83 creation date, 84 validity period,
 * 85 creator, 86 index, 87 format owner and 88 format type.  Optional and
 * unknown elements are kept raw; nothing is inferred from a missing element.
 */
public final class Cbeff {

    public final byte[] raw;
    /** ICAO header version, e.g. 0x0101, or -1. */
    public final int headerVersion;
    public final int biometricType;
    public final int biometricSubtype;
    /** 8 bytes, or null. */
    public final byte[] creationDate;
    /** 8 bytes, or null. */
    public final byte[] validityPeriod;
    public final int creator;
    public final int index;
    /** CBEFF format owner (0x0101 = JTC1 SC37), or -1. */
    public final int formatOwner;
    /** CBEFF format type, or -1. */
    public final int formatType;
    /** Unknown or vendor-specific BHT elements, by tag. */
    public final Map<Integer, byte[]> unknown;

    private Cbeff(byte[] raw, int headerVersion, int biometricType, int biometricSubtype,
                  byte[] creationDate, byte[] validityPeriod, int creator, int index,
                  int formatOwner, int formatType, Map<Integer, byte[]> unknown) {
        this.raw = raw;
        this.headerVersion = headerVersion;
        this.biometricType = biometricType;
        this.biometricSubtype = biometricSubtype;
        this.creationDate = creationDate;
        this.validityPeriod = validityPeriod;
        this.creator = creator;
        this.index = index;
        this.formatOwner = formatOwner;
        this.formatType = formatType;
        this.unknown = Collections.unmodifiableMap(unknown);
    }

    /** Parses a BHT value, collecting observations in a fresh list. */
    public static Cbeff parse(byte[] bht) {
        return parse(bht, 0, new ArrayList<LdsIssue>());
    }

    /**
     * Parses the value of an {@code A1} template.  A missing element is left
     * as -1/null rather than treated as an error: the CBEFF fields are
     * optional and some cards only carry 87/88.
     */
    public static Cbeff parse(byte[] bht, int dg, List<LdsIssue> issues) {
        List<LdsTlv.Node> nodes = LdsTlv.children(bht, 0,
                bht == null ? 0 : bht.length, dg, issues);
        int headerVersion = -1;
        int biometricType = -1;
        int biometricSubtype = -1;
        byte[] creationDate = null;
        byte[] validityPeriod = null;
        int creator = -1;
        int index = -1;
        int formatOwner = -1;
        int formatType = -1;
        Map<Integer, byte[]> unknown = new LinkedHashMap<Integer, byte[]>();
        for (LdsTlv.Node node : nodes) {
            switch (node.tag) {
            case 0x80:
                headerVersion = LdsBytes.u16(node.value(), 0);
                break;
            case 0x81:
                biometricType = LdsBytes.u8(node.value(), 0);
                break;
            case 0x82:
                biometricSubtype = LdsBytes.u8(node.value(), 0);
                break;
            case 0x83:
                creationDate = node.value();
                break;
            case 0x84:
                validityPeriod = node.value();
                break;
            case 0x85:
                creator = LdsBytes.u16(node.value(), 0);
                break;
            case 0x86:
                index = LdsBytes.u16(node.value(), 0);
                break;
            case 0x87:
                formatOwner = LdsBytes.u16(node.value(), 0);
                break;
            case 0x88:
                formatType = LdsBytes.u16(node.value(), 0);
                break;
            default:
                unknown.put(node.tag, node.value());
                issues.add(LdsIssue.info(LdsIssue.Code.UNKNOWN_TAG, dg, node.start,
                        String.format("unknown CBEFF header tag %02X kept as raw", node.tag)));
                break;
            }
        }
        return new Cbeff(LdsBytes.copy(bht), headerVersion, biometricType, biometricSubtype,
                creationDate, validityPeriod, creator, index, formatOwner, formatType, unknown);
    }
}
