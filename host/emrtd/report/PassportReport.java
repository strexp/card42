package card42.host.emrtd.report;

import java.util.ArrayList;
import java.util.List;

import card42.host.common.codec.Tags;
import card42.host.emrtd.lds.CardAccess;
import card42.host.emrtd.lds.Com;
import card42.host.emrtd.lds.Dg1;
import card42.host.emrtd.lds.Dg15;
import card42.host.emrtd.lds.Dg2;
import card42.host.emrtd.lds.SecurityInfo;

/**
 * Text / JSON rendering of a read eMRTD (H1.5).  It deliberately depends only
 * on the parsed data objects, so the CLI can print a report without the
 * reader.
 */
public final class PassportReport {

    private PassportReport() {
    }

    /** A human-readable multi-line report. */
    public static String text(Dg1 dg1, Com com, Dg15 dg15, Dg2 dg2) {
        StringBuilder b = new StringBuilder();
        if (dg1 != null) {
            b.append("Document number : ").append(dg1.documentNumber).append('\n');
            b.append("Surname         : ").append(dg1.surname).append('\n');
            b.append("Given names     : ").append(dg1.givenNames).append('\n');
            b.append("Nationality     : ").append(dg1.nationality).append('\n');
            b.append("Issuing state   : ").append(dg1.issuingState).append('\n');
            b.append("Date of birth   : ").append(dg1.dateOfBirth).append('\n');
            b.append("Sex             : ").append(dg1.sex).append('\n');
            b.append("Date of expiry  : ").append(dg1.dateOfExpiry).append('\n');
        }
        if (com != null) {
            b.append("LDS version     : ").append(com.ldsVersion)
                    .append(" (unicode ").append(com.unicodeVersion).append(")\n");
            b.append("Data groups     : ");
            for (int i = 0; i < com.dataGroupTags.length; i++) {
                b.append(String.format("%02X", com.dataGroupTags[i]));
                if (i + 1 < com.dataGroupTags.length) {
                    b.append(' ');
                }
            }
            b.append('\n');
        }
        if (dg2 != null && dg2.image != null) {
            b.append("Face image      : ").append(dg2.image.length)
                    .append(" B JPEG/JP2\n");
        }
        if (dg15 != null) {
            if (dg15.ecdsa) {
                b.append("Active auth key : ECDSA\n");
            } else {
                b.append("Active auth key : RSA-").append(dg15.modulus.bitLength()).append('\n');
            }
        }
        return b.toString();
    }

    /**
     * A minimal JSON object.  Fields are collected first and joined with commas
     * so the object is always well formed, whatever subset of the data groups is
     * present (in particular when the last field, e.g. {@code aaModulusBits},
     * has no successor).
     */
    public static String json(Dg1 dg1, Com com, Dg15 dg15, Dg2 dg2) {
        List<String> fields = new ArrayList<String>();
        if (dg1 != null) {
            fields.add(field("documentNumber", dg1.documentNumber));
            fields.add(field("surname", dg1.surname));
            fields.add(field("givenNames", dg1.givenNames));
            fields.add(field("nationality", dg1.nationality));
            fields.add(field("issuingState", dg1.issuingState));
            fields.add(field("dateOfBirth", dg1.dateOfBirth));
            fields.add(field("sex", dg1.sex));
            fields.add(field("dateOfExpiry", dg1.dateOfExpiry));
        }
        if (com != null) {
            fields.add(field("ldsVersion", com.ldsVersion));
            fields.add(field("unicodeVersion", com.unicodeVersion));
        }
        if (dg2 != null && dg2.image != null) {
            fields.add(field("faceImageBytes", Integer.toString(dg2.image.length)));
        }
        if (dg15 != null) {
            if (dg15.ecdsa) {
                fields.add(field("aaKeyType", "ECDSA"));
            } else {
                fields.add(field("aaModulusBits", Integer.toString(dg15.modulus.bitLength())));
            }
        }
        StringBuilder b = new StringBuilder("{\n");
        for (int i = 0; i < fields.size(); i++) {
            b.append("  ").append(fields.get(i));
            if (i + 1 < fields.size()) {
                b.append(',');
            }
            b.append('\n');
        }
        b.append("}\n");
        return b.toString();
    }

    /**
     * An LDS2 report: the advertised SecurityInfos (PACE / Chip Authentication)
     * and the record count and outer tags of each record EF (H7.4).
     */
    public static String lds2Text(CardAccess access, List<byte[]> records) {
        StringBuilder b = new StringBuilder();
        if (access != null) {
            b.append("CardAccess      : ").append(access.securityInfos.size())
                    .append(" SecurityInfo(s)\n");
            for (SecurityInfo info : access.securityInfos) {
                b.append("  ").append(info.typeName())
                        .append("  ").append(info.oid).append('\n');
                String detail = info.describe();
                if (!detail.isEmpty()) {
                    b.append("    ").append(detail).append('\n');
                }
            }
        }
        if (records != null) {
            b.append("Records         : ").append(records.size()).append('\n');
            for (int i = 0; i < records.size(); i++) {
                b.append("  record ").append(i + 1).append(" (").append(records.get(i).length)
                        .append(" B) tags: ").append(outerTags(records.get(i))).append('\n');
            }
        }
        return b.toString();
    }

    /** A minimal JSON object for an LDS2 read. */
    public static String lds2Json(CardAccess access, List<byte[]> records) {
        StringBuilder b = new StringBuilder("{\n");
        if (access != null) {
            b.append("  \"securityInfos\": [\n");
            for (int i = 0; i < access.securityInfos.size(); i++) {
                SecurityInfo info = access.securityInfos.get(i);
                b.append("    {\"type\": \"").append(info.typeName())
                        .append("\", \"oid\": \"").append(info.oid).append("\"}");
                b.append(i + 1 < access.securityInfos.size() ? ",\n" : "\n");
            }
            b.append("  ]");
            if (records != null) {
                b.append(',');
            }
            b.append('\n');
        }
        if (records != null) {
            b.append("  \"recordCount\": ").append(records.size()).append(",\n");
            b.append("  \"records\": [\n");
            for (int i = 0; i < records.size(); i++) {
                b.append("    {\"length\": ").append(records.get(i).length)
                        .append(", \"tags\": \"").append(outerTags(records.get(i))).append("\"}");
                b.append(i + 1 < records.size() ? ",\n" : "\n");
            }
            b.append("  ]\n");
        }
        b.append("}\n");
        return b.toString();
    }

    private static String outerTags(byte[] record) {
        StringBuilder b = new StringBuilder();
        int tag = record.length > 0 ? (record[0] & 0xFF) : 0;
        b.append(String.format("%02X", tag));
        byte[] inner = Tags.find(record, tag);
        if (inner != null) {
            int p = 0;
            while (p < inner.length) {
                int t = inner[p] & 0xFF;
                int tagLen = ((t & 0x1F) == 0x1F) ? 2 : 1;
                if (p + tagLen > inner.length) {
                    break;
                }
                int full = tagLen == 2
                        ? ((t << 8) | (inner[p + 1] & 0xFF)) : t;
                b.append(' ').append(String.format("%02X", full));
                int lOff = p + tagLen;
                if (lOff >= inner.length) {
                    break;
                }
                int lb = inner[lOff] & 0xFF;
                int lLen = (lb & 0x80) == 0 ? 1 : 1 + (lb & 0x7F);
                int vLen = (lb & 0x80) == 0 ? lb : 0;
                if ((lb & 0x80) != 0) {
                    for (int i = 0; i < (lb & 0x7F); i++) {
                        vLen = (vLen << 8) | (inner[lOff + 1 + i] & 0xFF);
                    }
                }
                p = lOff + lLen + vLen;
            }
        }
        return b.toString();
    }

    /** One {@code "name": "value"} pair with the value JSON-escaped. */
    private static String field(String name, String value) {
        return "\"" + name + "\": \"" + escape(value) + "\"";
    }

    /** Escapes the characters JSON requires to be escaped (RFC 8259 §7). */
    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder b = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
            case '"':
                b.append("\\\"");
                break;
            case '\\':
                b.append("\\\\");
                break;
            case '\n':
                b.append("\\n");
                break;
            case '\r':
                b.append("\\r");
                break;
            case '\t':
                b.append("\\t");
                break;
            default:
                if (c < 0x20) {
                    b.append(String.format("\\u%04x", (int) c));
                } else {
                    b.append(c);
                }
            }
        }
        return b.toString();
    }
}
