package card42.host.emrtd.report;

import java.util.List;

import card42.host.common.codec.Json;
import card42.host.common.codec.TlvCursor;
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
        Json.Obj out = new Json.Obj();
        if (dg1 != null) {
            out.put("documentNumber", dg1.documentNumber)
                    .put("surname", dg1.surname)
                    .put("givenNames", dg1.givenNames)
                    .put("nationality", dg1.nationality)
                    .put("issuingState", dg1.issuingState)
                    .put("dateOfBirth", dg1.dateOfBirth)
                    .put("sex", dg1.sex)
                    .put("dateOfExpiry", dg1.dateOfExpiry);
        }
        if (com != null) {
            out.put("ldsVersion", com.ldsVersion)
                    .put("unicodeVersion", com.unicodeVersion);
        }
        if (dg2 != null && dg2.image != null) {
            out.put("faceImageBytes", dg2.image.length);
        }
        if (dg15 != null) {
            if (dg15.ecdsa) {
                out.put("aaKeyType", "ECDSA");
            } else {
                out.put("aaModulusBits", dg15.modulus.bitLength());
            }
        }
        return out.build();
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
        Json.Obj out = new Json.Obj();
        if (access != null) {
            Json.Arr infos = new Json.Arr();
            for (SecurityInfo info : access.securityInfos) {
                infos.raw(new Json.Obj()
                        .put("type", info.typeName())
                        .put("oid", info.oid)
                        .build());
            }
            out.raw("securityInfos", infos.build());
        }
        if (records != null) {
            out.put("recordCount", records.size());
            Json.Arr recordArr = new Json.Arr();
            for (byte[] record : records) {
                recordArr.raw(new Json.Obj()
                        .put("length", record.length)
                        .put("tags", outerTags(record))
                        .build());
            }
            out.raw("records", recordArr.build());
        }
        return out.build();
    }

    private static String outerTags(byte[] record) {
        StringBuilder b = new StringBuilder();
        TlvCursor outer = new TlvCursor(record);
        if (outer.next() != TlvCursor.Status.OK) {
            return b.toString();
        }
        b.append(String.format("%02X", outer.tag()));
        TlvCursor inner = outer.child();
        while (inner.next() == TlvCursor.Status.OK) {
            b.append(' ').append(String.format("%02X", inner.tag()));
        }
        return b.toString();
    }
}
