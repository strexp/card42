package card42.host.emrtd.report;


import java.util.List;
import java.util.Map;

import card42.host.common.codec.Json;
import card42.host.common.codec.TlvCursor;
import card42.host.common.util.Hex;
import card42.host.emrtd.lds.common.CardAccess;
import card42.host.emrtd.lds.lds1.Com;
import card42.host.emrtd.lds.lds1.Dg1;
import card42.host.emrtd.lds.lds1.Dg15;
import card42.host.emrtd.lds.lds1.Dg2;
import card42.host.emrtd.lds.lds2.Lds2Record;
import card42.host.emrtd.lds.security.SecurityInfo;
import card42.host.emrtd.pa.Lds2Verifier;

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
     * and the record count/outer tags of one record EF (H7.4).  The named-EF
     * overloads also append the structured {@link Lds2Record} fields.
     */
    public static String lds2Text(CardAccess access, List<byte[]> records) {
        StringBuilder b = new StringBuilder();
        appendAccess(b, access);
        if (records != null) {
            b.append("Records         : ").append(records.size()).append('\n');
            for (int i = 0; i < records.size(); i++) {
                b.append("  record ").append(i + 1).append(" (").append(records.get(i).length)
                        .append(" B) tags: ").append(outerTags(records.get(i))).append('\n');
            }
        }
        return b.toString();
    }

    /**
     * An LDS2 report over several named record EFs (Entry/Exit/Visa/Certificates),
     * e.g. {@code "EF.EntryRecords (0101)" -> records}.  Top-level record DOs
     * are listed in file order; use {@code -json=1} for the hex payloads.
     */
    public static String lds2Text(CardAccess access, Map<String, List<byte[]>> groups) {
        return lds2Text(access, groups, null);
    }

    /**
     * The named-EF LDS2 report with optional authenticity results.  When
     * {@code verification} is supplied, each record is followed by its
     * signature/profile/trust status (Doc 9303-10 §5, Doc 9303-12 §7.1.2).
     */
    public static String lds2Text(CardAccess access, Map<String, List<byte[]>> groups,
                                  Map<String, List<Lds2Verifier.Verification>> verification) {
        StringBuilder b = new StringBuilder();
        appendAccess(b, access);
        if (groups != null) {
            for (Map.Entry<String, List<byte[]>> group : groups.entrySet()) {
                List<byte[]> records = group.getValue();
                List<Lds2Verifier.Verification> results =
                        verification == null ? null : verification.get(group.getKey());
                b.append(group.getKey()).append(": ").append(records.size())
                        .append(" record(s)\n");
                for (int i = 0; i < records.size(); i++) {
                    byte[] record = records.get(i);
                    b.append("  record ").append(i + 1).append(" (")
                            .append(record.length).append(" B) tags: ")
                            .append(outerTags(record)).append('\n');
                    indent(b, Lds2Record.parse(Lds2Record.Kind.forLabel(group.getKey()), record).toText(), "    ");
                    if (results != null && i < results.size()) {
                        b.append("    ").append(verificationText(results.get(i))).append('\n');
                    }
                }
            }
        }
        return b.toString();
    }

    private static String verificationText(Lds2Verifier.Verification result) {
        Lds2Verifier.CertificateCheck check = result.certificate;
        boolean certificate = result.label != null
                && Lds2Record.Kind.forLabel(result.label) == Lds2Record.Kind.CERTIFICATE;
        StringBuilder b = new StringBuilder("verification      : ");
        b.append(result.valid() ? "valid" : "INVALID");
        b.append(" (").append(certificate ? "certificate" : "signature");
        if (!certificate) {
            b.append('=').append(result.signatureValid);
        }
        b.append(", profile=").append(check != null && check.profileValid);
        b.append(", trust=").append(check != null && check.trusted);
        if (check != null && check.subject != null) {
            b.append(", signer=").append(check.subject);
        }
        b.append(')');
        if (!result.problems.isEmpty()) {
            b.append(" -- ").append(String.join("; ", result.problems));
        }
        return b.toString();
    }

    private static void appendAccess(StringBuilder b, CardAccess access) {
        if (access == null) {
            return;
        }
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
                recordArr.raw(recordJson(null, record).build());
            }
            out.raw("records", recordArr.build());
        }
        return out.build();
    }

    /**
     * A minimal JSON object for several named LDS2 record EFs: the same
     * {@code securityInfos} plus a {@code recordFiles} object whose values are
     * arrays of {@code {length, tags, hex, parsed}}.
     */
    public static String lds2Json(CardAccess access, Map<String, List<byte[]>> groups) {
        return lds2Json(access, groups, null);
    }

    public static String lds2Json(CardAccess access, Map<String, List<byte[]>> groups,
                                  Map<String, List<Lds2Verifier.Verification>> verification) {
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
        if (groups != null) {
            Json.Obj files = new Json.Obj();
            for (Map.Entry<String, List<byte[]>> group : groups.entrySet()) {
                List<Lds2Verifier.Verification> results =
                        verification == null ? null : verification.get(group.getKey());
                Json.Arr recordArr = new Json.Arr();
                for (int i = 0; i < group.getValue().size(); i++) {
                    Lds2Verifier.Verification result =
                            results != null && i < results.size() ? results.get(i) : null;
                    recordArr.raw(recordJson(group.getKey(), group.getValue().get(i), result)
                            .build());
                }
                files.raw(group.getKey(), recordArr.build());
            }
            out.raw("recordFiles", files.build());
        }
        return out.build();
    }

    private static Json.Obj recordJson(String label, byte[] record) {
        return recordJson(label, record, null);
    }

    private static Json.Obj recordJson(String label, byte[] record,
                                       Lds2Verifier.Verification verification) {
        Json.Obj out = new Json.Obj()
                .put("length", record.length)
                .put("tags", outerTags(record))
                .put("hex", Hex.format(record))
                .raw("parsed", Lds2Record.parse(Lds2Record.Kind.forLabel(label), record).toJson());
        if (verification != null) {
            Lds2Verifier.CertificateCheck check = verification.certificate;
            Json.Arr problems = new Json.Arr();
            for (String problem : verification.problems) {
                problems.add(problem);
            }
            boolean certificate = label != null
                    && Lds2Record.Kind.forLabel(label) == Lds2Record.Kind.CERTIFICATE;
            Json.Obj verificationJson = new Json.Obj()
                    .put("valid", verification.valid())
                    .put("profileValid", check != null && check.profileValid)
                    .put("trusted", check != null && check.trusted)
                    .put("signer", check == null ? null : check.subject)
                    .raw("problems", problems.build());
            if (!certificate) {
                verificationJson.put("signatureValid", verification.signatureValid);
            }
            out.raw("verification", verificationJson.build());
        }
        return out;
    }

    private static void indent(StringBuilder out, String text, String prefix) {
        int start = 0;
        while (start < text.length()) {
            int end = text.indexOf('\n', start);
            if (end < 0) {
                out.append(prefix).append(text.substring(start)).append('\n');
                return;
            }
            out.append(prefix).append(text, start, end + 1);
            start = end + 1;
        }
    }

    /**
     * The top-level DO tags of a record, in order.  A LDS2 record is a sequence
     * of data objects (Travel: 5F44 || 73 || 5F37 || 5F38; Visa: 5F28 || 71 ||
     * 5F37 || 5F38), not one TLV with children, so the cursor walks the whole
     * record rather than descending into the first object.
     */
    private static String outerTags(byte[] record) {
        StringBuilder b = new StringBuilder();
        TlvCursor cursor = new TlvCursor(record);
        while (cursor.next() == TlvCursor.Status.OK) {
            if (b.length() > 0) {
                b.append(' ');
            }
            b.append(String.format("%02X", cursor.tag()));
        }
        return b.toString();
    }
}
