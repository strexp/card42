package card42.test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import card42.host.common.codec.DerWriter;
import card42.host.common.codec.TlvWriter;
import card42.host.common.util.Hex;
import card42.host.emrtd.lds.Com;
import card42.host.emrtd.lds.Dg1;
import card42.host.emrtd.lds.Dg15;
import card42.host.emrtd.lds.CertificateRecord;
import card42.host.emrtd.lds.CertificateRecordBuilder;
import card42.host.emrtd.lds.Dg2;
import card42.host.emrtd.lds.Lds2Record;
import card42.host.emrtd.lds.TravelRecord;
import card42.host.emrtd.lds.TravelRecordBuilder;
import card42.host.emrtd.lds.VisaRecord;
import card42.host.emrtd.lds.VisaRecordBuilder;
import card42.host.emrtd.tools.EmrtdPersoExporter;
import card42.host.emrtd.report.PassportReport;

/**
 * Tests for the eMRTD text/JSON report ({@code host/emrtd/report/PassportReport}).
 *
 * <p>The JSON renderer must always emit a well-formed object, including when the
 * last field present is one that used to be the "trailing comma" case (e.g. the
 * AA modulus when EF.DG15 is absent).  Every document is checked with a strict
 * recursive-descent JSON parser rather than a substring match, so a dangling
 * comma or an unescaped quote fails the suite.
 */
final class PassportReportTest {

    private static final String LINE1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    private static final String LINE2 = "L898902C<3UTO6908061F9406236ZE184226B<<<<<10";

    private PassportReportTest() {
    }

    static void run() throws Exception {
        System.out.println("PassportReport");

        // Every data group absent: an empty object is still valid JSON.
        strictJson(PassportReport.json(null, null, null, null), "empty object");

        // DG1 + COM + DG2 but no DG15: the previous renderer left a trailing
        // comma after "faceImageBytes" (the field with comma=true when DG15 is
        // absent was "dateOfExpiry"/"unicodeVersion"; the bug also hit the
        // aaModulusBits-last case below).
        Dg1 dg1 = dg1();
        Com com = com("0107", "040001");
        Dg2 dg2 = dg2();
        String noAa = PassportReport.json(dg1, com, null, dg2);
        strictJson(noAa, "DG1+COM+DG2 without DG15");
        Asserts.check(noAa.contains("\"faceImageBytes\""), "report carries the face image size");
        Asserts.check(!noAa.contains(",\n}"), "no dangling comma without DG15");

        // DG15 present: the AA modulus is the last field.
        Dg15 dg15 = dg15();
        String withAa = PassportReport.json(dg1, com, dg15, dg2);
        strictJson(withAa, "DG1+COM+DG2+DG15");
        Asserts.check(withAa.contains("\"aaModulusBits\""), "report carries the AA modulus size");

        // Only DG15: the object has a single field and no comma.
        String onlyAa = PassportReport.json(null, null, dg15, null);
        strictJson(onlyAa, "DG15 only");

        // Values that need JSON escaping must be escaped.
        Com quoted = com("\"\\\n\t", "040001");
        String escaped = PassportReport.json(null, quoted, null, null);
        strictJson(escaped, "quoted/backslash/control values");
        Asserts.check(escaped.contains("\\\"") && escaped.contains("\\\\"),
                "quotes and backslashes are escaped");

        lds2Records();
    }

    /**
     * LDS2 records are a sequence of top-level DOs (Travel: 5F44 || 73 || 5F37
     * || 5F38).  The report must list those tags in order, not descend into the
     * first DO's value, and the named-record JSON must be well formed.
     */
    private static void lds2Records() throws Exception {
        byte[] record = Hex.parse("5F440355534173035F45015F3701005F380101");
        Map<String, List<byte[]>> groups = new LinkedHashMap<>();
        groups.put("EF.EntryRecords (0101)", List.of(record));
        String text = PassportReport.lds2Text(null, groups);
        Asserts.check(text.contains("tags: 5F44 73 5F37 5F38"),
                "LDS2 report lists the top-level record DOs (" + text + ")");
        Asserts.check(text.contains("EF.EntryRecords (0101): 1 record(s)"),
                "LDS2 report names the record EF");
        String json = PassportReport.lds2Json(null, groups);
        strictJson(json, "LDS2 named record files");
        Asserts.check(json.contains("\"recordFiles\"") && json.contains("\"hex\""),
                "LDS2 JSON carries the record files and hex payload");

        // A complete Table 86 Travel record: the fields inside DO'73' must be
        // decoded, not just the top-level tags.
        byte[] travelInfo = cat(
                tlv(0x5F44, ascii("USA")),
                tlv(0x5F45, ascii("20260101")),
                tlv(0x5F4B, ascii("CBP")),
                tlv(0x5F46, ascii("SFO")),
                tlv(0x5F4A, ascii("SFO00001")));
        byte[] travel = cat(tlv(0x5F44, ascii("USA")), tlv(0x73, travelInfo),
                tlv(0x5F37, new byte[] { 1, 2, 3, 4 }), tlv(0x5F38, new byte[] { 1 }));
        Map<String, List<byte[]>> travelGroups = new LinkedHashMap<>();
        travelGroups.put("EF.EntryRecords (0101)", List.of(travel));
        String travelText = PassportReport.lds2Text(null, travelGroups);
        Asserts.check(travelText.contains("travelDate        : 20260101")
                        && travelText.contains("inspectionAuthority: CBP"),
                "structured Travel record fields are rendered (" + travelText + ")");
        String travelJson = PassportReport.lds2Json(null, travelGroups);
        strictJson(travelJson, "structured Travel record JSON");
        Asserts.check(travelJson.contains("\"wellFormed\":true")
                        && travelJson.contains("\"travelDate\":\"20260101\""),
                "structured Travel record JSON carries the fields");

        // A Visa record: 5F28 || 71{...} || 5F37 || 5F38.
        byte[] visaInfo = cat(
                tlv(0x5F28, ascii("NLD")),
                tlv(0x43, ascii("VS")),
                tlv(0x49, ascii("NEW YORK")),
                tlv(0x5F25, ascii("20260101")),
                tlv(0x5F24, ascii("20270101")),
                tlv(0x5A, ascii("X1234567")),
                tlv(0x5B, ascii("DOE JOHN")),
                tlv(0x5F33, ascii("DOE")),
                tlv(0x5F34, ascii("JOHN")),
                tlv(0x5F35, ascii("M")),
                tlv(0x5F2B, ascii("19900101")),
                tlv(0x5F2C, ascii("NLD")),
                tlv(0x5F1F, ascii("V<NLDDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")));
        byte[] visa = cat(tlv(0x5F28, ascii("NLD")), tlv(0x71, visaInfo),
                tlv(0x5F37, new byte[] { 9, 9 }), tlv(0x5F38, new byte[] { 2 }));
        Map<String, List<byte[]>> visaGroups = new LinkedHashMap<>();
        visaGroups.put("EF.VisaRecords (0103)", List.of(visa));
        String visaText = PassportReport.lds2Text(null, visaGroups);
        Asserts.check(visaText.contains("issuingState      : NLD")
                        && visaText.contains("documentType      : VS")
                        && visaText.contains("placeOfIssue      : NEW YORK"),
                "structured Visa record fields are rendered (" + visaText + ")");
        String visaJson = PassportReport.lds2Json(null, visaGroups);
        strictJson(visaJson, "structured Visa record JSON");
        Asserts.check(visaJson.contains("\"wellFormed\":true")
                        && visaJson.contains("\"issuingState\":\"NLD\""),
                "structured Visa record JSON carries the fields");

        // EF.Certificates: 5F3A { country || serial } || 72 { X.509 }.
        byte[] cert = cat(tlv(0x5F3A, Hex.parse("55530102")),
                tlv(0x72, Hex.parse("3003010203")));
        Map<String, List<byte[]>> certGroups = new LinkedHashMap<>();
        certGroups.put("EF.Certificates (011A)", List.of(cert));
        String certText = PassportReport.lds2Text(null, certGroups);
        Asserts.check(certText.contains("country           : US")
                        && certText.contains("serialNumber      : 0102"),
                "structured Certificate record fields are rendered (" + certText + ")");
        String certJson = PassportReport.lds2Json(null, certGroups);
        strictJson(certJson, "structured Certificate record JSON");
        Asserts.check(certJson.contains("\"wellFormed\":true")
                        && certJson.contains("\"certificateBytes\":5"),
                "structured Certificate record JSON carries the X.509 length");

        builders();
    }

    /** Round-trips the structured writers through the readers (no card). */
    private static void builders() throws Exception {
        java.security.PrivateKey key =
                EmrtdPersoExporter.loadPrivateKey("perso/emrtd/dsc.key");

        byte[] travel = new TravelRecordBuilder()
                .state("USA").travelDate("20260101").inspectionAuthority("CBP")
                .inspectionLocation("SFO").inspectorReference("SFO00001")
                .certificateReference(1).build(key);
        TravelRecord travelRecord = (TravelRecord) Lds2Record.parse(
                "EF.EntryRecords (0101)", travel);
        Asserts.check(travelRecord.wellFormed && "USA".equals(travelRecord.state)
                        && "20260101".equals(travelRecord.travelDate()),
                "TravelRecordBuilder round-trips through TravelRecord");

        byte[] visa = new VisaRecordBuilder()
                .issuingState("NLD").documentType("VS").placeOfIssue("NEW YORK")
                .effectiveDate("20260101").expirationDate("20270101")
                .documentNumber("X1234567").name("DOE JOHN").surname("DOE")
                .givenNames("JOHN").sex("M").dateOfBirth("19900101")
                .nationality("NLD")
                .mrz("V<NLDDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
                .certificateReference(2).build(key);
        VisaRecord visaRecord = (VisaRecord) Lds2Record.parse(
                "EF.VisaRecords (0103)", visa);
        Asserts.check(visaRecord.wellFormed && "NLD".equals(visaRecord.issuingState)
                        && "VS".equals(visaRecord.documentType())
                        && Integer.valueOf(2).equals(visaRecord.certificateReference),
                "VisaRecordBuilder round-trips through VisaRecord");

        byte[] cert = new CertificateRecordBuilder().country("US")
                .serialNumber(Hex.parse("0102")).certificate(Hex.parse("3003010203"))
                .build();
        CertificateRecord certRecord = (CertificateRecord) Lds2Record.parse(
                "EF.Certificates (011A)", cert);
        Asserts.check(certRecord.wellFormed && "US".equals(certRecord.country)
                        && "0102".equals(certRecord.serialNumber),
                "CertificateRecordBuilder round-trips through CertificateRecord");
    }

    /** Parses the whole document strictly and asserts it is a JSON object. */
    private static void strictJson(String document, String what) {
        try {
            JsonParser parser = new JsonParser(document);
            parser.parseValue();
            parser.skipWhitespace();
            if (!parser.atEnd()) {
                throw new IllegalArgumentException("trailing data");
            }
            Asserts.check(true, "strict JSON: " + what);
        } catch (RuntimeException e) {
            Asserts.check(false, "strict JSON: " + what + " (" + e.getMessage() + ")");
        }
    }

    private static Dg1 dg1() {
        return Dg1.parse(tlv(0x61, tlv(0x5F1F, ascii(LINE1 + LINE2))));
    }

    private static Com com(String ldsVersion, String unicodeVersion) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x5F01, ascii(ldsVersion));
        TlvWriter.writeTlv(body, 0x5F36, ascii(unicodeVersion));
        TlvWriter.writeTlv(body, 0x5C, new byte[] { 0x61, 0x75 });
        return Com.parse(tlv(0x60, body.toByteArray()));
    }

    private static Dg2 dg2() {
        // 75 { 7F61 { 7F60 { JPEG SOI ... } } }.
        byte[] bdb = new byte[] { (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, 0x01 };
        return Dg2.parse(tlv(0x75, tlv(0x7F61, tlv(0x7F60, bdb))));
    }

    private static Dg15 dg15() {
        BigInteger modulus = BigInteger.ONE.shiftLeft(2047).add(BigInteger.valueOf(3));
        byte[] rsaPublicKey = DerWriter.sequence(
                DerWriter.integer(modulus), DerWriter.integer(BigInteger.valueOf(65537)));
        byte[] subjectPublicKey = DerWriter.tlv(0x03,
                DerWriter.concat(new byte[] { 0x00 }, rsaPublicKey));
        byte[] algorithm = DerWriter.sequence(
                DerWriter.oid("1.2.840.113549.1.1.1"), DerWriter.nullValue());
        return Dg15.parse(tlv(0x6F, DerWriter.sequence(algorithm, subjectPublicKey)));
    }

    private static byte[] ascii(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    private static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, value);
        return out.toByteArray();
    }

    private static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    /**
     * A strict JSON (RFC 8259) parser used only to validate the renderer: it
     * accepts exactly one value and rejects trailing data, trailing commas and
     * malformed strings.  It never converts to a tree, so it stays small.
     */
    private static final class JsonParser {

        private final String s;
        private int p;

        JsonParser(String s) {
            this.s = s;
        }

        boolean atEnd() {
            return p >= s.length();
        }

        void skipWhitespace() {
            while (p < s.length()) {
                char c = s.charAt(p);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    p++;
                } else {
                    break;
                }
            }
        }

        void parseValue() {
            skipWhitespace();
            if (atEnd()) {
                throw error("unexpected end of input");
            }
            char c = s.charAt(p);
            switch (c) {
            case '{':
                parseObject();
                break;
            case '[':
                parseArray();
                break;
            case '"':
                parseString();
                break;
            case 't':
                literal("true");
                break;
            case 'f':
                literal("false");
                break;
            case 'n':
                literal("null");
                break;
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    parseNumber();
                } else {
                    throw error("unexpected character '" + c + "'");
                }
            }
        }

        private void parseObject() {
            expect('{');
            skipWhitespace();
            if (peek() == '}') {
                p++;
                return;
            }
            while (true) {
                skipWhitespace();
                if (peek() != '"') {
                    throw error("object key must be a string");
                }
                parseString();
                skipWhitespace();
                expect(':');
                parseValue();
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    p++;
                    continue;
                }
                if (c == '}') {
                    p++;
                    return;
                }
                throw error("expected ',' or '}'");
            }
        }

        private void parseArray() {
            expect('[');
            skipWhitespace();
            if (peek() == ']') {
                p++;
                return;
            }
            while (true) {
                parseValue();
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    p++;
                    continue;
                }
                if (c == ']') {
                    p++;
                    return;
                }
                throw error("expected ',' or ']'");
            }
        }

        private void parseString() {
            expect('"');
            while (p < s.length()) {
                char c = s.charAt(p++);
                if (c == '"') {
                    return;
                }
                if (c == '\\') {
                    if (p >= s.length()) {
                        throw error("truncated escape");
                    }
                    char e = s.charAt(p++);
                    if (e == 'u') {
                        for (int i = 0; i < 4; i++) {
                            if (p >= s.length() || Character.digit(s.charAt(p++), 16) < 0) {
                                throw error("bad \\u escape");
                            }
                        }
                    } else if ("\"\\/bfnrt".indexOf(e) < 0) {
                        throw error("bad escape '\\" + e + "'");
                    }
                } else if (c < 0x20) {
                    throw error("unescaped control character");
                }
            }
            throw error("unterminated string");
        }

        private void parseNumber() {
            int start = p;
            if (peek() == '-') {
                p++;
            }
            if (peek() == '0') {
                p++;
            } else if (peek() >= '1' && peek() <= '9') {
                while (peek() >= '0' && peek() <= '9') {
                    p++;
                }
            } else {
                throw error("bad number");
            }
            if (peek() == '.') {
                p++;
                if (!(peek() >= '0' && peek() <= '9')) {
                    throw error("bad fraction");
                }
                while (peek() >= '0' && peek() <= '9') {
                    p++;
                }
            }
            if (peek() == 'e' || peek() == 'E') {
                p++;
                if (peek() == '+' || peek() == '-') {
                    p++;
                }
                if (!(peek() >= '0' && peek() <= '9')) {
                    throw error("bad exponent");
                }
                while (peek() >= '0' && peek() <= '9') {
                    p++;
                }
            }
            if (p == start) {
                throw error("bad number");
            }
        }

        private void literal(String word) {
            if (!s.startsWith(word, p)) {
                throw error("expected " + word);
            }
            p += word.length();
        }

        private char peek() {
            return p < s.length() ? s.charAt(p) : '\0';
        }

        private void expect(char c) {
            skipWhitespace();
            if (p >= s.length() || s.charAt(p) != c) {
                throw error("expected '" + c + "'");
            }
            p++;
        }

        private RuntimeException error(String message) {
            return new IllegalArgumentException(message + " at " + p);
        }
    }
}
