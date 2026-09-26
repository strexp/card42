package card42.test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import card42.host.common.codec.DerWriter;
import card42.host.common.codec.TlvWriter;
import card42.host.emrtd.lds.Com;
import card42.host.emrtd.lds.Dg1;
import card42.host.emrtd.lds.Dg15;
import card42.host.emrtd.lds.Dg2;
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

    static void run() {
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
