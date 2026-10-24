package card42.test;

import java.util.List;

import card42.host.emrtd.lds.common.LdsDataGroup;
import card42.host.emrtd.lds.common.LdsDate;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.LdsParseResult;
import card42.host.emrtd.lds.common.LdsText;
import card42.host.emrtd.lds.common.LdsTlv;
import card42.host.emrtd.lds.common.MrzCheckDigit;
import card42.host.emrtd.lds.common.ParseStatus;
import card42.host.emrtd.lds.lds1.Dg11;
import card42.host.emrtd.lds.lds1.Dg2;

/** Tests for the shared LDS model: TLV offsets, text, dates and dispatch. */
final class LdsCommonTest {

    private LdsCommonTest() {
    }

    static void run() {
        System.out.println("LdsCommon");
        tlvOffsets();
        tlvTruncation();
        textDecoding();
        dates();
        checkDigits();
        dispatch();
    }

    private static void tlvOffsets() {
        byte[] raw = LdsFixtures.tlv(0xA0,
                LdsFixtures.tlv(0x01, new byte[] { 0x41 }),
                LdsFixtures.tlv(0x5F02, new byte[] { 0x42, 0x43 }));
        java.util.List<LdsIssue> issues = new java.util.ArrayList<LdsIssue>();
        List<LdsTlv.Node> children = LdsTlv.body(raw, 0xA0, 0, issues);
        Asserts.eq(2, children.size(), "LdsTlv finds two children");
        Asserts.eq(2, children.get(0).start, "first child starts after the outer header");
        Asserts.eq(4, children.get(0).valueOffset, "first child value offset");
        Asserts.eq(0x5F02, children.get(1).tag, "two-byte child tag");
        Asserts.bytes(new byte[] { 0x42, 0x43 }, children.get(1).value(),
                "child value");
        Asserts.check(issues.isEmpty(), "no issue for a complete template");

        List<LdsTlv.Node> body = LdsTlv.body(raw, 0xA0, 0, issues);
        Asserts.eq(2, body.size(), "body unwraps the outer tag");
        Asserts.check(LdsTlv.first(body, 0x01) != null, "first by tag");
        Asserts.eq(1, LdsTlv.all(body, 0x01).size(), "all by tag");

        List<Integer> list = LdsTlv.tagList(new byte[] { 0x5F, 0x0E, 0x01 });
        Asserts.eq(2, list.size(), "tag list size");
        Asserts.eq(0x5F0E, list.get(0), "two-byte tag list entry");
        Asserts.eq(0x01, list.get(1), "one-byte tag list entry");
    }

    private static void tlvTruncation() {
        byte[] raw = LdsFixtures.tlv(0x6B, LdsFixtures.tlv(0x5F0E,
                LdsFixtures.ascii("NAME")));
        for (byte[] truncated : LdsFixtures.truncations(raw)) {
            java.util.List<LdsIssue> issues = new java.util.ArrayList<LdsIssue>();
            AssertNoThrow.run(() -> LdsTlv.body(truncated, 0x6B, 11, issues),
                    "truncated TLV does not throw");
            Asserts.check(!issues.isEmpty() || truncated.length == raw.length - 1,
                    "truncation is reported (or only the last byte was removed)");
        }
        java.util.List<LdsIssue> issues = new java.util.ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(new byte[] { 0x6C, 0x00 }, 0x6B, 11, issues);
        Asserts.eq(LdsIssue.Code.OUTER_TAG_MISMATCH, issues.get(0).code,
                "outer tag mismatch is reported");
        Asserts.eq(1, body.size(), "mismatched wrapper is still parsed as a bare template");
    }

    private static void textDecoding() {
        LdsText.Decoded ascii = LdsText.utf8OrLatin1(LdsFixtures.ascii("ABC"));
        Asserts.eq("ABC", ascii.text, "ASCII text");
        Asserts.check(!ascii.fallback, "ASCII is not a fallback");

        LdsText.Decoded utf8 = LdsText.utf8OrLatin1(LdsFixtures.utf8("张三"));
        Asserts.eq("张三", utf8.text, "UTF-8 text");
        Asserts.eq("UTF-8", utf8.charset, "UTF-8 detected");

        LdsText.Decoded latin = LdsText.utf8OrLatin1(new byte[] { (byte) 0xC3, 0x28 });
        Asserts.check(latin.fallback, "invalid UTF-8 uses the fallback");
        Asserts.eq("ISO-8859-1", latin.charset, "fallback charset");
        Asserts.check(LdsText.isUtf8(LdsFixtures.utf8("好")), "isUtf8 accepts valid text");
        Asserts.check(!LdsText.isUtf8(new byte[] { (byte) 0xFF }), "isUtf8 rejects 0xFF");
    }

    private static void dates() {
        LdsDate birth = LdsDate.birthDate("690806", 2026);
        Asserts.check(birth.valid, "birth date is valid");
        Asserts.eq("1969-08-06", birth.toString(), "birth century is 1969");

        LdsDate expiry = LdsDate.expiryDate("940623", 2026);
        Asserts.eq("1994-06-23", expiry.toString(), "expired passport stays 1994");
        Asserts.eq("2030-01-01", LdsDate.expiryDate("300101", 2026).toString(),
                "future expiry uses 20xx");

        Asserts.check(!LdsDate.yymmdd("230230", 2026).valid, "30 February is invalid");
        Asserts.check(LdsDate.yyyymmdd("20240229").valid, "leap day is valid");
        Asserts.check(!LdsDate.yyyymmdd("20230229").valid, "non-leap 29 February is invalid");
        Asserts.check(!LdsDate.yyyymmdd("2026").valid, "short date is invalid");
        Asserts.eq("2026-01-01", LdsDate.yyyymmddhhmmss("20260101120000").toString(),
                "date part of a timestamp");
    }

    private static void checkDigits() {
        Asserts.eq(3, MrzCheckDigit.compute("L898902C<"), "ICAO document number check digit");
        Asserts.eq(1, MrzCheckDigit.compute("690806"), "ICAO date check digit");
        Asserts.eq(0, MrzCheckDigit.value('<'), "< counts as zero");
        Asserts.eq(35, MrzCheckDigit.value('Z'), "Z counts as 35");
        Asserts.check(MrzCheckDigit.matches("L898902C<", '3'), "matches a valid digit");
        Asserts.check(!MrzCheckDigit.matches("L898902C<", '<'), "filler never matches");
    }

    private static void dispatch() {
        byte[] dg2Bytes = LdsFixtures.dg2(LdsFixtures.JPEG);
        LdsParseResult<LdsDataGroup> result = LdsDataGroup.parse(2, dg2Bytes);
        Asserts.check(result.value instanceof Dg2, "dispatcher returns Dg2");
        Asserts.eq(ParseStatus.OK, result.status, "dispatcher status");
        Asserts.bytes(dg2Bytes, result.raw(), "dispatcher keeps the raw EF");

        LdsParseResult<LdsDataGroup> dg11 = LdsDataGroup.parse(11, LdsFixtures.dg11());
        Asserts.check(dg11.value instanceof Dg11, "dispatcher returns Dg11");

        LdsParseResult<LdsDataGroup> unknown = LdsDataGroup.parse(6,
                LdsFixtures.tlv(0x66, new byte[] { 0x01 }));
        Asserts.eq(ParseStatus.OK, unknown.status, "reserved DG6 falls back to the generic view");

        LdsParseResult<LdsDataGroup> empty = LdsDataGroup.parse(1, new byte[0]);
        Asserts.eq(ParseStatus.INVALID, empty.status, "empty DG1 is invalid");
        Asserts.check(empty.value != null, "empty DG1 still carries the raw view");
        Asserts.eq(LdsIssue.Code.EMPTY_VALUE, empty.issues.get(0).code,
                "empty EF is reported");
    }

    /** Thin adapter so the assertion messages read well in the test output. */
    private interface Action {
        void run();
    }

    private static final class AssertNoThrow {
        static void run(Action action, String what) {
            try {
                action.run();
                Asserts.check(true, what);
            } catch (RuntimeException e) {
                Asserts.check(false, what + " (threw " + e + ")");
            }
        }
    }
}
