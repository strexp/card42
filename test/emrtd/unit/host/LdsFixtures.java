package card42.test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import card42.host.common.codec.TlvWriter;
import card42.host.common.util.Hex;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.LdsTlv;
import card42.host.emrtd.perso.BiometricRecordBuilder;
import card42.host.emrtd.perso.Dg2Builder;

/**
 * Synthetic LDS fixtures for the parser unit tests.  Nothing here is a real
 * document: the records are built with {@link TlvWriter} and the minimal ISO
 * 19794/CBEFF layouts the parsers consume.
 */
final class LdsFixtures {

    /** A tiny but signature-complete JPEG payload. */
    static final byte[] JPEG = Hex.parse(
            "FFD8FFE000104A46494600010100000100010000FFD9");

    private LdsFixtures() {
    }

    static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, value);
        return out.toByteArray();
    }

    static byte[] tlv(int tag, byte[]... children) {
        return tlv(tag, cat(children));
    }

    static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    /** A DG2 with one face built by the personalization builder. */
    static byte[] dg2(byte[] jpeg) {
        return Dg2Builder.build(jpeg, 400, 500);
    }

    /**
     * A DG2 with two identical {@code 7F60} templates: a compact way to test
     * the multi-face model without hand-writing a second facial record.
     */
    static byte[] dg2TwoTemplates(byte[] jpeg) {
        byte[] one = dg2(jpeg);
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(one, 0x75, 2, issues);
        LdsTlv.Node group = LdsTlv.first(body, 0x7F61);
        LdsTlv.Node template = LdsTlv.first(LdsTlv.childrenOf(group, 2, issues), 0x7F60);
        byte[] inner = cat(tlv(0x02, new byte[] { 0x02 }), template.encoded(),
                template.encoded());
        return tlv(0x75, tlv(0x7F61, inner));
    }

    /** A DG2 whose BDB has no ISO 19794 header (legacy signature scan). */
    static byte[] dg2Legacy() {
        byte[] bdb = cat(new byte[] { 0x01, 0x02, 0x03 }, JPEG);
        return tlv(0x75, tlv(0x7F61, tlv(0x02, new byte[] { 0x01 }),
                tlv(0x7F60, tlv(0x5F2E, bdb))));
    }

    /** A conformant DG3 with one JPEG finger image. */
    static byte[] dg3() {
        byte[] record = BiometricRecordBuilder.fingerImageRecord(
                1, 0, 320, 400, BiometricRecordBuilder.COMPRESSION_JPEG, JPEG);
        return BiometricRecordBuilder.dg3(record);
    }

    /** A DG3 with two finger templates (two {@code 7F60} for the same DG). */
    static byte[] dg3TwoTemplates() {
        byte[] one = dg3();
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(one, 0x63, 3, issues);
        LdsTlv.Node group = LdsTlv.first(body, 0x7F61);
        LdsTlv.Node template = LdsTlv.first(LdsTlv.childrenOf(group, 3, issues), 0x7F60);
        byte[] inner = cat(tlv(0x02, new byte[] { 0x02 }), template.encoded(),
                template.encoded());
        return tlv(0x63, tlv(0x7F61, inner));
    }

    /** A DG3 carrying an ISO 19794-2 minutiae record (kept raw). */
    static byte[] dg3Minutiae() {
        byte[] fmr = cat(ascii("FMR"), new byte[] { 0x00, 0x30, 0x31, 0x30, 0x00 });
        byte[] bht = BiometricRecordBuilder.cbeff(BiometricRecordBuilder.TYPE_FINGERPRINT,
                BiometricRecordBuilder.OWNER_JTC1_SC37,
                BiometricRecordBuilder.FORMAT_FINGER_IMAGE);
        return tlv(0x63, tlv(0x7F61, tlv(0x02, new byte[] { 0x01 }),
                tlv(0x7F60, tlv(0xA1, bht), tlv(0x5F2E, fmr))));
    }

    /** A conformant DG4 with one JPEG iris image. */
    static byte[] dg4() {
        byte[] record = BiometricRecordBuilder.irisRecord(1, 8, 640, 480, JPEG);
        return BiometricRecordBuilder.dg4(record);
    }

    static byte[] dg5(byte[]... images) {
        return BiometricRecordBuilder.dg5(images);
    }

    static byte[] dg7(byte[]... images) {
        return BiometricRecordBuilder.dg7(images);
    }

    /** A DG11 with every defined tag, a UTF-8 name, an unknown tag and a duplicate. */
    static byte[] dg11() {
        byte[] a0 = tlv(0xA0, tlv(0x02, new byte[] { 0x02 }),
                tlv(0x5F0F, utf8("OTHER<ONE")),
                tlv(0x5F0F, utf8("OTHER<TWO")));
        byte[] tags = Hex.parse("5F0E5F0F5F105F2B5F115F425F125F135F145F155F165F175F18");
        return tlv(0x6B, tlv(0x5C, tags),
                tlv(0x5F0E, utf8("张<<三")),
                a0,
                tlv(0x5F10, ascii("P1234567")),
                tlv(0x5F2B, ascii("19900101")),
                tlv(0x5F11, ascii("UTOPIA")),
                tlv(0x5F42, ascii("1<STREET<UTOPIA")),
                tlv(0x5F12, ascii("+4680000000")),
                tlv(0x5F13, ascii("ENGINEER")),
                tlv(0x5F14, ascii("DR")),
                tlv(0x5F15, ascii("SUMMARY")),
                tlv(0x5F16, JPEG),
                tlv(0x5F17, ascii("TD1<TD2")),
                tlv(0x5F18, ascii("CUSTODY")),
                tlv(0xDF01, new byte[] { 0x01, 0x02 }));
    }

    /** A DG12 with ASCII date/time, images and an unknown tag. */
    static byte[] dg12() {
        byte[] a0 = tlv(0xA0, tlv(0x02, new byte[] { 0x01 }),
                tlv(0x5F1A, ascii("OTHER<PERSON")));
        return tlv(0x6C, tlv(0x5C, Hex.parse("5F195F265F1A5F1B5F1C5F1D5F1E5F555F56")),
                tlv(0x5F19, ascii("UTO PASSPORT OFFICE")),
                tlv(0x5F26, ascii("20260101")),
                a0,
                tlv(0x5F1B, ascii("ENDORSEMENT")),
                tlv(0x5F1C, ascii("TAX")),
                tlv(0x5F1D, JPEG),
                tlv(0x5F1E, JPEG),
                tlv(0x5F55, ascii("20260101120000")),
                tlv(0x5F56, ascii("card42")),
                tlv(0xDF02, new byte[] { 0x03 }));
    }

    /** A DG12 whose 5F55 uses the BCD encoding. */
    static byte[] dg12BcdDateTime() {
        byte[] bcd = Hex.parse("20260101120000");
        return tlv(0x6C, tlv(0x5F19, ascii("UTO")),
                tlv(0x5F26, ascii("20260101")),
                tlv(0x5F55, bcd));
    }

    static byte[] dg13() {
        return tlv(0x6D, tlv(0x5F2B, Hex.parse("2021222324252627")));
    }

    static byte[] dg16() {
        List<byte[]> persons = new ArrayList<byte[]>();
        persons.add(BiometricRecordBuilder.personToNotify(1, "20260101",
                "UTOPIA<CONTACT", "+4680000001", "UTOPIA<STREET 1"));
        persons.add(BiometricRecordBuilder.personToNotify(2, "20260101",
                "UTOPIA<SECOND", "+4680000002", "UTOPIA<STREET 2"));
        return BiometricRecordBuilder.dg16(persons);
    }

    /** Builds a template group with a declared count and raw proprietary bodies. */
    static byte[] templateGroup(int outerTag, byte[]... templates) {
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        TlvWriter.writeTlv(inner, 0x02, new byte[] { (byte) templates.length });
        for (byte[] template : templates) {
            inner.write(template, 0, template.length);
        }
        return tlv(outerTag, inner.toByteArray());
    }

    /** Every truncation of {@code raw} (length 0 .. raw.length-1). */
    static List<byte[]> truncations(byte[] raw) {
        List<byte[]> out = new ArrayList<byte[]>();
        for (int length = 0; length < raw.length; length++) {
            out.add(Arrays.copyOf(raw, length));
        }
        return out;
    }
}
