package card42.test;

import java.io.ByteArrayOutputStream;

import card42.emv.PersoRules;
import card42.host.common.codec.TlvWriter;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for the STORE DATA Lc parsing (EMV CPS v2.0 Table 4-8) and the
 * DGI-value validation rules (EMV CPS v2.0 Annex A): a 1-byte or a 3-byte
 * ('00' || LcHi || LcLo) length field, plus the FCI/PSE/PPSE template checks
 * the card applies when applying a personalization DGI.
 */
final class PersoRulesTest {

    private PersoRulesTest() {
    }

    static void run() {
        System.out.println("PersoRules");

        // 1-byte Lc: CLA INS P1 P2 Lc <data>, Lc at offset 4.
        byte[] shortCmd = { (byte) 0x80, (byte) 0xE2, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5 };
        Asserts.eq(1, PersoRules.storeDataLcFieldLength(shortCmd, (short) 4, (short) 10),
                "short Lc field length");
        Asserts.eq(5, PersoRules.storeDataLc(shortCmd, (short) 4, (short) 1),
                "short Lc value");

        // 3-byte Lc: '00' || 0x01 0x00 = 256.
        byte[] longCmd = { (byte) 0x80, (byte) 0xE2, 0x00, 0x00, 0x00, 0x01, 0x00 };
        Asserts.eq(3, PersoRules.storeDataLcFieldLength(longCmd, (short) 4, (short) 7),
                "extended Lc field length");
        Asserts.eq(256, PersoRules.storeDataLc(longCmd, (short) 4, (short) 3),
                "extended Lc value");

        // A leading '00' with no room for the two length bytes is a 1-byte Lc=0.
        Asserts.eq(1, PersoRules.storeDataLcFieldLength(longCmd, (short) 4, (short) 6),
                "truncated extended Lc falls back to 1 byte");
        Asserts.eq(0, PersoRules.storeDataLc(longCmd, (short) 4, (short) 1),
                "Lc=0 value");

        // Lc beyond the buffer.
        Asserts.eq(0, PersoRules.storeDataLcFieldLength(shortCmd, (short) 4, (short) 4),
                "missing Lc");

        ppseTemplate();
        pseTemplate();
        pseRecord();
        fciTemplate();
        track2();
    }

    /** Track 2 Equivalent Data (tag 57, EMV v4.4 Book 3 Annex A Table 37). */
    private static void track2() {
        byte[] valid = Hex.parse("1234567890D2912101");
        Asserts.noThrow(() -> PersoRules.validateTrack2(valid, (short) 0,
                        (short) valid.length),
                "valid Track 2 (PAN D expiry)");

        byte[] oddPan = Hex.parse("1234567890D2912101FF");
        Asserts.noThrow(() -> PersoRules.validateTrack2(oddPan, (short) 0,
                        (short) oddPan.length),
                "valid Track 2 with F padding");

        byte[] noSeparator = Hex.parse("12345678901234567890");
        Asserts.sw((short) 0x6A80, () -> PersoRules.validateTrack2(noSeparator, (short) 0,
                        (short) noSeparator.length),
                "Track 2 without a D separator -> 6A80");

        Asserts.sw((short) 0x6A80, () -> PersoRules.validateTrack2(new byte[0], (short) 0,
                        (short) 0),
                "empty Track 2 -> 6A80");

        Asserts.sw((short) 0x6A80, () -> PersoRules.validateTrack2(new byte[20], (short) 0,
                        (short) 20),
                "Track 2 longer than 19 bytes -> 6A80");
    }

    /** EMV Contactless Book B v2.12 Table 3-2 / Table A-1 PPSE '9102' validation. */
    private static void ppseTemplate() {
        byte[] valid = ppse(entry("43415244420102", null, null, null));
        Asserts.noThrow(() -> PersoRules.validatePpseTemplate(valid, (short) 0,
                        (short) valid.length),
                "valid PPSE template");

        byte[] noBf0c = tlv(0xA5, tlv(0x50, Hex.parse("454D563432")));
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePpseTemplate(noBf0c, (short) 0,
                        (short) noBf0c.length),
                "PPSE without BF0C -> 6A80");

        byte[] empty = ppse(new byte[0]);
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePpseTemplate(empty, (short) 0,
                        (short) empty.length),
                "PPSE with an empty candidate list -> 6A80");

        byte[] kernel2 = ppse(entry("43415244420102", new byte[] { 0x00, 0x00 }, null, null));
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePpseTemplate(kernel2, (short) 0,
                        (short) kernel2.length),
                "PPSE 9F2A of length 2 -> 6A80");

        byte[] adf15 = ppse(entry("434152444201020102030405060708090A0B0C", null, null, null));
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePpseTemplate(adf15, (short) 0,
                        (short) adf15.length),
                "PPSE 4F longer than 16 bytes -> 6A80");

        // ADF Name (16) + Extended Selection (1) > 16 -> 6A80.
        byte[] extended = ppse(entry("434152444201020102030405060708090A", null,
                new byte[] { 0x01 }, null));
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePpseTemplate(extended, (short) 0,
                        (short) extended.length),
                "PPSE 9F29 + 4F > 16 -> 6A80");

        byte[] noAdf = ppse(entryNoAdf());
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePpseTemplate(noAdf, (short) 0,
                        (short) noAdf.length),
                "PPSE 61 without 4F -> 6A80");
    }

    /** EMV v4.4 Book 1 §12.2.3 PSE '9102' validation. */
    private static void pseTemplate() {
        byte[] valid = tlv(0xA5, tlv(0x88, new byte[] { 0x01 }));
        Asserts.noThrow(() -> PersoRules.validatePseTemplate(valid, (short) 0,
                        (short) valid.length),
                "valid PSE template");

        byte[] wrongSfi = tlv(0xA5, tlv(0x88, new byte[] { 0x02 }));
        Asserts.noThrow(() -> PersoRules.validatePseTemplate(wrongSfi, (short) 0,
                        (short) wrongSfi.length),
                "PSE SFI 2 is accepted (1-10 allowed)");
        Asserts.eq(2, PersoRules.pseDirectorySfi(wrongSfi, (short) 0,
                        (short) wrongSfi.length),
                "pseDirectorySfi reads the advertised SFI");
        byte[] sfi10 = tlv(0xA5, tlv(0x88, new byte[] { 0x0A }));
        Asserts.noThrow(() -> PersoRules.validatePseTemplate(sfi10, (short) 0,
                        (short) sfi10.length),
                "PSE SFI 10 is accepted");
        byte[] sfi0 = tlv(0xA5, tlv(0x88, new byte[] { 0x00 }));
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePseTemplate(sfi0, (short) 0,
                        (short) sfi0.length),
                "PSE SFI 0 -> 6A80");
        byte[] sfi11 = tlv(0xA5, tlv(0x88, new byte[] { 0x0B }));
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePseTemplate(sfi11, (short) 0,
                        (short) sfi11.length),
                "PSE SFI 11 -> 6A80");

        byte[] noSfi = tlv(0xA5, tlv(0x50, Hex.parse("454D563432")));
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePseTemplate(noSfi, (short) 0,
                        (short) noSfi.length),
                "PSE without 88 -> 6A80");
    }

    /** EMV CPS v2.0 Annex A Table A-20 PSE record validation. */
    private static void pseRecord() {
        byte[] valid = tlv(0x70, tlv(0x61, concat(
                tlv(0x4F, Hex.parse("43415244420102")),
                tlv(0x50, Hex.parse("454D563432")))));
        Asserts.noThrow(() -> PersoRules.validatePseRecord(valid, (short) 0,
                        (short) valid.length),
                "valid PSE record");

        byte[] noAdf = tlv(0x70, tlv(0x61, tlv(0x50, Hex.parse("454D563432"))));
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePseRecord(noAdf, (short) 0,
                        (short) noAdf.length),
                "PSE 61 without 4F -> 6A80");

        // Application Label '50' is mandatory in a PSE Directory Entry
        // (EMV v4.4 Book 1 §12.2.3 Table 12); CPS v2.0 Table A-20 marks it
        // optional, but the PSE is defined by Book 1.
        byte[] noLabel = tlv(0x70, tlv(0x61, tlv(0x4F, Hex.parse("43415244420102"))));
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePseRecord(noLabel, (short) 0,
                        (short) noLabel.length),
                "PSE 61 without 50 -> 6A80 (Book 1 Table 12)");

        byte[] shortAdf = tlv(0x70, tlv(0x61, concat(
                tlv(0x4F, Hex.parse("454D5634")),
                tlv(0x50, Hex.parse("454D563432")))));
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePseRecord(shortAdf, (short) 0,
                        (short) shortAdf.length),
                "PSE 4F shorter than 5 bytes -> 6A80");

        byte[] longPriority = tlv(0x70, tlv(0x61, concat(
                tlv(0x4F, Hex.parse("43415244420102")),
                tlv(0x50, Hex.parse("454D563432")),
                tlv(0x87, new byte[] { 0x01, 0x02 }))));
        Asserts.sw((short) 0x6A80, () -> PersoRules.validatePseRecord(longPriority, (short) 0,
                        (short) longPriority.length),
                "PSE 87 longer than 1 byte -> 6A80");
    }

    /** A5 FCI Proprietary Template detection. */
    private static void fciTemplate() {
        byte[] valid = tlv(0xA5, tlv(0x50, Hex.parse("454D563432")));
        Asserts.check(PersoRules.isFciTemplate(valid, (short) 0, (short) valid.length, (short) 0x50),
                "isFciTemplate finds 50");
        Asserts.check(!PersoRules.isFciTemplate(valid, (short) 0, (short) valid.length, (short) 0x88),
                "isFciTemplate misses 88");
        byte[] notA5 = tlv(0x70, Hex.parse("5000"));
        Asserts.check(!PersoRules.isFciTemplate(notA5, (short) 0, (short) notA5.length, (short) 0x50),
                "isFciTemplate rejects a non-A5 template");
        byte[] overlongLabel = tlv(0xA5, tlv(0x50, new byte[17]));
        Asserts.check(!PersoRules.isFciTemplate(overlongLabel, (short) 0,
                        (short) overlongLabel.length, (short) 0x50),
                "isFciTemplate rejects an over-long label");
    }

    // --- helpers -------------------------------------------------------------

    /** A5 { BF0C { <bf0c value> } }. */
    private static byte[] ppse(byte[] bf0cValue) {
        return tlv(0xA5, tlv(0xBF0C, bf0cValue));
    }

    /** One 61 Directory Entry. */
    private static byte[] entry(String aidHex, byte[] kernelId, byte[] extendedSelection,
            byte[] priority) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x4F, Hex.parse(aidHex));
        if (kernelId != null) {
            TlvWriter.writeTlv(body, 0x9F2A, kernelId);
        }
        if (extendedSelection != null) {
            TlvWriter.writeTlv(body, 0x9F29, extendedSelection);
        }
        if (priority != null) {
            TlvWriter.writeTlv(body, 0x87, priority);
        }
        return tlv(0x61, body.toByteArray());
    }

    /** A 61 with no 4F. */
    private static byte[] entryNoAdf() {
        return tlv(0x61, tlv(0x50, Hex.parse("454D563432")));
    }

    private static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, value);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int p = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, p, part.length);
            p += part.length;
        }
        return out;
    }
}
