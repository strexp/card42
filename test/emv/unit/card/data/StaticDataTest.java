package card42.test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import javacard.framework.ISO7816;

import card42.emv.EMVStaticData;
import card42.emv.PersoRules;
import card42.host.common.util.Hex;
import card42.host.emv.app.perso.PersoScript;
import card42.host.common.codec.Tags;
import card42.host.common.codec.TlvWriter;

/**
 * Pure-JVM tests for the personalized payment data (EMV v4.4 Book 3 §6.5.8,
 * §10.8): PDOL / IAC / IAD parsing, the DOL-based accessors and the format 1 /
 * format 2 GPO response.
 */
final class StaticDataTest {

    private StaticDataTest() {
    }

    static void run() {
        System.out.println("EMVStaticData");

        EMVStaticData sd = new EMVStaticData();
        byte[] config = Hex.parse(
                "82 02 79 00 94 04 08 01 05 01 "
                + "8C 15 9F02 06 9F03 06 9F1A 02 95 05 5F2A 02 9A 03 9C 01 9F37 04 "
                + "9F38 15 9F02 06 9F03 06 9F1A 02 95 05 5F2A 02 9A 03 9C 01 9F37 04 "
                + "9F0E 05 80 00 00 00 00 "
                + "9F10 20 0F A5 11 00 00 00 00 00 00 00 00 00 00 00 00 00 0F "
                + "AA BB CC DD EE FF 11 22 33 44 55 66 77 88 99");        sd.applyPaymentConfig(config, (short) 0, (short) config.length);

        Asserts.eq(29, sd.getPdolDataLength(), "PDOL data length");
        Asserts.eq(14, sd.getPdolValueOffset((short) 0x95), "PDOL TVR offset");
        Asserts.eq(29, sd.getCDOL1DataLength(), "CDOL1 data length");
        Asserts.eq(14, sd.getCDOL1ValueOffset((short) 0x95), "CDOL1 TVR offset");
        Asserts.eq(5, sd.getCDOL1ValueLength((short) 0x95), "CDOL1 TVR length");
        Asserts.eq(25, sd.getCDOL1ValueOffset((short) 0x9F37), "CDOL1 UN offset");

        Asserts.bytes(Hex.parse("80 00 00 00 00"),
                Arrays.copyOf(sd.getIacDenial(), sd.getIacDenialLength()),
                "IAC-Denial personalized");
        Asserts.bytes(Hex.parse("FF FF FF FF FF"),
                Arrays.copyOf(sd.getIacOnline(), sd.getIacOnlineLength()),
                "IAC-Online default");
        Asserts.bytes(Hex.parse(
                        "0F A5 11 00 00 00 00 00 00 00 00 00 00 00 00 00 0F "
                        + "AA BB CC DD EE FF 11 22 33 44 55 66 77 88 99"),
                Arrays.copyOf(sd.getIad(), sd.getIadLength()), "IAD personalized");
        Asserts.eq(32, sd.getIadLength(), "IAD length is 32 (Format Code 'A')");
        Asserts.eq(0x7900, sd.getAIP((byte) 0x00) & 0xFFFF, "AIP personalized");

        // The personalized contact AIP 0x7900 has byte 1 bit 3 = 0 (CCD), so
        // the contact GPO is Format 2 (EMV v4.4 Book 3 CCD §6.5.8.4).
        byte[] gpo1 = sd.getGpo((byte) 0x00);
        Asserts.eq(0x77, gpo1[0] & 0xFF, "CCD contact GPO is format 2");
        Asserts.bytes(Hex.parse("79 00"), Tags.find(gpo1, 0x82), "CCD contact GPO AIP tag");

        // A generic contact instance (AIP byte 1 bit 3 = 1) personalizes a
        // non-CCD CDOL2 (no inline tag '91') and returns Format 1.
        EMVStaticData sdGeneric = new EMVStaticData();
        sdGeneric.setAid(Hex.parse("43415244420101"));
        byte[] genericConfig = Hex.parse(
                "82 02 5C 00 94 04 08 01 05 01 8D 03 9F02 06");
        sdGeneric.applyPaymentConfig(genericConfig, (short) 0, (short) genericConfig.length);
        Asserts.check(!sdGeneric.isCcdFormat(), "generic contact is not CCD");
        Asserts.check(sd.isCcdFormat(), "CCD contact uses the CCD data format");
        byte[] gpoGeneric = sdGeneric.getGpo((byte) 0x00);
        Asserts.eq(0x80, gpoGeneric[0] & 0xFF, "generic contact GPO is format 1");
        Asserts.eq(0x5C00, ((gpoGeneric[2] & 0xFF) << 8) | (gpoGeneric[3] & 0xFF),
                "generic contact GPO AIP");

        // Format 2 for the contactless role: 77 { 82 AIP, 94 AFL }.
        byte[] gpo2 = sd.getGpo((byte) 0x01);
        short gpo2Length = sd.getGpoLength((byte) 0x01);
        Asserts.eq(0x77, gpo2[0] & 0xFF, "contactless GPO is format 2");
        Asserts.eq(gpo2Length, 2 + (gpo2[1] & 0xFF),
                "contactless GPO length matches body");
        Asserts.bytes(Hex.parse("79 00"), Tags.find(gpo2, 0x82),
                "contactless GPO AIP tag");
        Asserts.bytes(Hex.parse("08 01 05 01"), Tags.find(gpo2, 0x94),
                "contactless GPO AFL tag");

        // The PDOL is advertised in the FCI (default builder).
        EMVStaticData sd2 = new EMVStaticData();
        sd2.setAid(Hex.parse("43415244420101"));
        sd2.applyPaymentConfig(config, (short) 0, (short) config.length);
        Asserts.bytes(Hex.parse(
                "9F02 06 9F03 06 9F1A 02 95 05 5F2A 02 9A 03 9C 01 9F37 04"),
                Tags.find(sd2.getFCI((byte) 0x00), 0x9F38), "FCI advertises the PDOL");

        // The default FCI is 6F { 84, A5 { 50, 87, 5F2D, 9F38, BF0C { 9F4D } } }:
        // the A5 FCI Proprietary Template is mandatory and carries the label,
        // priority, language, PDOL and the Log Entry inside BF0C
        // (EMV v4.4 Book 1 Table 10, EMV v4.4 Book 3 Annex D4).
        byte[] defaultA5 = Tags.find(sd2.getFCI((byte) 0x00), 0xA5);
        Asserts.check(defaultA5 != null, "default FCI has an A5 template");
        Asserts.check(defaultA5 != null && Tags.find(defaultA5, 0x50) != null,
                "default FCI label is inside A5");
        Asserts.check(defaultA5 != null && Tags.find(defaultA5, 0x87) != null,
                "default FCI priority is inside A5");
        Asserts.check(defaultA5 != null && Tags.find(defaultA5, 0x9F38) != null,
                "default FCI PDOL is inside A5");
        Asserts.check(defaultA5 != null && Tags.find(defaultA5, 0x9F4D) != null,
                "default FCI Log Entry is inside A5");

        // The EMV CPS v2.0 Annex A DGI '9102' override is itself an A5 template; the Log Entry is
        // appended inside that A5 (EMV v4.4 Book 1 Table 10).
        EMVStaticData sdOverride = new EMVStaticData();
        sdOverride.setAid(Hex.parse("43415244420101"));
        byte[] override = Hex.parse("A5 06 50 04 54 45 53 54");
        sdOverride.setFciOverride(override, (short) 0, (short) override.length);
        byte[] overrideA5 = Tags.find(sdOverride.getFCI((byte) 0x00), 0xA5);
        Asserts.check(overrideA5 != null && Tags.find(overrideA5, 0x50) != null,
                "override label is inside A5");
        Asserts.check(overrideA5 != null && Tags.find(overrideA5, 0x9F4D) != null,
                "override Log Entry is inside A5");

        // READ RECORD state words (EMV v4.4 Book 3 §6.5.11): the AFL authorizes the
        // SFI, an SFI outside it is a missing file (6A82) and a record without
        // data in an existing file is a missing record (6A83).
        byte[] apdu = new byte[16];
        byte[] record = new byte[512];
        apdu[ISO7816.OFFSET_P1] = 0x01;
        apdu[ISO7816.OFFSET_P2] = 0x0C; // SFI 1, the file the AFL advertises
        sd.readRecord(apdu, record, (byte) 0x00);
        Asserts.eq(0x70, record[0] & 0xFF, "READ RECORD SFI 1 rec 1");

        apdu[ISO7816.OFFSET_P2] = 0x14; // SFI 2: not advertised in the AFL
        Asserts.sw(ISO7816.SW_FILE_NOT_FOUND,
                () -> sd.readRecord(apdu, record, (byte) 0x00),
                "READ RECORD unauthorized SFI -> 6A82");

        apdu[ISO7816.OFFSET_P2] = 0x0C; // SFI 1
        apdu[ISO7816.OFFSET_P1] = 0x06; // record 6: the file has no such record
        Asserts.sw(ISO7816.SW_RECORD_NOT_FOUND,
                () -> sd.readRecord(apdu, record, (byte) 0x00),
                "READ RECORD missing record -> 6A83");

        // SFI and record edge cases (docs/specs/common/toolchain.md §6): SFI 0 and 31 and
        // a log SFI (11) are not in the AFL -> 6A82; record 0 is a missing
        // record in an existing file -> 6A83.
        apdu[ISO7816.OFFSET_P1] = 0x01;
        apdu[ISO7816.OFFSET_P2] = 0x04; // SFI 0
        Asserts.sw(ISO7816.SW_FILE_NOT_FOUND,
                () -> sd.readRecord(apdu, record, (byte) 0x00),
                "READ RECORD SFI 0 -> 6A82");
        apdu[ISO7816.OFFSET_P2] = (byte) 0xFC; // SFI 31
        Asserts.sw(ISO7816.SW_FILE_NOT_FOUND,
                () -> sd.readRecord(apdu, record, (byte) 0x00),
                "READ RECORD SFI 31 -> 6A82");
        apdu[ISO7816.OFFSET_P2] = 0x5C; // SFI 11 (transaction log)
        Asserts.sw(ISO7816.SW_FILE_NOT_FOUND,
                () -> sd.readRecord(apdu, record, (byte) 0x00),
                "READ RECORD log SFI -> 6A82");
        apdu[ISO7816.OFFSET_P2] = 0x0C; // SFI 1
        apdu[ISO7816.OFFSET_P1] = 0x00; // record 0
        Asserts.sw(ISO7816.SW_RECORD_NOT_FOUND,
                () -> sd.readRecord(apdu, record, (byte) 0x00),
                "READ RECORD record 0 -> 6A83");

        // A stored record with a long-form 70 length placeholder is normalised
        // to the exact width on read (docs/specs/emv/personalization.md §3).
        EMVStaticData sd3 = new EMVStaticData();
        byte[] placeholder = Hex.parse("70 82 00 03 5A 00 00");
        sd3.setRecord((short) 0x0101, placeholder, (short) 0, (short) placeholder.length);
        byte[] stored = new byte[64];
        byte[] readApdu = new byte[16];
        readApdu[ISO7816.OFFSET_P1] = 0x01;
        readApdu[ISO7816.OFFSET_P2] = 0x0C;
        sd3.readRecord(readApdu, stored, (byte) 0x00);
        Asserts.eq(0x70, stored[0] & 0xFF, "stored record keeps the 70 tag");
        Asserts.eq(0x03, stored[1] & 0xFF, "stored record 70 length is normalised");
        Asserts.eq(5, card42.common.Tlv.totalLength(stored, (short) 0),
                "stored record total length after normalisation");

        // A personalized record longer than the 254-byte EMV record limit is
        // rejected with 6A80 rather than stored (EMV v4.4 Book 3 §7).
        EMVStaticData sdLongRecord = new EMVStaticData();
        byte[] oversizedRecord = new byte[255];
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdLongRecord.setRecord(
                        (short) 0x0101, oversizedRecord, (short) 0,
                        (short) oversizedRecord.length),
                "record > 254 B -> 6A80");

        // A 254-byte 70 record whose 1-byte length field must widen to the
        // long form on read would become 255 bytes: rejected with 6A80
        // (EMV v4.4 Book 3 §7.1).
        EMVStaticData sdWidening = new EMVStaticData();
        byte[] widening = new byte[254];
        widening[0] = 0x70;
        widening[1] = 0x01; // placeholder 1-byte length; body is actually 252 B
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdWidening.setRecord(
                        (short) 0x0101, widening, (short) 0,
                        (short) widening.length),
                "254 B record with a widening length field -> 6A80");

        // A non-zero inner '70' declared length that does not match the value
        // length is a personalization error (EMV CPS v2.0 §3.2); a correct one
        // and the '70 00' placeholder are accepted.
        EMVStaticData sdBadLen = new EMVStaticData();
        byte[] badLen = Hex.parse("70 02 5A 00 00");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdBadLen.setRecord(
                        (short) 0x0101, badLen, (short) 0, (short) badLen.length),
                "record with a mismatched 70 length -> 6A80");
        EMVStaticData sdGoodLen = new EMVStaticData();
        byte[] goodLen = Hex.parse("70 03 5A 00 00");
        sdGoodLen.setRecord((short) 0x0101, goodLen, (short) 0, (short) goodLen.length);
        Asserts.check(true, "record with a matching 70 length is accepted");

        // A record that is not a '70' template is rejected (EMV v4.4 Book 3 §7.1).
        EMVStaticData sdBadTemplate = new EMVStaticData();
        byte[] notRecord = Hex.parse("5A 02 12 34");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdBadTemplate.setRecord(
                        (short) 0x0101, notRecord, (short) 0,
                        (short) notRecord.length),
                "non-70 record -> 6A80");

        // Without a PDOL the FCI must not advertise 9F38 (EMV v4.4 Book 3 §6.5.8).
        EMVStaticData sd4 = new EMVStaticData();
        sd4.setAid(Hex.parse("43415244420101"));
        byte[] noPdol = Hex.parse("82 02 79 00 94 04 08 01 05 01");
        sd4.applyPaymentConfig(noPdol, (short) 0, (short) noPdol.length);
        Asserts.check(Tags.find(sd4.getFCI((byte) 0x00), 0x9F38) == null,
                "FCI without a PDOL omits 9F38");

        // A PDOL whose expanded data length exceeds the 64-byte session buffer
        // is still measured exactly; the applet refuses the GPO
        // (docs/specs/common/toolchain.md §6).
        EMVStaticData sdLong = new EMVStaticData();
        StringBuilder pdol = new StringBuilder("9F38 21 ");
        for (int i = 0; i < 11; i++) {
            pdol.append("9F02 06 ");
        }
        byte[] longPdol = PersoScript.parseValue(pdol.toString());
        sdLong.applyPaymentConfig(longPdol, (short) 0, (short) longPdol.length);
        Asserts.eq(66, sdLong.getPdolDataLength(), "long PDOL data length");

        // --- Optional data objects (EMV v4.4 Book 3 Annex A Table 37) ---------
        // The IINE (9F0C) and ASRPD (9F0A) are carried in the FCI issuer
        // discretionary data; the Token Requestor ID (9F19), PAR (9F24) and
        // Last 4 Digits of PAN (9F25) in record 1.  They are optional and only
        // emitted when personalized.
        byte[] par = new byte[29];
        for (short i = 0; i < par.length; i++) {
            par[i] = (byte) (0x30 + i);
        }
        ByteArrayOutputStream optCfg = new ByteArrayOutputStream();
        TlvWriter.writeTlv(optCfg, 0x82, Hex.parse("7900"));
        TlvWriter.writeTlv(optCfg, 0x94, Hex.parse("08010501"));
        TlvWriter.writeTlv(optCfg, 0x9F0C, Hex.parse("12345678"));
        TlvWriter.writeTlv(optCfg, 0x9F0A, Hex.parse("010241424344"));
        TlvWriter.writeTlv(optCfg, 0x9F19, Hex.parse("000000000001"));
        TlvWriter.writeTlv(optCfg, 0x9F24, par);
        TlvWriter.writeTlv(optCfg, 0x9F25, Hex.parse("9012"));
        byte[] optConfig = optCfg.toByteArray();

        EMVStaticData sdOpt = new EMVStaticData();
        sdOpt.setAid(Hex.parse("43415244420101"));
        sdOpt.applyPaymentConfig(optConfig, (short) 0, (short) optConfig.length);

        byte[] optFci = sdOpt.getFCI((byte) 0x00);
        Asserts.bytes(Hex.parse("12345678"), Tags.find(optFci, 0x9F0C),
                "FCI carries the IINE 9F0C");
        Asserts.bytes(Hex.parse("010241424344"), Tags.find(optFci, 0x9F0A),
                "FCI carries the ASRPD 9F0A");
        // Both are inside the BF0C FCI Issuer Discretionary Data template.
        byte[] optBf0c = Tags.find(optFci, 0xBF0C);
        Asserts.check(optBf0c != null && Tags.find(optBf0c, 0x9F0C) != null
                        && Tags.find(optBf0c, 0x9F0A) != null,
                "IINE and ASRPD are inside BF0C");

        byte[] optRecord = new byte[512];
        byte[] optApdu = new byte[16];
        optApdu[ISO7816.OFFSET_P1] = 0x01;
        optApdu[ISO7816.OFFSET_P2] = 0x0C; // SFI 1
        sdOpt.readRecord(optApdu, optRecord, (byte) 0x00);
        Asserts.bytes(Hex.parse("000000000001"), Tags.find(optRecord, 0x9F19),
                "record 1 carries the Token Requestor ID 9F19");
        Asserts.bytes(par, Tags.find(optRecord, 0x9F24),
                "record 1 carries the PAR 9F24");
        Asserts.bytes(Hex.parse("9012"), Tags.find(optRecord, 0x9F25),
                "record 1 carries the Last 4 Digits of PAN 9F25");

        // Without the optional objects the FCI and record 1 omit them.
        EMVStaticData sdNoOpt = new EMVStaticData();
        sdNoOpt.setAid(Hex.parse("43415244420101"));
        byte[] bare = Hex.parse("82 02 79 00 94 04 08 01 05 01");
        sdNoOpt.applyPaymentConfig(bare, (short) 0, (short) bare.length);
        byte[] bareFci = sdNoOpt.getFCI((byte) 0x00);
        Asserts.check(Tags.find(bareFci, 0x9F0C) == null
                        && Tags.find(bareFci, 0x9F0A) == null,
                "FCI omits absent optional objects");
        byte[] bareRecord = new byte[512];
        sdNoOpt.readRecord(optApdu, bareRecord, (byte) 0x00);
        Asserts.check(Tags.find(bareRecord, 0x9F19) == null
                        && Tags.find(bareRecord, 0x9F24) == null
                        && Tags.find(bareRecord, 0x9F25) == null,
                "record 1 omits absent optional objects");

        // --- Track 2 Equivalent Data / AUC / Application Version ---------------
        // Track 2 (57): the default record 1 derives it from the default
        // PAN/expiry, so a card without a personalized record 1 still carries
        // magnetic-stripe fallback data (EMV v4.4 Book 3 Annex A Table 37).
        Asserts.bytes(card42.emv.Defaults.TRACK2, Tags.find(bareRecord, 0x57),
                "default record 1 carries the default Track 2 (57)");
        Asserts.check(Tags.find(bareRecord, 0x9F07) == null
                        && Tags.find(bareRecord, 0x9F08) == null,
                "default record 1 omits absent AUC (9F07) / version (9F08)");

        // A personalized 57 / 9F07 / 9F08 is parsed and emitted.
        ByteArrayOutputStream opt2 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(opt2, 0x82, Hex.parse("7900"));
        TlvWriter.writeTlv(opt2, 0x94, Hex.parse("08010501"));
        TlvWriter.writeTlv(opt2, 0x57, Hex.parse("1234567890D2912101"));
        TlvWriter.writeTlv(opt2, 0x9F07, Hex.parse("3DC0"));
        TlvWriter.writeTlv(opt2, 0x9F08, Hex.parse("0002"));
        byte[] opt2Config = opt2.toByteArray();
        EMVStaticData sdOpt2 = new EMVStaticData();
        sdOpt2.setAid(Hex.parse("43415244420101"));
        sdOpt2.applyPaymentConfig(opt2Config, (short) 0, (short) opt2Config.length);
        byte[] opt2Record = new byte[512];
        sdOpt2.readRecord(optApdu, opt2Record, (byte) 0x00);
        Asserts.bytes(Hex.parse("1234567890D2912101"), Tags.find(opt2Record, 0x57),
                "personalized Track 2 (57) is emitted");
        Asserts.bytes(Hex.parse("3DC0"), Tags.find(opt2Record, 0x9F07),
                "personalized AUC (9F07) is emitted");
        Asserts.bytes(Hex.parse("0002"), Tags.find(opt2Record, 0x9F08),
                "personalized Application Version (9F08) is emitted");

        // Invalid optional-object values are refused (EMV v4.4 Book 3 Annex A Table 37).
        EMVStaticData sdBadTrack2 = new EMVStaticData();
        byte[] badTrack2 = Hex.parse("57 03 12 34 56"); // no 'D' separator
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdBadTrack2.applyPaymentConfig(
                        badTrack2, (short) 0, (short) badTrack2.length),
                "Track 2 without a D separator -> 6A80");
        EMVStaticData sdBadAuc = new EMVStaticData();
        byte[] badAuc = Hex.parse("9F07 01 3D");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdBadAuc.applyPaymentConfig(
                        badAuc, (short) 0, (short) badAuc.length),
                "AUC of length 1 -> 6A80");
        EMVStaticData sdBadVer = new EMVStaticData();
        byte[] badVer = Hex.parse("9F08 03 00 00 02");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdBadVer.applyPaymentConfig(
                        badVer, (short) 0, (short) badVer.length),
                "Application Version of length 3 -> 6A80");

        // --- DOL rules (EMV v4.4 Book 3 §5.4) ---------------------------------
        // A personalized DOL may only list primitive data objects; a constructed
        // tag is rejected with 6A80 instead of being stored.
        EMVStaticData sdBadPdol = new EMVStaticData();
        byte[] badPdol = Hex.parse("9F38 03 70 01 00");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdBadPdol.applyPaymentConfig(
                        badPdol, (short) 0, (short) badPdol.length),
                "constructed tag in a PDOL -> 6A80");
        EMVStaticData sdBadCdol = new EMVStaticData();
        byte[] badCdol = Hex.parse("8C 03 A5 01 00");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdBadCdol.applyPaymentConfig(
                        badCdol, (short) 0, (short) badCdol.length),
                "constructed tag in a CDOL1 -> 6A80");
        // The PDOL extracted from a 9102 A5 override is validated too.
        EMVStaticData sdBadOverride = new EMVStaticData();
        byte[] badA5 = Hex.parse("A5 06 9F38 03 70 01 00");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdBadOverride.setFciOverride(
                        badA5, (short) 0, (short) badA5.length),
                "constructed tag in an override PDOL -> 6A80");

        // --- Overlong DGI values are rejected, not truncated ------------------
        // A value that does not fit its storage field is 6A80 rather than a
        // silent truncation that would corrupt the FCI/record while still
        // reporting success (EMV CPS v2.0 §4.3.4.5).
        EMVStaticData sdTruncLabel = new EMVStaticData();
        byte[] longLabel = Hex.parse(
                "50 11 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdTruncLabel.applyPaymentConfig(
                        longLabel, (short) 0, (short) longLabel.length),
                "overlong 50 (label) -> 6A80");

        EMVStaticData sdTruncAfl = new EMVStaticData();
        byte[] longAfl = Hex.parse(
                "94 11 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdTruncAfl.applyPaymentConfig(
                        longAfl, (short) 0, (short) longAfl.length),
                "overlong 94 (AFL) -> 6A80");

        // --- Fixed-length tags are rejected when short (EMV CPS v2.0 Annex A) --
        // AIP is exactly 2 bytes (Table A-15): a 1-byte value must not fall back
        // to the role default.
        EMVStaticData sdShortAip = new EMVStaticData();
        byte[] shortAip = Hex.parse("82 01 79");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdShortAip.applyPaymentConfig(
                        shortAip, (short) 0, (short) shortAip.length),
                "1-byte 82 (AIP) -> 6A80");

        // Application Priority Indicator is exactly 1 byte (Table A-18).
        EMVStaticData sdLongPriority = new EMVStaticData();
        byte[] longPriority = Hex.parse("87 02 00 01");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdLongPriority.applyPaymentConfig(
                        longPriority, (short) 0, (short) longPriority.length),
                "2-byte 87 (priority) -> 6A80");

        // LCOL/UCOL are exactly 1 byte (EMV v4.4 Book 3 §10.8).
        EMVStaticData sdLongLcol = new EMVStaticData();
        byte[] longLcol = Hex.parse("9F14 02 00 05");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdLongLcol.applyPaymentConfig(
                        longLcol, (short) 0, (short) longLcol.length),
                "2-byte 9F14 (LCOL) -> 6A80");
        EMVStaticData sdLongUcol = new EMVStaticData();
        byte[] longUcol = Hex.parse("9F23 02 00 0A");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdLongUcol.applyPaymentConfig(
                        longUcol, (short) 0, (short) longUcol.length),
                "2-byte 9F23 (UCOL) -> 6A80");

        // A DOL that validates as primitive but exceeds the 64-byte CDOL field.
        EMVStaticData sdTruncCdol = new EMVStaticData();
        StringBuilder bigCdol = new StringBuilder("8C 42 ");
        for (int i = 0; i < 22; i++) {
            bigCdol.append("9F02 07 ");
        }
        byte[] longCdol = PersoScript.parseValue(bigCdol.toString());
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdTruncCdol.applyPaymentConfig(
                        longCdol, (short) 0, (short) longCdol.length),
                "overlong 8C (CDOL1) -> 6A80");

        // The 9102 FCI override is itself capped at 128 bytes.
        EMVStaticData sdTruncFci = new EMVStaticData();
        byte[] longFci = new byte[130];
        longFci[0] = (byte) 0xA5;
        longFci[1] = (byte) 0x81;
        longFci[2] = (byte) 0x7F; // 127-byte value -> 130-byte A5 TLV
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdTruncFci.setFciOverride(
                        longFci, (short) 0, (short) longFci.length),
                "overlong 9102 -> 6A80");

        // --- RSA certificate limits (EMV v4.4 Book 2 Table 43) ----------------
        // The SDA certificate fields are bounded by the Table 43 modulus
        // limits: the issuer certificate (90) by the CA key (248 B), the SSAD
        // (93) by the SDA-only issuer key (248 B), and the issuer-signed ICC
        // (9F46) and PIN (9F2D) certificates by the issuer key with an ICC
        // certificate (247 B).  An overlong value is 6A80, not stored.
        ByteArrayOutputStream certCfg = new ByteArrayOutputStream();
        TlvWriter.writeTlv(certCfg, 0x90, new byte[249]);
        byte[] longIssuerCert = certCfg.toByteArray();
        EMVStaticData sdCert = new EMVStaticData();
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdCert.applyPaymentConfig(
                        longIssuerCert, (short) 0, (short) longIssuerCert.length),
                "issuer certificate > 248 B -> 6A80");

        certCfg.reset();
        TlvWriter.writeTlv(certCfg, 0x93, new byte[249]);
        byte[] longSsad = certCfg.toByteArray();
        EMVStaticData sdSsad = new EMVStaticData();
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdSsad.applyPaymentConfig(
                        longSsad, (short) 0, (short) longSsad.length),
                "SSAD > 248 B -> 6A80");

        certCfg.reset();
        TlvWriter.writeTlv(certCfg, 0x9F46, new byte[248]);
        byte[] longIccCert = certCfg.toByteArray();
        EMVStaticData sdIcc = new EMVStaticData();
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdIcc.applyPaymentConfig(
                        longIccCert, (short) 0, (short) longIccCert.length),
                "ICC certificate > 247 B -> 6A80");

        certCfg.reset();
        TlvWriter.writeTlv(certCfg, 0x9F2D, new byte[248]);
        byte[] longPinCert = certCfg.toByteArray();
        EMVStaticData sdPin = new EMVStaticData();
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> sdPin.applyPaymentConfig(
                        longPinCert, (short) 0, (short) longPinCert.length),
                "PIN certificate > 247 B -> 6A80");

        // A value exactly at the limit is accepted.
        certCfg.reset();
        TlvWriter.writeTlv(certCfg, 0x9F46, new byte[247]);
        TlvWriter.writeTlv(certCfg, 0x90, new byte[248]);
        byte[] atLimit = certCfg.toByteArray();
        EMVStaticData sdLimit = new EMVStaticData();
        Asserts.noThrow(() -> sdLimit.applyPaymentConfig(
                        atLimit, (short) 0, (short) atLimit.length),
                "certificates at the Table 43 limits are accepted");

        // --- FCI template validation (EMV CPS v2.0 Table A-14 / A-21) --------
        // The payment 9102 must be an A5 containing the mandatory label '50'.
        Asserts.check(PersoRules.isFciTemplate(
                        Hex.parse("A5 06 50 04 54 45 53 54"), (short) 0, (short) 8,
                        (short) 0x50), "A5 with 50 is a valid FCI template");
        Asserts.check(!PersoRules.isFciTemplate(
                        Hex.parse("A5 04 87 02 00 01"), (short) 0, (short) 6,
                        (short) 0x50), "A5 without 50 is rejected");
        Asserts.check(!PersoRules.isFciTemplate(
                        Hex.parse("6F 06 50 04 54 45 53 54"), (short) 0, (short) 8,
                        (short) 0x50), "non-A5 is rejected");
        // The PSE 9102 requires '88' and the PPSE 9102 requires 'BF0C'.
        Asserts.check(PersoRules.isFciTemplate(
                        Hex.parse("A5 03 88 01 01"), (short) 0, (short) 5,
                        (short) 0x88), "PSE A5 with 88 is valid");
        Asserts.check(PersoRules.isFciTemplate(
                        Hex.parse("A5 08 BF0C 05 61 03 4F 01 01"), (short) 0, (short) 10,
                        (short) 0xBF0C), "PPSE A5 with BF0C is valid");
        Asserts.check(!PersoRules.isFciTemplate(
                        Hex.parse("A5 03 88 01 01"), (short) 0, (short) 5,
                        (short) 0x50), "A5 without the required tag is rejected");
        // A malformed A5 (length runs past the container) is rejected.
        Asserts.check(!PersoRules.isFciTemplate(
                        Hex.parse("A5 10 50 04 54 45 53 54"), (short) 0, (short) 8,
                        (short) 0x50), "A5 with overlong length is rejected");
        // validateFciTemplate throws 6A80 on a non-A5 value.
        byte[] notA5 = Hex.parse("6F 06 50 04 54 45 53 54");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validateFciTemplate(
                        notA5, (short) 0, (short) notA5.length, (short) 0x50),
                "validateFciTemplate non-A5 -> 6A80");

        // --- PPSE template validation (Book B v2.12 Table 3-2 / Table A-1) ----
        // A well-formed PPSE: A5 { BF0C { 61 { 4F, 9F2A } } }.
        ByteArrayOutputStream goodEntry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(goodEntry, 0x4F, Hex.parse("43415244420101"));
        TlvWriter.writeTlv(goodEntry, 0x9F2A, new byte[] { 0x00 });
        ByteArrayOutputStream goodBf0c = new ByteArrayOutputStream();
        TlvWriter.writeTlv(goodBf0c, 0x61, goodEntry.toByteArray());
        ByteArrayOutputStream goodA5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(goodA5, 0xA5, wrapTlv(0xBF0C, goodBf0c.toByteArray()));
        byte[] goodPpse = goodA5.toByteArray();
        Asserts.noThrow(() -> PersoRules.validatePpseTemplate(
                        goodPpse, (short) 0, (short) goodPpse.length),
                "valid PPSE template accepted");

        // An empty candidate list is rejected.
        ByteArrayOutputStream emptyA5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(emptyA5, 0xA5, wrapTlv(0xBF0C, new byte[0]));
        byte[] emptyPpse = emptyA5.toByteArray();
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validatePpseTemplate(
                        emptyPpse, (short) 0, (short) emptyPpse.length),
                "empty PPSE candidate list -> 6A80");

        // A Directory Entry without 4F is rejected.
        ByteArrayOutputStream noAdfA5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(noAdfA5, 0xA5,
                wrapTlv(0xBF0C, wrapTlv(0x61, wrapTlv(0x50, Hex.parse("54455354")))));
        byte[] noAdfPpse = noAdfA5.toByteArray();
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validatePpseTemplate(
                        noAdfPpse, (short) 0, (short) noAdfPpse.length),
                "PPSE entry without 4F -> 6A80");

        // An ADF Name shorter than the 5-byte RID is rejected (Table 3-2).
        ByteArrayOutputStream shortAdfEntry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(shortAdfEntry, 0x4F, Hex.parse("454D5634"));
        ByteArrayOutputStream shortAdfA5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(shortAdfA5, 0xA5,
                wrapTlv(0xBF0C, wrapTlv(0x61, shortAdfEntry.toByteArray())));
        byte[] shortAdfPpse = shortAdfA5.toByteArray();
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validatePpseTemplate(
                        shortAdfPpse, (short) 0, (short) shortAdfPpse.length),
                "PPSE ADF Name shorter than 5 bytes -> 6A80");

        // A two-byte Application Priority Indicator is rejected (Table 3-3).
        ByteArrayOutputStream badPrioEntry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(badPrioEntry, 0x4F, Hex.parse("43415244420101"));
        TlvWriter.writeTlv(badPrioEntry, 0x87, new byte[] { 0x00, 0x01 });
        ByteArrayOutputStream badPrioA5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(badPrioA5, 0xA5,
                wrapTlv(0xBF0C, wrapTlv(0x61, badPrioEntry.toByteArray())));
        byte[] badPrioPpse = badPrioA5.toByteArray();
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validatePpseTemplate(
                        badPrioPpse, (short) 0, (short) badPrioPpse.length),
                "PPSE 87 of two bytes -> 6A80");

        // A two-byte 9F2A is rejected (EMV Contactless Book B v2.12 Table A-1:
        // 1 or 3-8 bytes).
        ByteArrayOutputStream badKernelEntry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(badKernelEntry, 0x4F, Hex.parse("43415244420101"));
        TlvWriter.writeTlv(badKernelEntry, 0x9F2A, new byte[] { 0x00, 0x01 });
        ByteArrayOutputStream badKernelA5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(badKernelA5, 0xA5,
                wrapTlv(0xBF0C, wrapTlv(0x61, badKernelEntry.toByteArray())));
        byte[] badKernelPpse = badKernelA5.toByteArray();
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validatePpseTemplate(
                        badKernelPpse, (short) 0, (short) badKernelPpse.length),
                "PPSE 9F2A of two bytes -> 6A80");

        // Length(9F29) + Length(4F) > 16 is rejected (EMV Contactless Book B v2.12 Table A-1).
        ByteArrayOutputStream extEntry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(extEntry, 0x4F, new byte[15]);
        TlvWriter.writeTlv(extEntry, 0x9F29, new byte[2]);
        ByteArrayOutputStream extA5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(extA5, 0xA5,
                wrapTlv(0xBF0C, wrapTlv(0x61, extEntry.toByteArray())));
        byte[] extPpse = extA5.toByteArray();
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validatePpseTemplate(
                        extPpse, (short) 0, (short) extPpse.length),
                "PPSE 9F29 + 4F > 16 -> 6A80");

        // --- PSE record validation (EMV CPS v2.0 Annex A Table A-20) ----------
        // A well-formed directory record: 70 { 61 { 4F, 50, 87 } }.
        ByteArrayOutputStream goodPseEntry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(goodPseEntry, 0x4F, Hex.parse("43415244420101"));
        TlvWriter.writeTlv(goodPseEntry, 0x50, Hex.parse("454D563432"));
        TlvWriter.writeTlv(goodPseEntry, 0x87, new byte[] { 0x01 });
        byte[] goodPseRecord = wrapTlv(0x70, wrapTlv(0x61, goodPseEntry.toByteArray()));
        Asserts.noThrow(() -> PersoRules.validatePseRecord(
                        goodPseRecord, (short) 0, (short) goodPseRecord.length),
                "valid PSE record accepted");

        // A 70 without a 61 Directory Entry is rejected.
        byte[] noEntryRecord = wrapTlv(0x70, wrapTlv(0x50, Hex.parse("54455354")));
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validatePseRecord(
                        noEntryRecord, (short) 0, (short) noEntryRecord.length),
                "PSE record without 61 -> 6A80");

        // A 61 without the mandatory ADF Name (4F) is rejected.
        byte[] noAdfRecord = wrapTlv(0x70,
                wrapTlv(0x61, wrapTlv(0x50, Hex.parse("54455354"))));
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validatePseRecord(
                        noAdfRecord, (short) 0, (short) noAdfRecord.length),
                "PSE entry without 4F -> 6A80");

        // A 61 without the mandatory Application Label (50) is rejected
        // (EMV v4.4 Book 1 §12.2.3 Table 12).
        byte[] noLabelRecord = wrapTlv(0x70,
                wrapTlv(0x61, wrapTlv(0x4F, Hex.parse("43415244420101"))));
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validatePseRecord(
                        noLabelRecord, (short) 0, (short) noLabelRecord.length),
                "PSE entry without 50 -> 6A80");

        // An ADF Name shorter than the 5-byte RID is rejected.
        byte[] shortAdfRecord = wrapTlv(0x70,
                wrapTlv(0x61, wrapTlv(0x4F, Hex.parse("454D5634"))));
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validatePseRecord(
                        shortAdfRecord, (short) 0, (short) shortAdfRecord.length),
                "PSE ADF Name shorter than 5 bytes -> 6A80");

        // A two-byte Application Priority Indicator is rejected.
        ByteArrayOutputStream badPriorityEntry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(badPriorityEntry, 0x4F, Hex.parse("43415244420101"));
        TlvWriter.writeTlv(badPriorityEntry, 0x87, new byte[] { 0x00, 0x01 });
        byte[] badPriorityRecord = wrapTlv(0x70,
                wrapTlv(0x61, badPriorityEntry.toByteArray()));
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validatePseRecord(
                        badPriorityRecord, (short) 0, (short) badPriorityRecord.length),
                "PSE priority indicator of two bytes -> 6A80");

        // A value that is not a 70 template is rejected.
        byte[] notPseRecord = Hex.parse("61 03 4F 01 01");
        Asserts.sw(ISO7816.SW_WRONG_DATA, () -> PersoRules.validatePseRecord(
                        notPseRecord, (short) 0, (short) notPseRecord.length),
                "PSE record not a 70 template -> 6A80");

        // --- FCI override with an existing BF0C (EMV CPS v2.0 Table A-14) -------------
        // The payment A5 override may already carry BF0C; the Log Entry is
        // merged into it instead of adding a second BF0C.
        EMVStaticData sdMerge = new EMVStaticData();
        sdMerge.setAid(Hex.parse("43415244420101"));
        byte[] mergeOverride = wrapTlv(0xA5,
                wrapTlv(0xBF0C, wrapTlv(0x50, Hex.parse("54455354"))));
        sdMerge.setFciOverride(mergeOverride, (short) 0, (short) mergeOverride.length);
        byte[] mergedFci = sdMerge.getFCI((byte) 0x00);
        Asserts.eq(1, Tags.findAll(mergedFci, 0xBF0C).size(),
                "A5 override keeps a single BF0C");
        Asserts.check(Tags.find(mergedFci, 0x9F4D) != null,
                "Log Entry merged into the existing BF0C");
    }

    /** Wraps a value in a BER-TLV (helper for the PPSE / FCI tests). */
    private static byte[] wrapTlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, value);
        return out.toByteArray();
    }
}
