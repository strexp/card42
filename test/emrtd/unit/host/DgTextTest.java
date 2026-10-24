package card42.test;

import java.util.List;

import card42.host.emrtd.lds.common.ImageData;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.ParseStatus;
import card42.host.emrtd.lds.lds1.Dg5;
import card42.host.emrtd.lds.lds1.Dg7;
import card42.host.emrtd.lds.lds1.Dg8;
import card42.host.emrtd.lds.lds1.Dg9;
import card42.host.emrtd.lds.lds1.Dg10;
import card42.host.emrtd.lds.lds1.Dg11;
import card42.host.emrtd.lds.lds1.Dg12;
import card42.host.emrtd.lds.lds1.Dg13;
import card42.host.emrtd.lds.lds1.Dg16;
import card42.host.emrtd.lds.lds1.PersonToNotify;

/** DG5/DG7/DG8-10/DG11/DG12/DG13/DG16 parser tests. */
final class DgTextTest {

    private DgTextTest() {
    }

    static void run() {
        System.out.println("DgText");
        dg5();
        dg7();
        dg8To10();
        dg11();
        dg11EncodingFallback();
        dg12();
        dg12BcdDateTime();
        dg13();
        dg16();
        malformed();
    }

    private static void dg5() {
        Dg5 dg5 = Dg5.parse(LdsFixtures.dg5(LdsFixtures.JPEG, LdsFixtures.JPEG));
        Asserts.eq(2, dg5.portraits.size(), "DG5 portraits");
        Asserts.eq(ParseStatus.OK, dg5.status, "DG5 status");
        Asserts.eq(ImageData.Format.JPEG, dg5.portraits.get(0).format, "DG5 format");
        Asserts.bytes(LdsFixtures.JPEG, dg5.portraits.get(1).bytes, "DG5 image bytes");
    }

    private static void dg7() {
        Dg7 dg7 = Dg7.parse(LdsFixtures.dg7(LdsFixtures.JPEG));
        Asserts.eq(1, dg7.signatures.size(), "DG7 signatures");
        Asserts.eq(ParseStatus.OK, dg7.status, "DG7 status");
        Asserts.eq(ImageData.Format.JPEG, dg7.signatures.get(0).format, "DG7 format");
    }

    private static void dg8To10() {
        byte[] template = LdsFixtures.tlv(0x5F2B, new byte[] { 1, 2, 3 });
        Dg8 dg8 = Dg8.parse(LdsFixtures.templateGroup(0x68, template));
        Asserts.eq(1, dg8.templates.size(), "DG8 templates");
        Asserts.eq(1, dg8.declaredCount, "DG8 declared count");
        Asserts.eq(ParseStatus.OK, dg8.status, "DG8 status");
        Asserts.check(dg8.templates.get(0)[0] == 0x5F, "DG8 template keeps its tag");

        Dg9 dg9 = Dg9.parse(LdsFixtures.templateGroup(0x69, template));
        Asserts.eq(1, dg9.templates.size(), "DG9 templates");
        Dg10 dg10 = Dg10.parse(LdsFixtures.templateGroup(0x6A, template));
        Asserts.eq(1, dg10.templates.size(), "DG10 templates");

        Dg8 empty = Dg8.parse(LdsFixtures.tlv(0x68, new byte[0]));
        Asserts.eq(ParseStatus.OK, empty.status, "empty DG8 structure is valid");
        Asserts.check(empty.templates.isEmpty(), "empty DG8 has no template");
    }

    private static void dg11() {
        Dg11 dg11 = Dg11.parse(LdsFixtures.dg11());
        Asserts.eq(ParseStatus.OK, dg11.status, "DG11 status");
        Asserts.eq("张<<三", dg11.fullName, "DG11 full name is UTF-8");
        Asserts.eq(2, dg11.otherNames.size(), "DG11 repeated other names");
        Asserts.eq("OTHER<ONE", dg11.otherNames.get(0), "DG11 first other name");
        Asserts.eq("P1234567", dg11.personalNumber, "DG11 personal number");
        Asserts.eq("1990-01-01", dg11.fullDateOfBirth.toString(), "DG11 full date of birth");
        Asserts.eq("UTOPIA", dg11.placeOfBirth, "DG11 place of birth");
        Asserts.eq("1<STREET<UTOPIA", dg11.permanentAddress, "DG11 address");
        Asserts.eq("+4680000000", dg11.telephone, "DG11 telephone");
        Asserts.eq("ENGINEER", dg11.profession, "DG11 profession");
        Asserts.eq("DR", dg11.title, "DG11 title");
        Asserts.eq("SUMMARY", dg11.personalSummary, "DG11 summary");
        Asserts.eq(ImageData.Format.JPEG, dg11.proofOfCitizenship.format,
                "DG11 proof of citizenship image");
        Asserts.eq("TD1<TD2", dg11.otherValidTdNumbers, "DG11 other TD numbers");
        Asserts.eq("CUSTODY", dg11.custodyInformation, "DG11 custody information");
        Asserts.check(dg11.unknown.containsKey(0xDF01), "DG11 unknown tag is kept");
        Asserts.check(!dg11.declaredTags.isEmpty(), "DG11 tag list is exposed");
    }

    private static void dg11EncodingFallback() {
        byte[] raw = LdsFixtures.tlv(0x6B,
                LdsFixtures.tlv(0x5F0E, new byte[] { (byte) 0xC3, 0x28 }));
        Dg11 dg11 = Dg11.parse(raw);
        Asserts.eq(ParseStatus.PARTIAL, dg11.status, "DG11 bad encoding is partial");
        Asserts.check(hasCode(dg11.issues, LdsIssue.Code.BAD_ENCODING),
                "DG11 bad encoding issue");
    }

    private static void dg12() {
        Dg12 dg12 = Dg12.parse(LdsFixtures.dg12());
        Asserts.eq(ParseStatus.OK, dg12.status, "DG12 status");
        Asserts.eq("UTO PASSPORT OFFICE", dg12.issuingAuthority, "DG12 issuing authority");
        Asserts.eq("2026-01-01", dg12.dateOfIssue.toString(), "DG12 date of issue");
        Asserts.eq(1, dg12.otherPersons.size(), "DG12 other persons");
        Asserts.eq("ENDORSEMENT", dg12.endorsements, "DG12 endorsements");
        Asserts.eq("TAX", dg12.taxExitRequirements, "DG12 tax requirements");
        Asserts.eq(ImageData.Format.JPEG, dg12.frontImage.format, "DG12 front image");
        Asserts.eq(ImageData.Format.JPEG, dg12.rearImage.format, "DG12 rear image");
        Asserts.eq("20260101120000", dg12.personalizationDateTime,
                "DG12 personalization date/time");
        Asserts.eq("2026-01-01", dg12.personalizationDate.toString(),
                "DG12 parsed personalization date");
        Asserts.eq("card42", dg12.personalizationSystemSerial, "DG12 personalization serial");
        Asserts.check(dg12.unknown.containsKey(0xDF02), "DG12 unknown tag is kept");
    }

    private static void dg12BcdDateTime() {
        Dg12 dg12 = Dg12.parse(LdsFixtures.dg12BcdDateTime());
        Asserts.eq("20260101120000", dg12.personalizationDateTime,
                "DG12 BCD date/time");
        Asserts.eq("2026-01-01", dg12.personalizationDate.toString(),
                "DG12 BCD date");
    }

    private static void dg13() {
        Dg13 dg13 = Dg13.parse(LdsFixtures.dg13());
        Asserts.eq(ParseStatus.OK, dg13.status, "DG13 status");
        Asserts.check(dg13.value.length > 0, "DG13 keeps the issuer-defined value");

        Dg13 noWrapper = Dg13.parse(LdsFixtures.tlv(0x5F2B, new byte[] { 1 }));
        Asserts.eq(ParseStatus.PARTIAL, noWrapper.status, "DG13 without 6D is partial");
        Asserts.check(hasCode(noWrapper.issues, LdsIssue.Code.OUTER_TAG_MISMATCH),
                "DG13 outer tag issue");
    }

    private static void dg16() {
        Dg16 dg16 = Dg16.parse(LdsFixtures.dg16());
        Asserts.eq(ParseStatus.OK, dg16.status, "DG16 status");
        Asserts.eq(2, dg16.persons.size(), "DG16 persons");
        PersonToNotify first = dg16.persons.get(0);
        Asserts.eq(0xA1, first.templateTag, "DG16 first template tag");
        Asserts.eq("UTOPIA<CONTACT", first.name, "DG16 name");
        Asserts.eq("+4680000001", first.telephone, "DG16 telephone");
        Asserts.eq("UTOPIA<STREET 1", first.address, "DG16 address");
        Asserts.eq("2026-01-01", first.dateRecorded.toString(), "DG16 date recorded");

        byte[] unknown = LdsFixtures.tlv(0x70,
                LdsFixtures.tlv(0x02, new byte[] { 0x01 }),
                LdsFixtures.tlv(0xA1,
                        LdsFixtures.tlv(0x5F50, LdsFixtures.ascii("20260101")),
                        LdsFixtures.tlv(0x5F51, LdsFixtures.ascii("NAME")),
                        LdsFixtures.tlv(0xDF03, new byte[] { 0x09 })));
        Dg16 withUnknown = Dg16.parse(unknown);
        Asserts.check(withUnknown.persons.get(0).unknown.containsKey(0xDF03),
                "DG16 unknown tag is kept");
    }

    private static void malformed() {
        byte[][] samples = {
                LdsFixtures.dg5(LdsFixtures.JPEG),
                LdsFixtures.dg7(LdsFixtures.JPEG),
                LdsFixtures.templateGroup(0x68, LdsFixtures.tlv(0x5F2B, new byte[] { 1 })),
                LdsFixtures.dg11(),
                LdsFixtures.dg12(),
                LdsFixtures.dg13(),
                LdsFixtures.dg16()
        };
        for (byte[] sample : samples) {
            for (byte[] truncated : LdsFixtures.truncations(sample)) {
                try {
                    switch (sample[0]) {
                    case 0x65:
                        Dg5.parse(truncated);
                        break;
                    case 0x67:
                        Dg7.parse(truncated);
                        break;
                    case 0x68:
                        Dg8.parse(truncated);
                        break;
                    case 0x6B:
                        Dg11.parse(truncated);
                        break;
                    case 0x6C:
                        Dg12.parse(truncated);
                        break;
                    case 0x6D:
                        Dg13.parse(truncated);
                        break;
                    default:
                        Dg16.parse(truncated);
                        break;
                    }
                    Asserts.check(true, "truncated text DG does not throw");
                } catch (RuntimeException e) {
                    Asserts.check(false, "truncated text DG threw " + e);
                }
            }
        }
        Asserts.eq(ParseStatus.INVALID, Dg11.parse(new byte[0]).status,
                "empty DG11 is invalid");
        Asserts.eq(ParseStatus.INVALID, Dg12.parse(new byte[0]).status,
                "empty DG12 is invalid");
        Asserts.eq(ParseStatus.INVALID, Dg13.parse(new byte[0]).status,
                "empty DG13 is invalid");
        Asserts.eq(ParseStatus.INVALID, Dg16.parse(new byte[0]).status,
                "empty DG16 is invalid");
    }

    private static boolean hasCode(List<LdsIssue> issues, LdsIssue.Code code) {
        for (LdsIssue issue : issues) {
            if (issue.code == code) {
                return true;
            }
        }
        return false;
    }
}
