package card42.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.MrzCheckDigit;
import card42.host.emrtd.lds.common.ParseStatus;
import card42.host.emrtd.lds.lds2.Mrv;
import card42.host.emrtd.lds.lds2.VisaRecord;
import card42.host.emrtd.lds.lds2.VisaRecordBuilder;

/** MRV-A/MRV-B and VisaRecord integration tests (ICAO Doc 9303-7/§5.2.3). */
final class MrvTest {

    private MrvTest() {
    }

    static void run() throws Exception {
        System.out.println("Mrv");
        mrvA();
        mrvB();
        badCheckDigit();
        badDate();
        visaRecord();
    }

    private static void mrvA() {
        Mrv mrv = Mrv.parse(mrvA(2026), 2026);
        Asserts.eq(Mrv.Layout.MRV_A, mrv.layout, "MRV-A layout");
        Asserts.eq(ParseStatus.OK, mrv.status, "MRV-A status");
        Asserts.eq("V<", mrv.documentCode, "MRV-A document code");
        Asserts.eq("UTO", mrv.issuingState, "MRV-A issuing state");
        Asserts.eq("ERIKSSON", mrv.surname, "MRV-A surname");
        Asserts.eq("ANNA MARIA", mrv.givenNames, "MRV-A given names");
        Asserts.eq("L898902C<", mrv.visaNumber, "MRV-A visa number");
        Asserts.eq("UTO", mrv.nationality, "MRV-A nationality");
        Asserts.eq("1969-08-06", mrv.birthDate.toString(), "MRV-A birth date");
        Asserts.eq("1994-06-23", mrv.expiryDate.toString(), "MRV-A expiry date");
        Asserts.eq("F", mrv.sex, "MRV-A sex");
        Asserts.check(mrv.visaNumberCheckOk, "MRV-A visa check digit");
        Asserts.check(mrv.issues.isEmpty(), "MRV-A has no issues");
    }

    private static void mrvB() {
        Mrv mrv = Mrv.parse(mrvB(2026), 2026);
        Asserts.eq(Mrv.Layout.MRV_B, mrv.layout, "MRV-B layout");
        Asserts.eq(ParseStatus.OK, mrv.status, "MRV-B status");
        Asserts.eq("L898902C<", mrv.visaNumber, "MRV-B visa number");
        Asserts.eq("1969-08-06", mrv.birthDate.toString(), "MRV-B birth date");
    }

    private static void badCheckDigit() {
        String mrv = mrvA(2026);
        char[] chars = mrv.toCharArray();
        int checkIndex = 44 + 9;
        chars[checkIndex] = chars[checkIndex] == '3' ? '4' : '3';
        Mrv parsed = Mrv.parse(new String(chars), 2026);
        Asserts.eq(ParseStatus.PARTIAL, parsed.status, "MRV wrong check digit is partial");
        Asserts.check(hasCode(parsed.issues, LdsIssue.Code.BAD_CHECK_DIGIT),
                "MRV wrong check digit issue");
    }

    private static void badDate() {
        String mrv = mrvA(2026);
        char[] chars = mrv.toCharArray();
        "991332".getChars(0, 6, chars, 44 + 13);
        Mrv parsed = Mrv.parse(new String(chars), 2026);
        Asserts.check(!parsed.birthDate.valid, "MRV invalid date has no LocalDate");
        Asserts.check(hasCode(parsed.issues, LdsIssue.Code.BAD_DATE), "MRV invalid date issue");
        Asserts.eq(ParseStatus.INVALID, Mrv.parse("ABC", 2026).status,
                "short MRV is invalid");
    }

    private static void visaRecord() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();

        byte[] record = new VisaRecordBuilder()
                .issuingState("UTO")
                .documentType("V")
                .machineReadableVisaA(mrvA(2026))
                .machineReadableVisaB(mrvB(2026))
                .placeOfIssue("UTOPIA")
                .effectiveDate("20260101")
                .expirationDate("20270101")
                .documentNumber("D23145890")
                .name("ERIKSSON<<ANNA<MARIA")
                .surname("ERIKSSON")
                .givenNames("ANNA MARIA")
                .sex("F")
                .dateOfBirth("19690806")
                .nationality("UTO")
                .mrz("V<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<")
                .build(keyPair.getPrivate());

        VisaRecord visa = new VisaRecord(record);
        Asserts.check(visa.wellFormed, "visa record is well formed");
        Asserts.check(visa.mrvA() != null, "visa record exposes MRV-A");
        Asserts.eq(Mrv.Layout.MRV_A, visa.mrvA().layout, "visa MRV-A layout");
        Asserts.check(visa.mrvB() != null, "visa record exposes MRV-B");
        Asserts.eq("2026-01-01", visa.effectiveDateValue().toString(),
                "visa effective date");
        Asserts.eq("2027-01-01", visa.expirationDateValue().toString(),
                "visa expiration date");
        Asserts.eq(ParseStatus.OK, visa.mrvA().status, "visa MRV-A status");
        Asserts.check(visa.verify(keyPair.getPublic()), "visa signature still verifies");

        VisaRecord noMrv = new VisaRecord(recordWithoutMrv(keyPair));
        Asserts.check(noMrv.mrvA() == null && noMrv.mrvB() == null,
                "visa record without MRV yields null models");
    }

    private static byte[] recordWithoutMrv(KeyPair keyPair) throws Exception {
        return new VisaRecordBuilder()
                .issuingState("UTO")
                .documentType("V")
                .placeOfIssue("UTOPIA")
                .effectiveDate("20260101")
                .expirationDate("20270101")
                .documentNumber("D23145890")
                .name("ERIKSSON<<ANNA<MARIA")
                .surname("ERIKSSON")
                .givenNames("ANNA MARIA")
                .sex("F")
                .dateOfBirth("19690806")
                .nationality("UTO")
                .mrz("V<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<")
                .build(keyPair.getPrivate());
    }

    private static String mrvA(int referenceYear) {
        return mrv(44, referenceYear);
    }

    private static String mrvB(int referenceYear) {
        return mrv(36, referenceYear);
    }

    /** Builds a valid MRV-A (width 44) or MRV-B (width 36). */
    private static String mrv(int width, int referenceYear) {
        String line1 = pad("V<UTOERIKSSON<<ANNA<MARIA", width);
        String visa = "L898902C<";
        String dob = "690806";
        String doe = "940623";
        StringBuilder line2 = new StringBuilder();
        line2.append(visa).append((char) ('0' + MrzCheckDigit.compute(visa)));
        line2.append("UTO");
        line2.append(dob).append((char) ('0' + MrzCheckDigit.compute(dob)));
        line2.append('F');
        line2.append(doe).append((char) ('0' + MrzCheckDigit.compute(doe)));
        int optional = width - 1 - 28;
        for (int i = 0; i < optional; i++) {
            line2.append('<');
        }
        line2.append('<'); // composite/filler: not validated for MRV
        return line1 + line2;
    }

    private static String pad(String s, int length) {
        StringBuilder b = new StringBuilder(s);
        while (b.length() < length) {
            b.append('<');
        }
        return b.substring(0, length);
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
