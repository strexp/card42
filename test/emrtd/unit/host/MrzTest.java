package card42.test;

import java.util.List;

import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.ParseStatus;
import card42.host.emrtd.lds.lds1.Mrz;

/** MRZ layout, check digit and date tests (ICAO Doc 9303-4). */
final class MrzTest {

    private static final String TD3_LINE1 =
            "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    private static final String TD3_LINE2 =
            "L898902C<3UTO6908061F9406236ZE184226B<<<<<14";

    private static final String TD1_LINE1 = "I<YTOD231458907<<<<<<<<<<<<<<<";
    private static final String TD1_LINE2 = "3407127M9507122YTO<<<<<<<<<<<2";
    private static final String TD1_LINE3 = "ERIKSSON<<ANNA<MARIA<<<<<<<<<<";

    // ICAO Doc 9303-3 Appendix A example 5 (lower line only).
    private static final String TD2_LINE1 = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<";
    private static final String TD2_LINE2 = "HA672242<6YTO5802254M9601086<<<<<<<8";

    private MrzTest() {
    }

    static void run() {
        System.out.println("Mrz");
        td3();
        td1();
        td2();
        badCheckDigit();
        badDate();
        shortAndNoisyInput();
    }

    private static void td3() {
        Mrz mrz = Mrz.parse(TD3_LINE1 + TD3_LINE2, 2026);
        Asserts.eq(Mrz.Layout.TD3, mrz.layout, "TD3 layout");
        Asserts.eq(ParseStatus.OK, mrz.status, "TD3 status");
        Asserts.eq("P<", mrz.documentCode, "TD3 document code");
        Asserts.eq("UTO", mrz.issuingState, "TD3 issuing state");
        Asserts.eq("ERIKSSON", mrz.surname, "TD3 surname");
        Asserts.eq("ANNA MARIA", mrz.givenNames, "TD3 given names");
        Asserts.eq("L898902C<", mrz.documentNumber, "TD3 document number");
        Asserts.eq("UTO", mrz.nationality, "TD3 nationality");
        Asserts.eq("690806", mrz.dateOfBirth, "TD3 date of birth");
        Asserts.eq("F", mrz.sex, "TD3 sex");
        Asserts.eq("940623", mrz.dateOfExpiry, "TD3 date of expiry");
        Asserts.eq("ZE184226B", mrz.personalNumber, "TD3 personal number");
        Asserts.eq("4", mrz.compositeCheckDigit, "TD3 composite check digit");
        Asserts.eq("1969-08-06", mrz.birthDate.toString(), "TD3 parsed birth date");
        Asserts.eq("1994-06-23", mrz.expiryDate.toString(), "TD3 parsed expiry date");
        Asserts.check(mrz.documentNumberCheckOk, "TD3 document check digit");
        Asserts.check(mrz.dateOfBirthCheckOk, "TD3 date-of-birth check digit");
        Asserts.check(mrz.dateOfExpiryCheckOk, "TD3 date-of-expiry check digit");
        Asserts.check(mrz.personalNumberCheckOk, "TD3 personal-number check digit");
        Asserts.check(mrz.compositeCheckOk, "TD3 composite check digit is valid");
        Asserts.check(mrz.issues.isEmpty(), "TD3 has no issues");
    }

    private static void td1() {
        Mrz mrz = Mrz.parse(TD1_LINE1 + TD1_LINE2 + TD1_LINE3, 2026);
        Asserts.eq(Mrz.Layout.TD1, mrz.layout, "TD1 layout");
        Asserts.eq(ParseStatus.OK, mrz.status, "TD1 status");
        Asserts.eq("I<", mrz.documentCode, "TD1 document code");
        Asserts.eq("YTO", mrz.issuingState, "TD1 issuing state");
        Asserts.eq("D23145890", mrz.documentNumber, "TD1 document number");
        Asserts.eq("ERIKSSON", mrz.surname, "TD1 surname");
        Asserts.eq("ANNA MARIA", mrz.givenNames, "TD1 given names");
        Asserts.eq("340712", mrz.dateOfBirth, "TD1 date of birth");
        Asserts.eq("1934-07-12", mrz.birthDate.toString(), "TD1 parsed birth date");
        Asserts.eq("M", mrz.sex, "TD1 sex");
        Asserts.eq("950712", mrz.dateOfExpiry, "TD1 date of expiry");
        Asserts.check(mrz.compositeCheckOk, "TD1 composite check digit");
        Asserts.check(mrz.issues.isEmpty(), "TD1 has no issues");
    }

    private static void td2() {
        Mrz mrz = Mrz.parse(TD2_LINE1 + TD2_LINE2, 2026);
        Asserts.eq(Mrz.Layout.TD2, mrz.layout, "TD2 layout");
        Asserts.eq(ParseStatus.OK, mrz.status, "TD2 status");
        Asserts.eq("HA672242<", mrz.documentNumber, "TD2 document number");
        Asserts.eq("YTO", mrz.nationality, "TD2 nationality");
        Asserts.eq("580225", mrz.dateOfBirth, "TD2 date of birth");
        Asserts.eq("M", mrz.sex, "TD2 sex");
        Asserts.eq("960108", mrz.dateOfExpiry, "TD2 date of expiry");
        Asserts.check(mrz.compositeCheckOk, "TD2 composite check digit");
        Asserts.check(mrz.issues.isEmpty(), "TD2 has no issues");
    }

    private static void badCheckDigit() {
        char[] chars = TD3_LINE2.toCharArray();
        chars[9] = chars[9] == '3' ? '4' : '3';
        Mrz mrz = Mrz.parse(TD3_LINE1 + new String(chars), 2026);
        Asserts.eq(ParseStatus.PARTIAL, mrz.status, "wrong document check digit is partial");
        Asserts.check(!mrz.documentNumberCheckOk, "wrong document check digit is flagged");
        Asserts.check(hasCode(mrz.issues, LdsIssue.Code.BAD_CHECK_DIGIT),
                "wrong check digit issue");
        Asserts.eq("L898902C<", mrz.documentNumber, "field is kept despite a check failure");
    }

    private static void badDate() {
        char[] chars = TD3_LINE2.toCharArray();
        "691332".getChars(0, 6, chars, 13);
        Mrz mrz = Mrz.parse(TD3_LINE1 + new String(chars), 2026);
        Asserts.check(!mrz.birthDate.valid, "invalid date has no LocalDate");
        Asserts.check(hasCode(mrz.issues, LdsIssue.Code.BAD_DATE), "invalid date issue");
    }

    private static void shortAndNoisyInput() {
        Asserts.eq(ParseStatus.INVALID, Mrz.parse("ABC", 2026).status,
                "short MRZ is invalid");
        Asserts.eq(ParseStatus.INVALID, Mrz.parse((String) null, 2026).status,
                "null MRZ is invalid");

        Mrz withNewlines = Mrz.parse(TD3_LINE1 + "\r\n" + TD3_LINE2 + "\n", 2026);
        Asserts.eq(ParseStatus.OK, withNewlines.status, "CR/LF is ignored");
        Asserts.eq(88, withNewlines.normalized.length(), "normalized MRZ length");
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
