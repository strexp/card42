package card42.host.emrtd.lds;

import card42.host.common.codec.Tags;

/**
 * Data group 1: the MRZ (ICAO Doc 9303-10 §4.7.1, Doc 9303-4 for the TD1/TD2/TD3
 * layouts).  The layout is chosen from the MRZ length: TD1 is three 30-character
 * lines (90), TD2 two 36-character lines (72) and TD3 two 44-character lines
 * (88).  Only the fields a report needs are extracted (H1.1).
 */
public final class Dg1 {

    public final String mrz;
    public final String issuingState;
    public final String surname;
    public final String givenNames;
    public final String documentNumber;
    public final String nationality;
    public final String dateOfBirth;
    public final String sex;
    public final String dateOfExpiry;

    private Dg1(String mrz) {
        this.mrz = mrz;
        int len = mrz.length();
        if (len >= 90) {
            // TD1: three 30-character lines (name on line 3).
            String line1 = slice(mrz, 0, 30);
            String line2 = slice(mrz, 30, 60);
            String line3 = slice(mrz, 60, 90);
            this.issuingState = slice(line1, 2, 5).trim();
            this.documentNumber = slice(line1, 5, 14).trim();
            String[] names = names(line3);
            this.surname = names[0];
            this.givenNames = names[1];
            this.dateOfBirth = slice(line2, 0, 6);
            this.sex = slice(line2, 7, 8);
            this.dateOfExpiry = slice(line2, 8, 14);
            this.nationality = slice(line2, 15, 18).trim();
        } else if (len >= 88) {
            // TD3: two 44-character lines.
            String line1 = slice(mrz, 0, 44);
            String line2 = slice(mrz, 44, 88);
            this.issuingState = slice(line1, 2, 5).trim();
            String[] names = names(slice(line1, 5, 44));
            this.surname = names[0];
            this.givenNames = names[1];
            this.documentNumber = slice(line2, 0, 9).trim();
            this.nationality = slice(line2, 10, 13).trim();
            this.dateOfBirth = slice(line2, 13, 19);
            this.sex = slice(line2, 20, 21);
            this.dateOfExpiry = slice(line2, 21, 27);
        } else if (len >= 72) {
            // TD2: two 36-character lines.
            String line1 = slice(mrz, 0, 36);
            String line2 = slice(mrz, 36, 72);
            this.issuingState = slice(line1, 2, 5).trim();
            String[] names = names(slice(line1, 5, 36));
            this.surname = names[0];
            this.givenNames = names[1];
            this.documentNumber = slice(line2, 0, 9).trim();
            this.nationality = slice(line2, 10, 13).trim();
            this.dateOfBirth = slice(line2, 13, 19);
            this.sex = slice(line2, 20, 21);
            this.dateOfExpiry = slice(line2, 21, 27);
        } else {
            throw new IllegalArgumentException(
                    "DG1 MRZ length " + len + " is not TD1/TD2/TD3");
        }
    }

    /** Parses a DG1 (tag 61 containing 5F1F). */
    public static Dg1 parse(byte[] dg1) {
        byte[] value = Tags.find(dg1, 0x5F1F);
        if (value == null) {
            throw new IllegalArgumentException("DG1 has no MRZ (5F1F)");
        }
        return new Dg1(new String(value, java.nio.charset.StandardCharsets.US_ASCII));
    }

    private static String[] names(String field) {
        int sep = field.indexOf("<<");
        if (sep < 0) {
            return new String[] { field.replace('<', ' ').trim(), "" };
        }
        String surname = field.substring(0, sep).replace('<', ' ').trim();
        String given = field.substring(sep + 2).replace('<', ' ').trim();
        return new String[] { surname, given };
    }

    private static String slice(String s, int from, int to) {
        if (from >= s.length()) {
            return "";
        }
        return s.substring(from, Math.min(to, s.length()));
    }
}
