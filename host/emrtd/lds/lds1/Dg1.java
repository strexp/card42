package card42.host.emrtd.lds.lds1;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import card42.host.emrtd.lds.common.LdsBytes;
import card42.host.emrtd.lds.common.LdsDataGroup;
import card42.host.emrtd.lds.common.LdsDate;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.LdsText;
import card42.host.emrtd.lds.common.LdsTlv;
import card42.host.emrtd.lds.common.ParseStatus;

/**
 * Data group 1: the MRZ (ICAO Doc 9303-10 §4.7.1, Doc 9303-4 for the TD1/TD2/TD3
 * layouts).  DG1 = {@code 61 { 5F1F <MRZ> }}.
 *
 * <p>The class keeps the convenience fields it always had
 * ({@code documentNumber}, {@code surname}, ...) and adds the complete
 * {@link Mrz} model, check digits and parsed dates.  Parsing is tolerant: a
 * missing or malformed MRZ yields {@link ParseStatus#INVALID} with the raw EF
 * and issues instead of an exception, so a report can still show the card.
 */
public final class Dg1 implements LdsDataGroup {

    /** The complete EF bytes, including the outer tag. */
    public final byte[] raw;
    /** The MRZ string with CR/LF removed, or null. */
    public final String mrz;
    public final String documentCode;
    public final String issuingState;
    public final String surname;
    public final String givenNames;
    public final String documentNumber;
    public final String nationality;
    /** The raw six-digit {@code YYMMDD} field. */
    public final String dateOfBirth;
    /** "M", "F" or "&lt;". */
    public final String sex;
    /** The raw six-digit {@code YYMMDD} field. */
    public final String dateOfExpiry;

    public final String documentNumberCheckDigit;
    public final String dateOfBirthCheckDigit;
    public final String dateOfExpiryCheckDigit;
    public final String personalNumber;
    public final String personalNumberCheckDigit;
    public final String optionalData1;
    public final String optionalData2;
    public final String compositeCheckDigit;
    public final LdsDate birthDate;
    public final LdsDate expiryDate;

    public final ParseStatus status;
    public final List<LdsIssue> issues;

    private final Mrz model;

    private Dg1(byte[] raw, Mrz model, ParseStatus status, List<LdsIssue> issues) {
        this.raw = LdsBytes.copy(raw);
        this.model = model;
        this.mrz = model == null ? null : model.normalized;
        this.documentCode = model == null ? null : model.documentCode.trim();
        this.issuingState = model == null ? null : model.issuingState;
        this.surname = model == null ? null : model.surname;
        this.givenNames = model == null ? null : model.givenNames;
        this.documentNumber = model == null ? null : model.documentNumber;
        this.nationality = model == null ? null : model.nationality;
        this.dateOfBirth = model == null ? null : model.dateOfBirth;
        this.sex = model == null ? null : model.sex;
        this.dateOfExpiry = model == null ? null : model.dateOfExpiry;
        this.documentNumberCheckDigit = model == null ? null : model.documentNumberCheckDigit;
        this.dateOfBirthCheckDigit = model == null ? null : model.dateOfBirthCheckDigit;
        this.dateOfExpiryCheckDigit = model == null ? null : model.dateOfExpiryCheckDigit;
        this.personalNumber = model == null ? null : model.personalNumber;
        this.personalNumberCheckDigit =
                model == null ? null : model.personalNumberCheckDigit;
        this.optionalData1 = model == null ? null : model.optionalData1;
        this.optionalData2 = model == null ? null : model.optionalData2;
        this.compositeCheckDigit = model == null ? null : model.compositeCheckDigit;
        this.birthDate = model == null ? null : model.birthDate;
        this.expiryDate = model == null ? null : model.expiryDate;
        this.status = status;
        this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(issues));
    }

    /** Parses a DG1 EF, resolving two-digit years against the current year. */
    public static Dg1 parse(byte[] dg1) {
        return parse(dg1, LocalDate.now().getYear());
    }

    /** Parses a DG1 EF, resolving two-digit years against {@code referenceYear}. */
    public static Dg1 parse(byte[] dg1, int referenceYear) {
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        List<LdsTlv.Node> body = LdsTlv.body(dg1, 0x61, 1, issues);
        LdsTlv.Node mrz = LdsTlv.first(body, 0x5F1F);
        Mrz model = null;
        if (mrz == null) {
            issues.add(LdsIssue.error(LdsIssue.Code.MISSING_MANDATORY, 1, 0,
                    "DG1 has no MRZ (5F1F)"));
        } else {
            model = Mrz.parse(LdsText.ascii(mrz.value()), referenceYear);
            issues.addAll(model.issues);
        }
        ParseStatus status;
        if (model == null || model.layout == Mrz.Layout.UNKNOWN) {
            status = ParseStatus.INVALID;
        } else {
            status = hasProblems(issues) || model.status != ParseStatus.OK
                    ? ParseStatus.PARTIAL : ParseStatus.OK;
        }
        return new Dg1(dg1, model, status, issues);
    }

    private static boolean hasProblems(List<LdsIssue> issues) {
        for (LdsIssue issue : issues) {
            if (issue.severity != LdsIssue.Severity.INFO) {
                return true;
            }
        }
        return false;
    }

    /** The complete MRZ model, or null when DG1 has no usable MRZ. */
    public Mrz mrz() {
        return model;
    }

    /** The two-character document code at MRZ line 1 positions 1-2. */
    public String documentCode() {
        return documentCode;
    }

    /** True when the MRZ was parsed and all check digits/dates are valid. */
    public boolean fullyValid() {
        return status == ParseStatus.OK;
    }

    @Override
    public int dg() {
        return 1;
    }

    @Override
    public byte[] raw() {
        return raw.clone();
    }

    @Override
    public ParseStatus status() {
        return status;
    }

    @Override
    public List<LdsIssue> issues() {
        return issues;
    }
}
