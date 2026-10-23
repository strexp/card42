package card42.host.emrtd.lds.lds2;

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;

import card42.host.common.codec.TlvWriter;

/**
 * Builds a signed Visa Record (ICAO Doc 9303-10 §5.2.3, Table 90).  The DO
 * order is fixed by the table; optional fields are omitted when unset.  The
 * signature covers {@code 71 || Len || value}.
 */
public final class VisaRecordBuilder extends Lds2RecordBuilder {

    private String issuingState;
    private String documentType;
    private String machineReadableVisaA;
    private String machineReadableVisaB;
    private byte[] numberOfEntries;
    private byte[] durationOfStay;
    private String passportNumber;
    private byte[] visaType;
    private byte[] territory;
    private String placeOfIssue;
    private String effectiveDate;
    private String expirationDate;
    private String documentNumber;
    private String additionalInfo;
    private String name;
    private String surname;
    private String givenNames;
    private String sex;
    private String dateOfBirth;
    private String nationality;
    private String mrz;
    private byte[] biometricsReference;
    private int certificateReference = 1;

    public VisaRecordBuilder issuingState(String value) {
        issuingState = value;
        return this;
    }

    public VisaRecordBuilder documentType(String value) {
        documentType = value;
        return this;
    }

    public VisaRecordBuilder machineReadableVisaA(String value) {
        machineReadableVisaA = value;
        return this;
    }

    public VisaRecordBuilder machineReadableVisaB(String value) {
        machineReadableVisaB = value;
        return this;
    }

    public VisaRecordBuilder numberOfEntries(byte[] value) {
        numberOfEntries = value;
        return this;
    }

    public VisaRecordBuilder durationOfStay(byte[] value) {
        durationOfStay = value;
        return this;
    }

    public VisaRecordBuilder passportNumber(String value) {
        passportNumber = value;
        return this;
    }

    public VisaRecordBuilder visaType(byte[] value) {
        visaType = value;
        return this;
    }

    public VisaRecordBuilder territory(byte[] value) {
        territory = value;
        return this;
    }

    public VisaRecordBuilder placeOfIssue(String value) {
        placeOfIssue = value;
        return this;
    }

    public VisaRecordBuilder effectiveDate(String value) {
        effectiveDate = value;
        return this;
    }

    public VisaRecordBuilder expirationDate(String value) {
        expirationDate = value;
        return this;
    }

    public VisaRecordBuilder documentNumber(String value) {
        documentNumber = value;
        return this;
    }

    public VisaRecordBuilder additionalInfo(String value) {
        additionalInfo = value;
        return this;
    }

    public VisaRecordBuilder name(String value) {
        name = value;
        return this;
    }

    public VisaRecordBuilder surname(String value) {
        surname = value;
        return this;
    }

    public VisaRecordBuilder givenNames(String value) {
        givenNames = value;
        return this;
    }

    public VisaRecordBuilder sex(String value) {
        sex = value;
        return this;
    }

    public VisaRecordBuilder dateOfBirth(String value) {
        dateOfBirth = value;
        return this;
    }

    public VisaRecordBuilder nationality(String value) {
        nationality = value;
        return this;
    }

    public VisaRecordBuilder mrz(String value) {
        mrz = value;
        return this;
    }

    public VisaRecordBuilder biometricsReference(byte[] value) {
        biometricsReference = value;
        return this;
    }

    public VisaRecordBuilder certificateReference(int value) {
        certificateReference = value;
        return this;
    }

    /** The signed record bytes for APPEND RECORD. */
    public byte[] build(PrivateKey lds2TsKey) throws Exception {
        require("issuingState", issuingState);
        require("documentType", documentType);
        require("placeOfIssue", placeOfIssue);
        require("effectiveDate", effectiveDate);
        require("expirationDate", expirationDate);
        require("documentNumber", documentNumber);
        require("name", name);
        require("surname", surname);
        require("givenNames", givenNames);
        require("sex", sex);
        require("dateOfBirth", dateOfBirth);
        require("nationality", nationality);
        require("mrz", mrz);

        ByteArrayOutputStream fields = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fields, 0x5F28, ascii(issuingState));
        TlvWriter.writeTlv(fields, 0x43, ascii(documentType));
        if (machineReadableVisaA != null) {
            TlvWriter.writeTlv(fields, 0x5F71, ascii(machineReadableVisaA));
        }
        if (machineReadableVisaB != null) {
            TlvWriter.writeTlv(fields, 0x5F72, ascii(machineReadableVisaB));
        }
        if (numberOfEntries != null) {
            TlvWriter.writeTlv(fields, 0x5F73, numberOfEntries);
        }
        if (durationOfStay != null) {
            TlvWriter.writeTlv(fields, 0x5F74, durationOfStay);
        }
        if (passportNumber != null) {
            TlvWriter.writeTlv(fields, 0x5F75, ascii(passportNumber));
        }
        if (visaType != null) {
            TlvWriter.writeTlv(fields, 0x5F76, visaType);
        }
        if (territory != null) {
            TlvWriter.writeTlv(fields, 0x5F77, territory);
        }
        TlvWriter.writeTlv(fields, 0x49, ascii(placeOfIssue));
        TlvWriter.writeTlv(fields, 0x5F25, ascii(effectiveDate));
        TlvWriter.writeTlv(fields, 0x5F24, ascii(expirationDate));
        TlvWriter.writeTlv(fields, 0x5A, ascii(documentNumber));
        if (additionalInfo != null) {
            TlvWriter.writeTlv(fields, 0x5F32, ascii(additionalInfo));
        }
        TlvWriter.writeTlv(fields, 0x5B, ascii(name));
        TlvWriter.writeTlv(fields, 0x5F33, ascii(surname));
        TlvWriter.writeTlv(fields, 0x5F34, ascii(givenNames));
        TlvWriter.writeTlv(fields, 0x5F35, ascii(sex));
        TlvWriter.writeTlv(fields, 0x5F2B, ascii(dateOfBirth));
        TlvWriter.writeTlv(fields, 0x5F2C, ascii(nationality));
        TlvWriter.writeTlv(fields, 0x5F1F, ascii(mrz));
        if (biometricsReference != null) {
            TlvWriter.writeTlv(fields, 0x5F40, biometricsReference);
        }

        byte[] signedInfo = tlv(0x71, fields.toByteArray());
        byte[] signature = sign(lds2TsKey, signedInfo);
        return concat(tlv(0x5F28, ascii(issuingState)), signedInfo,
                tlv(0x5F37, signature), certificateReferenceDo(certificateReference));
    }
}
