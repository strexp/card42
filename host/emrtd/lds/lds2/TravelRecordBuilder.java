package card42.host.emrtd.lds.lds2;

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;

import card42.host.common.codec.TlvWriter;

/**
 * Builds a signed Entry/Exit Travel Record (ICAO Doc 9303-10 §5.1.3/§5.1.4,
 * Table 86).  The DO order is fixed by the table; optional fields are omitted
 * when unset.  The signature covers {@code 73 || Len || value} (including the
 * tag and length) and the record ends with {@code 5F38} referencing an
 * EF.Certificates record.
 */
public final class TravelRecordBuilder extends Lds2RecordBuilder {

    private String state;
    private String travelDate;
    private String inspectionAuthority;
    private String inspectionLocation;
    private String inspectorReference;
    private String visaApprovals;
    private String inspectionResult;
    private String modeOfTravel;
    private byte[] durationOfStay;
    private String conditions;
    private int certificateReference = 1;

    public TravelRecordBuilder state(String value) {
        state = value;
        return this;
    }

    public TravelRecordBuilder travelDate(String value) {
        travelDate = value;
        return this;
    }

    public TravelRecordBuilder inspectionAuthority(String value) {
        inspectionAuthority = value;
        return this;
    }

    public TravelRecordBuilder inspectionLocation(String value) {
        inspectionLocation = value;
        return this;
    }

    public TravelRecordBuilder inspectorReference(String value) {
        inspectorReference = value;
        return this;
    }

    public TravelRecordBuilder visaApprovals(String value) {
        visaApprovals = value;
        return this;
    }

    public TravelRecordBuilder inspectionResult(String value) {
        inspectionResult = value;
        return this;
    }

    public TravelRecordBuilder modeOfTravel(String value) {
        modeOfTravel = value;
        return this;
    }

    public TravelRecordBuilder durationOfStay(byte[] value) {
        durationOfStay = value;
        return this;
    }

    public TravelRecordBuilder conditions(String value) {
        conditions = value;
        return this;
    }

    public TravelRecordBuilder certificateReference(int value) {
        certificateReference = value;
        return this;
    }

    /** The signed record bytes for APPEND RECORD. */
    public byte[] build(PrivateKey lds2TsKey) throws Exception {
        require("state", state);
        require("travelDate", travelDate);
        require("inspectionAuthority", inspectionAuthority);
        require("inspectionLocation", inspectionLocation);
        require("inspectorReference", inspectorReference);

        ByteArrayOutputStream fields = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fields, 0x5F44, ascii(state));
        if (visaApprovals != null) {
            TlvWriter.writeTlv(fields, 0x5F4C, ascii(visaApprovals));
        }
        TlvWriter.writeTlv(fields, 0x5F45, ascii(travelDate));
        TlvWriter.writeTlv(fields, 0x5F4B, ascii(inspectionAuthority));
        TlvWriter.writeTlv(fields, 0x5F46, ascii(inspectionLocation));
        TlvWriter.writeTlv(fields, 0x5F4A, ascii(inspectorReference));
        if (inspectionResult != null) {
            TlvWriter.writeTlv(fields, 0x5F4D, ascii(inspectionResult));
        }
        if (modeOfTravel != null) {
            TlvWriter.writeTlv(fields, 0x5F49, ascii(modeOfTravel));
        }
        if (durationOfStay != null) {
            TlvWriter.writeTlv(fields, 0x5F48, durationOfStay);
        }
        if (conditions != null) {
            TlvWriter.writeTlv(fields, 0x5F4E, ascii(conditions));
        }

        byte[] signedInfo = tlv(0x73, fields.toByteArray());
        byte[] signature = sign(lds2TsKey, signedInfo);
        return concat(tlv(0x5F44, ascii(state)), signedInfo,
                tlv(0x5F37, signature), certificateReferenceDo(certificateReference));
    }
}
