package card42.host.emrtd.lds;

/**
 * A SecurityInfo whose protocol OID the reader does not recognise.  It is
 * preserved in the parsed list rather than dropped, so the base contract ("all
 * entries of the DER SET OF SecurityInfo") holds and a report can list every
 * advertised entry (ICAO Doc 9303-11 §3).
 */
public final class UnknownSecurityInfo extends SecurityInfo {

    UnknownSecurityInfo(String oid) {
        super(oid);
    }

    @Override
    public String describe() {
        return "unrecognised protocol";
    }
}
