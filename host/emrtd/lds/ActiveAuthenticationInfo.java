package card42.host.emrtd.lds;

/**
 * Active Authentication protocol information (ICAO Doc 9303-11 §9.2.4): version
 * and the mandatory signature-algorithm OID.
 */
public final class ActiveAuthenticationInfo extends SecurityInfo {

    public final int version;
    /** The signature algorithm OID (mandatory, Doc 9303-11 §9.2.4). */
    public final String signatureAlgorithm;

    ActiveAuthenticationInfo(String oid, int version, String signatureAlgorithm) {
        super(oid);
        this.version = version;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public String describe() {
        return "signature " + signatureAlgorithm;
    }
}
