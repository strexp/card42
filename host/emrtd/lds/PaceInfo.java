package card42.host.emrtd.lds;

/**
 * PACE protocol information (BSI TR-03110-3, ICAO Doc 9303-11 §3.3): the
 * protocol OID, version and the standardized domain-parameter id (Table 6).
 */
public final class PaceInfo extends SecurityInfo {

    public final int version;
    /** The standardized domain-parameter id, or null when absent. */
    public final Integer parameterId;

    PaceInfo(String oid, int version, Integer parameterId) {
        super(oid);
        this.version = version;
        this.parameterId = parameterId;
    }

    /** True for the ECDH generic mapping profile (the modern default). */
    public boolean isEcdhGenericMapping() {
        return oid.startsWith(ID_PACE_ECDH_GM);
    }

    /** True for the DH generic mapping profile. */
    public boolean isDhGenericMapping() {
        return oid.startsWith(ID_PACE_DH_GM);
    }

    @Override
    public String describe() {
        return "PACE parameter id " + parameterId;
    }
}
