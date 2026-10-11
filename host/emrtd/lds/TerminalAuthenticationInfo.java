package card42.host.emrtd.lds;

import card42.host.common.util.Hex;

/**
 * Terminal Authentication SecurityInfo (BSI TR-03110-3 A.1.1.3):
 * {@code SEQUENCE { protocol id-TA, version INTEGER, efCVCA FileID OPTIONAL }}.
 * Version 2 is the profile used for LDS2 (ICAO Doc 9303-11 §7.1); the
 * {@code efCVCA} field is absent in version 2.
 */
public final class TerminalAuthenticationInfo extends SecurityInfo {

    public final int version;
    public final byte[] efCVCA;

    public TerminalAuthenticationInfo(String oid, int version, byte[] efCVCA) {
        super(oid);
        this.version = version;
        this.efCVCA = efCVCA;
    }

    @Override
    public String describe() {
        return "version " + version + (efCVCA == null ? "" : " efCVCA " + Hex.format(efCVCA));
    }
}
