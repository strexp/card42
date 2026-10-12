package card42.host.emrtd.lds;

import card42.host.common.util.Hex;

/**
 * Terminal Authentication SecurityInfo (BSI TR-03110-3 A.1.1.3):
 * {@code SEQUENCE { protocol id-TA, version INTEGER, efCVCA FileID OPTIONAL }}.
 * ICAO Doc 9303-11 §9.2.8 requires version 1; the optional {@code efCVCA} names
 * the EF.CVCA file when the default (short) file identifier is not used.
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
