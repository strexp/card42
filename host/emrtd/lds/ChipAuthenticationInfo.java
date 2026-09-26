package card42.host.emrtd.lds;

/**
 * Chip Authentication protocol information (BSI TR-03110-3, ICAO Doc 9303-11
 * §6): the protocol OID, version and optional key id.
 */
public final class ChipAuthenticationInfo extends SecurityInfo {

    public final int version;
    /** The key id, or null when implicit. */
    public final Integer keyId;

    ChipAuthenticationInfo(String oid, int version, Integer keyId) {
        super(oid);
        this.version = version;
        this.keyId = keyId;
    }

    /** The key agreement algorithm implied by the OID: "ECDH" or "DH". */
    public String keyAgreement() {
        return isEcdh() ? "ECDH" : "DH";
    }

    /** True for the ECDH Chip Authentication profiles. */
    public boolean isEcdh() {
        return oid.startsWith("0.4.0.127.0.7.2.2.3.2");
    }

    /** The symmetric key length in bits (128/192/256); 3DES profiles map to 128. */
    public int keyLength() {
        if (oid.endsWith(".4")) {
            return 256;
        }
        if (oid.endsWith(".3")) {
            return 192;
        }
        return 128;
    }

    /** The cipher algorithm implied by the OID: "AES" or "DESede". */
    public String cipherAlgorithm() {
        return oid.contains(".3.2.1") || oid.contains(".3.1.1") ? "DESede" : "AES";
    }

    @Override
    public String describe() {
        return keyAgreement() + "/" + cipherAlgorithm();
    }
}
