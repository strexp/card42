package card42.host.emrtd.lds;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * The chip's static Chip Authentication public key (BSI TR-03110-3, ICAO Doc
 * 9303-11 §6.1.4): protocol OID ({@code id-PK-ECDH} / {@code id-PK-DH}), the
 * RFC 5280 SubjectPublicKeyInfo and an optional key id.
 */
public final class ChipAuthenticationPublicKeyInfo extends SecurityInfo {

    /** The DER SubjectPublicKeyInfo, or null when malformed. */
    public final byte[] subjectPublicKeyInfo;
    /** The key id, or null when implicit. */
    public final Integer keyId;

    ChipAuthenticationPublicKeyInfo(String oid, byte[] subjectPublicKeyInfo, Integer keyId) {
        super(oid);
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        this.keyId = keyId;
    }

    /** True for the ECDH profile. */
    public boolean isEcdh() {
        return ID_PK_ECDH.equals(oid);
    }

    /** Rebuilds the JCE public key from the SubjectPublicKeyInfo. */
    public PublicKey toPublicKey() throws Exception {
        String algorithm = isEcdh() ? "EC" : "DH";
        return KeyFactory.getInstance(algorithm)
                .generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo));
    }

    /**
     * The raw uncompressed EC point {@code W = 0x04 || X || Y} from the
     * SubjectPublicKeyInfo, or null when malformed.  Lets the ECDH be done with
     * the self-contained P-256 arithmetic instead of a JCE EC provider.
     */
    public byte[] rawPoint() {
        if (subjectPublicKeyInfo == null) {
            return null;
        }
        card42.host.common.codec.Der.Tlv root =
                card42.host.common.codec.Der.read(subjectPublicKeyInfo, 0);
        java.util.List<card42.host.common.codec.Der.Tlv> fields =
                card42.host.common.codec.Der.children(subjectPublicKeyInfo, root);
        if (fields.size() < 2) {
            return null;
        }
        byte[] value = card42.host.common.codec.Der.value(subjectPublicKeyInfo, fields.get(1));
        if (value.length < 2 || value[0] != 0) {
            return null;
        }
        return java.util.Arrays.copyOfRange(value, 1, value.length);
    }

    @Override
    public String describe() {
        return "key id " + keyId;
    }
}
