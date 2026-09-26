package card42.host.emrtd.lds;

import java.util.ArrayList;
import java.util.List;

import card42.host.common.codec.Der;

/**
 * A SecurityInfo object as carried by EF.CardAccess / EF.CardSecurity
 * (ICAO Doc 9303-11 §9.2, BSI TR-03110-3).  The base carries the protocol OID;
 * the concrete subclasses add the version / parameter id / key material of the
 * PACE, Chip Authentication and Active Authentication profiles (H7.2).
 */
public abstract class SecurityInfo {

    public static final String ID_AA = "2.23.136.1.1.5";
    public static final String ID_PK_DH = "0.4.0.127.0.7.2.2.1.1";
    public static final String ID_PK_ECDH = "0.4.0.127.0.7.2.2.1.2";
    public static final String ID_CA_DH_3DES = "0.4.0.127.0.7.2.2.3.1.1";
    public static final String ID_CA_ECDH_3DES = "0.4.0.127.0.7.2.2.3.2.1";
    public static final String ID_CA_DH_AES_128 = "0.4.0.127.0.7.2.2.3.1.2";
    public static final String ID_CA_DH_AES_192 = "0.4.0.127.0.7.2.2.3.1.3";
    public static final String ID_CA_DH_AES_256 = "0.4.0.127.0.7.2.2.3.1.4";
    public static final String ID_CA_ECDH_AES_128 = "0.4.0.127.0.7.2.2.3.2.2";
    public static final String ID_CA_ECDH_AES_192 = "0.4.0.127.0.7.2.2.3.2.3";
    public static final String ID_CA_ECDH_AES_256 = "0.4.0.127.0.7.2.2.3.2.4";
    public static final String ID_PACE_DH_GM = "0.4.0.127.0.7.2.2.4.1";
    public static final String ID_PACE_ECDH_GM = "0.4.0.127.0.7.2.2.4.2";
    public static final String ID_PACE_DH_IM = "0.4.0.127.0.7.2.2.4.3";
    public static final String ID_PACE_ECDH_IM = "0.4.0.127.0.7.2.2.4.4";
    public static final String ID_PACE_ECDH_CAM = "0.4.0.127.0.7.2.2.4.6";
    public static final String ID_PACE_DH_GM_3DES = "0.4.0.127.0.7.2.2.4.1.1";
    public static final String ID_PACE_ECDH_GM_3DES = "0.4.0.127.0.7.2.2.4.2.1";
    public static final String ID_PACE_ECDH_GM_AES_128 = "0.4.0.127.0.7.2.2.4.2.2";
    public static final String ID_PACE_ECDH_GM_AES_256 = "0.4.0.127.0.7.2.2.4.2.4";

    public final String oid;

    protected SecurityInfo(String oid) {
        this.oid = oid;
    }

    /**
     * A one-line description of this entry's type-specific fields for the
     * reports, or an empty string when it has none.  Replaces the report's
     * {@code instanceof} downcasts with a polymorphic call.
     */
    public String describe() {
        return "";
    }

    /** The concrete type name shown in the reports. */
    public String typeName() {
        return getClass().getSimpleName();
    }

    /** Parses a DER SET OF SecurityInfo (EF.CardAccess / CardSecurity eContent). */
    public static List<SecurityInfo> parseList(byte[] der) {
        List<SecurityInfo> out = new ArrayList<SecurityInfo>();
        if (der == null || der.length == 0) {
            return out;
        }
        Der.Tlv root = Der.read(der, 0);
        List<Der.Tlv> elements = root.tag == 0x31
                ? Der.children(der, root)
                : java.util.Collections.singletonList(root);
        for (Der.Tlv element : elements) {
            out.add(parse(der, element));
        }
        return out;
    }

    /** Parses one SecurityInfo SEQUENCE.  An unrecognised OID yields an {@link UnknownSecurityInfo}. */
    public static SecurityInfo parse(byte[] der, Der.Tlv sequence) {
        List<Der.Tlv> fields = Der.children(der, sequence);
        if (fields.isEmpty()) {
            return new UnknownSecurityInfo("");
        }
        String oid = Der.oid(der, fields.get(0));
        Der.Tlv required = fields.size() > 1 ? fields.get(1) : null;
        Der.Tlv optional = fields.size() > 2 ? fields.get(2) : null;
        if (ID_AA.equals(oid)) {
            // signatureAlgorithm is mandatory (ICAO Doc 9303-11 §9.2.4).
            if (optional == null) {
                throw new IllegalArgumentException(
                        "ActiveAuthenticationInfo requires signatureAlgorithm");
            }
            return new ActiveAuthenticationInfo(oid,
                    required == null ? 0 : Der.intValue(der, required),
                    Der.oid(der, optional));
        }
        if (ID_PK_DH.equals(oid) || ID_PK_ECDH.equals(oid)) {
            byte[] spki = required == null ? null : Der.encoded(der, required);
            Integer keyId = optional == null ? null : Der.intValue(der, optional);
            return new ChipAuthenticationPublicKeyInfo(oid, spki, keyId);
        }
        if (isChipAuthentication(oid)) {
            Integer keyId = optional == null ? null : Der.intValue(der, optional);
            return new ChipAuthenticationInfo(oid,
                    required == null ? 0 : Der.intValue(der, required), keyId);
        }
        if (isPace(oid)) {
            Integer parameterId = optional == null ? null : Der.intValue(der, optional);
            return new PaceInfo(oid, required == null ? 0 : Der.intValue(der, required),
                    parameterId);
        }
        return new UnknownSecurityInfo(oid);
    }

    /** True for a Chip Authentication protocol OID. */
    public static boolean isChipAuthentication(String oid) {
        return ID_CA_DH_3DES.equals(oid) || ID_CA_ECDH_3DES.equals(oid)
                || ID_CA_DH_AES_128.equals(oid) || ID_CA_DH_AES_192.equals(oid)
                || ID_CA_DH_AES_256.equals(oid) || ID_CA_ECDH_AES_128.equals(oid)
                || ID_CA_ECDH_AES_192.equals(oid) || ID_CA_ECDH_AES_256.equals(oid);
    }

    /** True for a PACE protocol OID. */
    public static boolean isPace(String oid) {
        return oid.startsWith("0.4.0.127.0.7.2.2.4.");
    }
}
