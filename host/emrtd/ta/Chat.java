package card42.host.emrtd.ta;

import java.util.List;

import card42.host.common.codec.Der;
import card42.host.common.codec.DerWriter;

/**
 * Certificate Holder Authorization Template (BSI TR-03110-4 §2.1.3.2,
 * ICAO Doc 9303-10 §5.4.1): {@code 7F4C { 06 <templates OID>, 53 <discretionary> }}.
 * The OID identifies the template ({@code id-IS}, {@code 0.4.0.127.0.7.3.1.2.1}),
 * and the discretionary byte encodes the role in b8/b7 and the relative read
 * authorization in b2/b1.
 */
public final class Chat {

    /** {@code id-IS} template OID (BSI TR-03110-4 §2.1.3.2). */
    public static final String OID_ID_IS = "0.4.0.127.0.7.3.1.2.1";

    /** The role bits b8/b7 of the discretionary byte (TR-03110-4 Table 2). */
    public static final byte ROLE_CVCA = (byte) 0xC0;
    public static final byte ROLE_DV_DOMESTIC = (byte) 0x80;
    public static final byte ROLE_DV_FOREIGN = (byte) 0x40;
    public static final byte ROLE_IS = (byte) 0x00;

    /** The relative-authorization role, encoded in b8/b7 of the discretionary byte. */
    public enum Role {
        CVCA(ROLE_CVCA), DV_DOMESTIC(ROLE_DV_DOMESTIC), DV_FOREIGN(ROLE_DV_FOREIGN), IS(ROLE_IS);

        public final byte bits;

        Role(byte bits) {
            this.bits = bits;
        }
    }

    public final String oid;
    public final Role role;
    public final byte[] relativeAuthorization;

    private Chat(String oid, Role role, byte[] relativeAuthorization) {
        this.oid = oid;
        this.role = role;
        this.relativeAuthorization = relativeAuthorization;
    }

    /** Parses a {@code 7F4C} CHAT TLV. */
    public static Chat parse(byte[] der, Der.Tlv chat) {
        List<Der.Tlv> fields = Der.children(der, chat);
        String oid = null;
        byte[] authorization = null;
        for (Der.Tlv field : fields) {
            if (field.tag == 0x06) {
                oid = Der.oid(der, field);
            } else if (field.tag == 0x53) {
                authorization = Der.value(der, field);
            }
        }
        if (oid == null || authorization == null || authorization.length < 1) {
            throw new IllegalArgumentException("CHAT requires an OID and discretionary data");
        }
        return new Chat(oid, roleOf(authorization[0]), authorization);
    }

    /** Encodes a {@code 7F4C} CHAT with the {@code id-IS} template OID. */
    public static byte[] encode(Role role, byte[] relativeAuthorization) {
        return DerWriter.tlv(0x7F4C, DerWriter.concat(
                DerWriter.oid(OID_ID_IS), DerWriter.tlv(0x53, relativeAuthorization)));
    }

    /** The role encoded in bits b8/b7 of the discretionary byte. */
    public static Role roleOf(byte discretionary) {
        switch (discretionary & 0xC0) {
        case 0xC0:
            return Role.CVCA;
        case 0x80:
            return Role.DV_DOMESTIC;
        case 0x40:
            return Role.DV_FOREIGN;
        default:
            return Role.IS;
        }
    }

    /** The relative read authorization bit for DG3 (fingerprint) or DG4 (iris). */
    public boolean mayReadDg3() {
        return (relativeAuthorization[0] & 0x01) != 0;
    }

    public boolean mayReadDg4() {
        return (relativeAuthorization[0] & 0x02) != 0;
    }
}
