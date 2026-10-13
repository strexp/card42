package card42.host.emrtd.lds;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import card42.host.common.codec.Der;
import card42.host.common.codec.Tags;

/**
 * Data group 15: the Active Authentication public key (ICAO Doc 9303-10 §4.7.15,
 * Doc 9303-11 §6.1.5).  DG15 = 6F { SubjectPublicKeyInfo }, an RFC 5280
 * SubjectPublicKeyInfo (H1.3).  The key is RSA (ISO/IEC 9796-2 Scheme 1 AA) or
 * an EC key (ECDSA AA, Doc 9303-11 §6.1.2.3).
 *
 * <p>The EC point is kept as the raw uncompressed P-256 point so verification
 * uses the self-contained {@code card42.host.common.crypto.Ecdsa} and needs no
 * external EC provider (the integration JVM does not always expose SunEC).
 */
public final class Dg15 {

    private static final String OID_RSA = "1.2.840.113549.1.1.1";

    public final PublicKey publicKey;
    /** True for an EC key (ECDSA Active Authentication). */
    public final boolean ecdsa;
    /** RSA modulus, or null for an ECDSA key. */
    public final BigInteger modulus;
    /** RSA public exponent, or null for an ECDSA key. */
    public final BigInteger exponent;
    /** EC uncompressed P-256 point {@code 04||X||Y}, or null for RSA. */
    public final byte[] ecPointW;

    private Dg15(PublicKey publicKey, boolean ecdsa, BigInteger modulus, BigInteger exponent,
                 byte[] ecPointW) {
        this.publicKey = publicKey;
        this.ecdsa = ecdsa;
        this.modulus = modulus;
        this.exponent = exponent;
        this.ecPointW = ecPointW;
    }

    public static Dg15 parse(byte[] dg15) {
        byte[] subjectPublicKeyInfo = Tags.find(dg15, 0x6F);
        if (subjectPublicKeyInfo == null) {
            throw new IllegalArgumentException("DG15 has no 6F SubjectPublicKeyInfo");
        }
        Der.Tlv sequence = Der.read(subjectPublicKeyInfo, 0);
        List<Der.Tlv> fields = Der.children(subjectPublicKeyInfo, sequence);
        String algorithm = Der.oid(subjectPublicKeyInfo,
                Der.children(subjectPublicKeyInfo, fields.get(0)).get(0));
        try {
            if (OID_RSA.equals(algorithm)) {
                RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo));
                return new Dg15(key, false, key.getModulus(), key.getPublicExponent(), null);
            }
            // id-ecPublicKey: the BIT STRING holds 0x00 || 04 || X(32) || Y(32).
            Der.Tlv bitString = fields.get(1);
            byte[] value = Der.value(subjectPublicKeyInfo, bitString);
            if (value.length != 66 || value[0] != 0x00 || value[1] != 0x04) {
                throw new IllegalArgumentException("DG15 EC point is not an uncompressed P-256 key");
            }
            byte[] point = new byte[65];
            System.arraycopy(value, 1, point, 0, 65);
            return new Dg15(null, true, null, null, point);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(
                    "DG15 is not a supported SubjectPublicKeyInfo", e);
        }
    }

    /** The AA RSA public key as a JDK key for signature verification (null for EC). */
    public PublicKey toPublicKey() {
        return publicKey;
    }
}
