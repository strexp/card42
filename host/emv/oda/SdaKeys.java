package card42.host.emv.oda;

import java.math.BigInteger;

/**
 * RSA key material and modulus sizes for the offline SDA certificate-chain
 * generator {@link Sda} (EMV v4.4 Book 2 §5).
 *
 * <p>The generator holds no key material itself: the caller supplies a profile.
 * The modulus sizes are derived from the key lengths, and the ICC DDA/CDA and
 * PIN encipherment key pairs are generated at the issuer modulus size
 * (EMV v4.4 Book 2 Annex D1.1/D1.2).
 */
public final class SdaKeys {

    /** Certification Authority modulus. */
    public final BigInteger caModulus;
    /** Certification Authority private exponent. */
    public final BigInteger caPrivateExponent;
    /** Issuer public key modulus. */
    public final BigInteger issuerModulus;
    /** Issuer private exponent. */
    public final BigInteger issuerPrivateExponent;
    /** CA Public Key Index advertised in tag 8F. */
    public final byte[] caPublicKeyIndex;
    /** Issuer/ICC public key exponent, as returned in tag 9F32 (e.g. 01 00 01). */
    public final byte[] exponent;

    /** CA modulus length in bytes (NCA). */
    public final int caModulusBytes;
    /** Issuer modulus length in bytes (NI). */
    public final int issuerModulusBytes;
    /** ICC DDA/CDA modulus length in bytes (NIC). */
    public final int iccModulusBytes;
    /** ICC PIN encipherment modulus length in bytes (NPE). */
    public final int pinModulusBytes;

    public SdaKeys(BigInteger caModulus, BigInteger caPrivateExponent,
                   BigInteger issuerModulus, BigInteger issuerPrivateExponent,
                   byte[] caPublicKeyIndex, byte[] exponent) {
        this.caModulus = caModulus;
        this.caPrivateExponent = caPrivateExponent;
        this.issuerModulus = issuerModulus;
        this.issuerPrivateExponent = issuerPrivateExponent;
        this.caPublicKeyIndex = caPublicKeyIndex;
        this.exponent = exponent;
        this.caModulusBytes = modulusLength(caModulus);
        this.issuerModulusBytes = modulusLength(issuerModulus);
        this.iccModulusBytes = issuerModulusBytes;
        this.pinModulusBytes = issuerModulusBytes;
    }

    /** The "leftmost digits" field of an ICC certificate: NI - 42 (Book 2 tables 14/23). */
    public int pinLeftmost() {
        return issuerModulusBytes - 42;
    }

    private static int modulusLength(BigInteger modulus) {
        return (modulus.bitLength() + 7) / 8;
    }
}
