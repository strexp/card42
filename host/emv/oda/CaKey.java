package card42.host.emv.oda;

import java.math.BigInteger;

/**
 * An EMV Certification Authority public key (EMV v4.4 Book 2 §5.1).
 *
 * <p>The terminal selects the CA key with the CA Public Key Index ('8F')
 * carried in the SDA certificate chain.  The library itself holds no key
 * material: the caller supplies a {@link CaKeyStore}.
 */
public final class CaKey {

    /** RSA modulus. */
    public final BigInteger modulus;
    /** RSA public exponent. */
    public final BigInteger exponent;

    public CaKey(BigInteger modulus, BigInteger exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
    }

    /** Builds a key from the modulus and exponent as hex strings. */
    public static CaKey ofHex(String modulusHex, String exponentHex) {
        return new CaKey(new BigInteger(modulusHex, 16),
                new BigInteger(exponentHex, 16));
    }
}
