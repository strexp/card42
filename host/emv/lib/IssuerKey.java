package card42.host.emv.lib;

import java.math.BigInteger;

/**
 * An RSA public key recovered from the SDA/DDA/CDA certificate chain
 * (EMV v4.4 Book 2 §5/§6).  A neutral value type in {@code emv.lib} so the
 * kernel core and the CVM code do not depend on the ODA implementation package.
 */
public final class IssuerKey {

    public final BigInteger modulus;
    public final BigInteger exponent;
    /** Static data to be authenticated (EMV v4.4 Book 3 §10.3); ICC cert hash input. */
    public final byte[] staticData;
    /** Modulus length in bytes, as recovered from the certificate. */
    public final int modulusBytes;
    /** The card PAN (tag '5A') the issuer certificate was issued for, or null. */
    public final byte[] pan;

    public IssuerKey(BigInteger modulus, BigInteger exponent, byte[] staticData,
                     int modulusBytes) {
        this(modulus, exponent, staticData, modulusBytes, null);
    }

    public IssuerKey(BigInteger modulus, BigInteger exponent, byte[] staticData,
                     int modulusBytes, byte[] pan) {
        this.modulus = modulus;
        this.exponent = exponent;
        this.staticData = staticData;
        this.modulusBytes = modulusBytes;
        this.pan = pan;
    }
}
