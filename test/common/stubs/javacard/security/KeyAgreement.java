package javacard.security;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code KeyAgreement}
 * (docs/specs/common/toolchain.md §6).  It implements the ECDH
 * ({@code ALG_EC_SVDP_DH_PLAIN}) operation used by Chip Authentication with a
 * JCE provider, so the card-side and host-side implementations can be checked
 * against each other in a pure-JVM roundtrip.
 */
public class KeyAgreement {

    public static final byte ALG_EC_SVDP_DH = (byte) 1;
    public static final byte ALG_EC_SVDP_DH_PLAIN = (byte) 3;

    private final byte algorithm;
    private Key key;

    private KeyAgreement(byte algorithm) {
        this.algorithm = algorithm;
    }

    public static KeyAgreement getInstance(byte algorithm, boolean externalAccess) {
        if (algorithm != ALG_EC_SVDP_DH && algorithm != ALG_EC_SVDP_DH_PLAIN) {
            throw new CryptoException((short) 1);
        }
        return new KeyAgreement(algorithm);
    }

    public static KeyAgreement getInstance(byte algorithm) {
        return getInstance(algorithm, false);
    }

    public void init(Key theKey) {
        this.key = theKey;
    }

    public short generateSecret(byte[] publicData, short publicOffset, short publicLength,
                                byte[] secret, short secretOffset) {
        if (!(key instanceof ECPrivateKey)) {
            throw new CryptoException((short) 1);
        }
        try {
            ECPrivateKey privateKey = (ECPrivateKey) key;
            ECParameterSpec params = paramsFor(privateKey.curveName());
            java.security.PrivateKey jcePrivate = KeyFactory.getInstance("EC")
                    .generatePrivate(new ECPrivateKeySpec(
                            new BigInteger(1, privateKey.scalarBytes()), params));

            int coord = (privateKey.getSize() + 7) / 8;
            int off = publicOffset;
            int len = publicLength;
            if (len == 1 + 2 * coord && (publicData[off] & 0xFF) == 0x04) {
                off++;
                len--;
            }
            byte[] x = new byte[coord];
            byte[] y = new byte[coord];
            System.arraycopy(publicData, off, x, 0, coord);
            System.arraycopy(publicData, off + coord, y, 0, coord);
            java.security.PublicKey jcePublic = KeyFactory.getInstance("EC")
                    .generatePublic(new ECPublicKeySpec(
                            new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), params));

            javax.crypto.KeyAgreement agreement = javax.crypto.KeyAgreement.getInstance("ECDH");
            agreement.init(jcePrivate);
            agreement.doPhase(jcePublic, true);
            byte[] shared = agreement.generateSecret();
            System.arraycopy(shared, 0, secret, secretOffset, shared.length);
            return (short) shared.length;
        } catch (Exception e) {
            throw new CryptoException((short) 1);
        }
    }

    private static ECParameterSpec paramsFor(String name) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(name));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }
}
