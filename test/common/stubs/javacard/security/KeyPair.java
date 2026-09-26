package javacard.security;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code KeyPair}
 * (docs/specs/common/toolchain.md §6).  {@link #genKeyPair()} does not generate real
 * key material: the card-side eMRTD tests set the AA key explicitly, so the
 * stub only has to hand out the two key objects.
 */
public class KeyPair {

    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

    public KeyPair(byte algorithm, short keyLength) {
        if (algorithm != KeyBuilder.ALG_TYPE_RSA) {
            throw new CryptoException((short) 1);
        }
        publicKey = new RSAPublicKey(keyLength);
        privateKey = new RSAPrivateKey(keyLength);
    }

    public RSAPublicKey getPublic() {
        return publicKey;
    }

    public RSAPrivateKey getPrivate() {
        return privateKey;
    }

    public void genKeyPair() {
        throw new CryptoException((short) 1);
    }
}
