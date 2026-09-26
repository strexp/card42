package javacard.security;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code KeyBuilder}
 * (docs/specs/common/toolchain.md §6).  Only the key types and lengths used by the
 * card-side crypto classes under test are provided; the constant values need
 * not match the real API because every user links against this stub.
 */
public class KeyBuilder {

    public static final byte TYPE_DES = (byte) 1;
    public static final byte TYPE_AES = (byte) 2;
    public static final byte TYPE_RSA_PUBLIC = (byte) 3;
    public static final byte TYPE_RSA_PRIVATE = (byte) 4;
    public static final byte TYPE_EC_FP_PUBLIC = (byte) 5;
    public static final byte TYPE_EC_FP_PRIVATE = (byte) 6;

    public static final short LENGTH_DES = (short) 64;
    public static final short LENGTH_DES3_2KEY = (short) 128;
    public static final short LENGTH_DES3_3KEY = (short) 192;
    public static final short LENGTH_AES_128 = (short) 128;
    public static final short LENGTH_AES_192 = (short) 192;
    public static final short LENGTH_AES_256 = (short) 256;
    public static final short LENGTH_RSA_1024 = (short) 1024;
    public static final short LENGTH_RSA_2048 = (short) 2048;
    public static final short LENGTH_EC_FP_192 = (short) 192;
    public static final short LENGTH_EC_FP_224 = (short) 224;
    public static final short LENGTH_EC_FP_256 = (short) 256;
    public static final short LENGTH_EC_FP_384 = (short) 384;
    public static final short LENGTH_EC_FP_521 = (short) 521;

    /** The RSA algorithm selector accepted by {@link KeyPair}. */
    public static final byte ALG_TYPE_RSA = (byte) 1;

    private KeyBuilder() {
    }

    public static Key buildKey(byte keyType, short keyLength, boolean keyEncryption) {
        if (keyType == TYPE_DES) {
            return new DESKey(keyLength);
        }
        if (keyType == TYPE_AES) {
            return new AESKey(keyLength);
        }
        if (keyType == TYPE_RSA_PUBLIC) {
            return new RSAPublicKey(keyLength);
        }
        if (keyType == TYPE_RSA_PRIVATE) {
            return new RSAPrivateKey(keyLength);
        }
        if (keyType == TYPE_EC_FP_PUBLIC) {
            return new ECPublicKey(keyLength);
        }
        if (keyType == TYPE_EC_FP_PRIVATE) {
            return new ECPrivateKey(keyLength);
        }
        throw new CryptoException((short) 1);
    }

    public static KeyPair buildKeyPair(byte algorithm, short keyLength) {
        return new KeyPair(algorithm, keyLength);
    }
}
