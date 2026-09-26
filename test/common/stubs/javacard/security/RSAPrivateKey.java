package javacard.security;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code RSAPrivateKey} interface
 * (docs/specs/common/toolchain.md §6).  It stores the modulus/exponent as big-endian
 * byte arrays so the JCE-backed {@code Signature} stub can rebuild a JCE key.
 */
public class RSAPrivateKey implements Key {

    private final short size;
    private byte[] modulus = new byte[0];
    private byte[] exponent = new byte[0];

    public RSAPrivateKey(short size) {
        this.size = size;
    }

    public void setModulus(byte[] buffer, short offset, short length) {
        modulus = slice(buffer, offset, length);
    }

    public void setExponent(byte[] buffer, short offset, short length) {
        exponent = slice(buffer, offset, length);
    }

    public short getModulus(byte[] buffer, short offset) {
        System.arraycopy(modulus, 0, buffer, offset, modulus.length);
        return (short) modulus.length;
    }

    public short getExponent(byte[] buffer, short offset) {
        System.arraycopy(exponent, 0, buffer, offset, exponent.length);
        return (short) exponent.length;
    }

    public byte[] modulusBytes() {
        return modulus;
    }

    public byte[] exponentBytes() {
        return exponent;
    }

    @Override
    public boolean isInitialized() {
        return modulus.length > 0 && exponent.length > 0;
    }

    @Override
    public void clearKey() {
        modulus = new byte[0];
        exponent = new byte[0];
    }

    @Override
    public byte getType() {
        return KeyBuilder.TYPE_RSA_PRIVATE;
    }

    @Override
    public short getSize() {
        return size;
    }

    private static byte[] slice(byte[] buffer, short offset, short length) {
        byte[] out = new byte[length];
        System.arraycopy(buffer, offset, out, 0, length);
        return out;
    }
}
