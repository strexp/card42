package javacard.security;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code ECKey} interface
 * (docs/specs/common/toolchain.md §6).  The curve parameters are stored but the
 * JCE-backed {@link KeyAgreement} stub always uses the named curve matching the
 * key size, so the pure-JVM Chip Authentication roundtrip exercises the same
 * ECDH construction as the card.
 */
public abstract class ECKey implements Key {

    private byte[] field = new byte[0];
    private byte[] a = new byte[0];
    private byte[] b = new byte[0];
    private byte[] g = new byte[0];
    private byte[] r = new byte[0];
    private short k;

    protected final short size;

    protected ECKey(short size) {
        this.size = size;
    }

    public void setFieldFP(byte[] buffer, short offset, short length) {
        field = slice(buffer, offset, length);
    }

    public void setA(byte[] buffer, short offset, short length) {
        a = slice(buffer, offset, length);
    }

    public void setB(byte[] buffer, short offset, short length) {
        b = slice(buffer, offset, length);
    }

    public void setG(byte[] buffer, short offset, short length) {
        g = slice(buffer, offset, length);
    }

    public void setR(byte[] buffer, short offset, short length) {
        r = slice(buffer, offset, length);
    }

    public void setK(short k) {
        this.k = k;
    }

    /** The named JCE curve for this key size (the stub ignores explicit params). */
    public String curveName() {
        switch (size) {
        case KeyBuilder.LENGTH_EC_FP_192:
            return "secp192r1";
        case KeyBuilder.LENGTH_EC_FP_224:
            return "secp224r1";
        case KeyBuilder.LENGTH_EC_FP_384:
            return "secp384r1";
        case KeyBuilder.LENGTH_EC_FP_521:
            return "secp521r1";
        default:
            return "secp256r1";
        }
    }

    @Override
    public void clearKey() {
        field = new byte[0];
        a = new byte[0];
        b = new byte[0];
        g = new byte[0];
        r = new byte[0];
        k = 0;
    }

    @Override
    public short getSize() {
        return size;
    }

    static byte[] slice(byte[] buffer, short offset, short length) {
        byte[] out = new byte[length];
        System.arraycopy(buffer, offset, out, 0, length);
        return out;
    }
}
