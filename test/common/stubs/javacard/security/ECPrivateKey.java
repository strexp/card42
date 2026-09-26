package javacard.security;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code ECPrivateKey} interface
 * (docs/specs/common/toolchain.md §6).  It stores the private scalar so the
 * JCE-backed {@link KeyAgreement} stub can run ECDH.
 */
public class ECPrivateKey extends ECKey {

    private byte[] s = new byte[0];

    public ECPrivateKey(short size) {
        super(size);
    }

    public void setS(byte[] buffer, short offset, short length) {
        s = slice(buffer, offset, length);
    }

    public short getS(byte[] buffer, short offset) {
        System.arraycopy(s, 0, buffer, offset, s.length);
        return (short) s.length;
    }

    public byte[] scalarBytes() {
        return s;
    }

    @Override
    public boolean isInitialized() {
        return s.length > 0;
    }

    @Override
    public void clearKey() {
        super.clearKey();
        s = new byte[0];
    }

    @Override
    public byte getType() {
        return KeyBuilder.TYPE_EC_FP_PRIVATE;
    }
}
