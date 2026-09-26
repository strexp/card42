package javacard.security;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code ECPublicKey} interface
 * (docs/specs/common/toolchain.md §6).  It stores the encoded public point W so
 * the JCE-backed {@link KeyAgreement} stub can run ECDH.
 */
public class ECPublicKey extends ECKey {

    private byte[] w = new byte[0];

    public ECPublicKey(short size) {
        super(size);
    }

    public void setW(byte[] buffer, short offset, short length) {
        w = slice(buffer, offset, length);
    }

    public short getW(byte[] buffer, short offset) {
        System.arraycopy(w, 0, buffer, offset, w.length);
        return (short) w.length;
    }

    public byte[] wBytes() {
        return w;
    }

    @Override
    public boolean isInitialized() {
        return w.length > 0;
    }

    @Override
    public void clearKey() {
        super.clearKey();
        w = new byte[0];
    }

    @Override
    public byte getType() {
        return KeyBuilder.TYPE_EC_FP_PUBLIC;
    }
}
