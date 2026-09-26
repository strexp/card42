package javacard.security;

/**
 * Minimal plain-JVM stand-in for the Java Card {@code AESKey} interface
 * (docs/specs/common/toolchain.md §6).  It stores the raw key bytes so the JCE-backed
 * {@code javacardx.crypto.Cipher} stub can feed them to a JCE cipher; the card
 * crypto classes only call {@link #setKey(byte[], short)}.
 */
public class AESKey implements Key {

    private final short size;
    private byte[] key;

    public AESKey(short size) {
        this.size = size;
    }

    public void setKey(byte[] keyData, short offset) {
        short length = (short) (size / 8);
        key = new byte[length];
        System.arraycopy(keyData, offset, key, 0, length);
    }

    public byte getKey(byte[] out, short offset) {
        if (key != null) {
            System.arraycopy(key, 0, out, offset, key.length);
        }
        return 0;
    }

    @Override
    public boolean isInitialized() {
        return key != null;
    }

    @Override
    public void clearKey() {
        key = null;
    }

    @Override
    public byte getType() {
        return KeyBuilder.TYPE_AES;
    }

    @Override
    public short getSize() {
        return size;
    }
}
