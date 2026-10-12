package card42.host.emrtd.ta;

import java.util.Arrays;

/**
 * A CV certificate Certificate Authority/Holder Reference (BSI TR-03110-3
 * A.7.1 Table 15): 2-byte ISO 3166-1 country code, up to 9 bytes holder
 * mnemonic and 5 bytes sequence number, ISO 8859-1.  It is carried as a
 * variable-length (up to 16 octets) character string and identifies the public
 * key of the issuing authority (CAR) or of the certificate holder (CHR); the
 * same bytes are sent in {@code MSE:Set DST} / {@code MSE:Set AT} (DO'83'),
 * matching JMRTD's unpadded {@code CVCPrincipal.getName()}.
 */
public final class CvcPrincipal {

    /** Fixed upper bound: country (2) + mnemonic (9) + sequence (5). */
    public static final int MAX_LENGTH = 16;

    private final byte[] value;

    private CvcPrincipal(byte[] value) {
        this.value = value;
    }

    public static CvcPrincipal parse(byte[] der, int off, int len) {
        if (len < 1 || len > MAX_LENGTH) {
            throw new IllegalArgumentException("CVC principal must be 1.." + MAX_LENGTH + " bytes");
        }
        byte[] value = Arrays.copyOfRange(der, off, off + len);
        for (byte b : value) {
            if ((b & 0xFF) < 0x20 || (b & 0xFF) > 0x7E) {
                throw new IllegalArgumentException("CVC principal contains a non-printable byte");
            }
        }
        return new CvcPrincipal(value);
    }

    public static CvcPrincipal of(String name) {
        byte[] raw = name.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        return parse(raw, 0, raw.length);
    }

    /** The raw value as sent in DO'83' and stored in the certificate. */
    public byte[] encode() {
        return Arrays.copyOf(value, value.length);
    }

    /** The ISO 8859-1 name. */
    public String name() {
        return new String(value, java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof CvcPrincipal && Arrays.equals(value, ((CvcPrincipal) other).value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return name();
    }
}
