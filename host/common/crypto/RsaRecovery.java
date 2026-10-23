package card42.host.common.crypto;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * RSA public-key recovery and the shared byte/record helpers used by both the
 * offline data authentication verifiers ({@code card42.host.emv.oda}) and the
 * offline SDA generator ({@code card42.host.emv.app.perso}) (EMV v4.4 Book 2
 * Annex A2.1).
 *
 * <p>It is a generic crypto primitive, so it lives in {@code common}; both the
 * verification ({@code emv.oda}) and personalization ({@code emv.app.perso})
 * modules can depend on it without creating an {@code oda -> app} edge.
 */
public final class RsaRecovery {

    private RsaRecovery() {
    }

    /**
     * Raw RSA public-key recovery: returns {@code signature^exponent mod modulus}
     * as a fixed modulus-length byte string (EMV v4.4 Book 2 Annex A2.1).
     */
    public static byte[] recover(byte[] signature, BigInteger modulus, BigInteger exponent) {
        return toFixed(new BigInteger(1, signature).modPow(exponent, modulus),
                modulusLength(modulus));
    }

    /**
     * The value of a complete {@code 70} record template, without the wrapper
     * (EMV v4.4 Book 3 Annex B; the Application Elementary File data record is
     * a {@code 70} template).
     */
    public static byte[] templateValue(byte[] record) {
        if (record.length < 2 || (record[0] & 0xFF) != 0x70) {
            throw new IllegalArgumentException("Not a 70 record template");
        }
        int first = record[1] & 0xFF;
        int lengthField = (first & 0x80) == 0 ? 1 : 1 + (first & 0x7F);
        return Arrays.copyOfRange(record, 1 + lengthField, record.length);
    }

    /** Big-endian byte string of exactly {@code length} bytes, left-padded with zero. */
    public static byte[] toFixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        int start = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
        int size = raw.length - start;
        if (size > length) {
            throw new IllegalArgumentException("Value does not fit in " + length + " bytes");
        }
        byte[] out = new byte[length];
        System.arraycopy(raw, start, out, length - size, size);
        return out;
    }

    /** The modulus length in bytes. */
    public static int modulusLength(BigInteger modulus) {
        return (modulus.bitLength() + 7) / 8;
    }
}
