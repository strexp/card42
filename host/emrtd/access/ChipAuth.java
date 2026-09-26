package card42.host.emrtd.access;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.crypto.P256;
import card42.host.emrtd.lds.ChipAuthenticationInfo;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Terminal-side Chip Authentication, ECDH 3DES profile (ICAO Doc 9303-11 §6.2,
 * BSI TR-03110-3 A.4/B.2, H7.3).
 *
 * <p>The terminal generates an ephemeral P-256 key pair on the chip's curve,
 * sends its public key with {@code MSE:SET KAT} (DO'91'), computes the shared
 * secret {@code Z = ECDH(ephemeral_priv, chip_static_pub)} and re-keys the
 * secure-messaging session with {@code KDF(Z, 1/2)}, restarting the send
 * sequence counter at zero.  The response to MSE is still protected with the
 * old (BAC/PACE) keys, so the new {@link Iso7816Sm} is installed only
 * afterwards.
 *
 * <p>The P-256 arithmetic is the self-contained {@link P256}, so no external EC
 * provider is needed (the JDK's SunEC is not on the module graph of the
 * integration suites).
 */
public final class ChipAuth {

    private ChipAuth() {
    }

    /** Runs Chip Authentication and installs the new SM session on the terminal. */
    public static Iso7816Sm authenticate(EmrtdTerminal terminal, byte[] chipPublicKeyW,
                                         ChipAuthenticationInfo info) throws Exception {
        if (!info.isEcdh()) {
            throw new IllegalArgumentException("only ECDH Chip Authentication is supported");
        }
        if (!"DESede".equals(info.cipherAlgorithm())) {
            throw new IllegalArgumentException(
                    "only the 3DES Chip Authentication profile is supported");
        }
        SecureRandom random = new SecureRandom();
        BigInteger ephemeral = P256.randomScalar(random);
        byte[] ephemeralW = P256.encode(P256.scalarMult(ephemeral, P256.generator()));

        ByteArrayOutputStream data = new ByteArrayOutputStream();
        writeTlv(data, 0x91, ephemeralW);
        if (info.keyId != null) {
            writeTlv(data, 0x84, unsigned(BigInteger.valueOf(info.keyId)));
        }

        ResponseAPDU r = terminal.transmit(0x00, 0x22, 0x41, 0xA6, data.toByteArray(), 0);
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException("MSE:SET KAT failed: "
                    + Integer.toHexString(r.getSW()));
        }

        P256.Point z = P256.scalarMult(ephemeral, P256.decode(chipPublicKeyW));
        byte[] ksEnc = deriveKey(P256.x(z), 1);
        byte[] ksMac = deriveKey(P256.x(z), 2);
        Iso7816Sm sm = new Iso7816Sm(ksEnc, ksMac, 0L);
        terminal.setSecureMessaging(sm);
        return sm;
    }

    /** KDF(Z, counter) = SHA-1(Z || 00 00 00 counter), 16 bytes with DES parity. */
    public static byte[] deriveKey(byte[] z, int counter) throws Exception {
        byte[] in = new byte[z.length + 4];
        System.arraycopy(z, 0, in, 0, z.length);
        in[z.length + 3] = (byte) counter;
        byte[] key = java.util.Arrays.copyOf(
                MessageDigest.getInstance("SHA-1").digest(in), 16);
        for (int i = 0; i < key.length; i++) {
            if ((Integer.bitCount(key[i] & 0xFF) & 1) == 0) {
                key[i] ^= 0x01;
            }
        }
        return key;
    }

    /** The uncompressed EC point W = 0x04 || X || Y. */
    public static byte[] encodeW(ECPublicKey key) {
        byte[] x = unsigned(key.getW().getAffineX());
        byte[] y = unsigned(key.getW().getAffineY());
        int size = (key.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        byte[] w = new byte[1 + 2 * size];
        w[0] = 0x04;
        System.arraycopy(x, 0, w, 1 + size - x.length, x.length);
        System.arraycopy(y, 0, w, 1 + 2 * size - y.length, y.length);
        return w;
    }

    private static void writeTlv(ByteArrayOutputStream out, int tag, byte[] value) {
        out.write(tag);
        if (value.length <= 0x7F) {
            out.write(value.length);
        } else if (value.length <= 0xFF) {
            out.write(0x81);
            out.write(value.length);
        } else {
            out.write(0x82);
            out.write(value.length >> 8);
            out.write(value.length);
        }
        out.write(value, 0, value.length);
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            return java.util.Arrays.copyOfRange(raw, 1, raw.length);
        }
        return raw;
    }
}
