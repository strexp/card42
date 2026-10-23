package card42.host.emrtd.access;


import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.DerWriter;
import card42.host.common.crypto.Kdf;
import card42.host.common.crypto.P256;
import card42.host.common.util.Sw;
import card42.host.emrtd.lds.security.ChipAuthenticationInfo;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Terminal-side Chip Authentication, ECDH 3DES or AES-128 profile
 * (ICAO Doc 9303-11 §6.2, BSI TR-03110-3 A.4/B.2, H7.3).
 *
 * <p>The terminal generates an ephemeral P-256 key pair on the chip's curve,
 * computes the shared secret {@code Z = ECDH(ephemeral_priv, chip_static_pub)}
 * and re-keys the secure-messaging session with {@code KDF(Z, 1/2)}, restarting
 * the send sequence counter at zero.
 *
 * <p>The 3DES profile uses {@code MSE:Set KAT} (DO'91'); the AES profile uses
 * {@code MSE:Set AT} (DO'80' = the CA OID) followed by {@code GENERAL
 * AUTHENTICATE} (DO'80' = the ephemeral key), with no protocol response data in
 * version 1 (BSI TR-03110-3 B.2/B.14.3).  The response to the authenticating
 * command is still protected with the old (BAC/PACE) keys, so the new SM is
 * installed only afterwards.
 *
 * <p>The P-256 arithmetic is the self-contained {@link P256}, so no external EC
 * provider is needed (the JDK's SunEC is not on the module graph of the
 * integration suites).
 */
public final class ChipAuth {

    private ChipAuth() {
    }

    /** The CA result: the re-keyed secure messaging and the terminal's ephemeral public key. */
    public static final class Result {
        public final SecureMessaging secureMessaging;
        /**
         * The terminal's ephemeral public key W (uncompressed {@code 0x04||X||Y}).
         * Terminal Authentication derives {@code Comp(PKDH,IFD)} (the
         * x-coordinate) from it (ICAO Doc 9303-11 §7.1.2/§7.1.4.2.3).
         */
        public final byte[] terminalPublicKeyW;

        Result(SecureMessaging secureMessaging, byte[] terminalPublicKeyW) {
            this.secureMessaging = secureMessaging;
            this.terminalPublicKeyW = terminalPublicKeyW;
        }
    }

    /** Runs Chip Authentication and installs the new SM session on the terminal. */
    public static SecureMessaging authenticate(EmrtdTerminal terminal, byte[] chipPublicKeyW,
                                               ChipAuthenticationInfo info) throws Exception {
        return authenticateResult(terminal, chipPublicKeyW, info).secureMessaging;
    }

    /** Runs Chip Authentication, returning the SM session and the terminal's ephemeral key. */
    public static Result authenticateResult(EmrtdTerminal terminal, byte[] chipPublicKeyW,
                                            ChipAuthenticationInfo info) throws Exception {
        if (!info.isEcdh()) {
            throw new IllegalArgumentException("only ECDH Chip Authentication is supported");
        }
        boolean aes = "AES".equals(info.cipherAlgorithm());
        if (!aes && !"DESede".equals(info.cipherAlgorithm())) {
            throw new IllegalArgumentException(
                    "only the 3DES and AES-128 Chip Authentication profiles are supported");
        }
        if (aes && !"0.4.0.127.0.7.2.2.3.2.2".equals(info.oid)) {
            throw new IllegalArgumentException(
                    "only AES-128 Chip Authentication is supported");
        }
        SecureRandom random = new SecureRandom();
        BigInteger ephemeral = P256.randomScalar(random);
        byte[] ephemeralW = P256.encode(P256.scalarMult(ephemeral, P256.generator()));

        if (aes) {
            // CA v1 with AES: MSE:Set AT (DO'80' = OID, DO'84' = key id) then
            // GENERAL AUTHENTICATE (DO'80' = the ephemeral key); the response
            // carries no protocol data in version 1 (BSI TR-03110-3 B.2).
            ByteArrayOutputStream mse = new ByteArrayOutputStream();
            writeTlv(mse, 0x80, oidContent(info.oid));
            if (info.keyId != null) {
                writeTlv(mse, 0x84, unsigned(BigInteger.valueOf(info.keyId)));
            }
            ResponseAPDU mseResponse = terminal.transmit(0x00, 0x22, 0x41, 0xA4,
                    mse.toByteArray(), 0);
            if (mseResponse.getSW() != 0x9000) {
                throw new IllegalStateException("MSE:Set AT (CA) failed: "
                        + Sw.format(mseResponse.getSW()));
            }
            ResponseAPDU ga = terminal.transmit(0x00, 0x86, 0x00, 0x00,
                    generalAuthenticate(0x80, ephemeralW), 0);
            if (ga.getSW() != 0x9000) {
                throw new IllegalStateException("CA GENERAL AUTHENTICATE failed: "
                        + Sw.format(ga.getSW()));
            }
        } else {
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            writeTlv(data, 0x91, ephemeralW);
            if (info.keyId != null) {
                writeTlv(data, 0x84, unsigned(BigInteger.valueOf(info.keyId)));
            }
            ResponseAPDU r = terminal.transmit(0x00, 0x22, 0x41, 0xA6, data.toByteArray(), 0);
            if (r.getSW() != 0x9000) {
                throw new IllegalStateException("MSE:SET KAT failed: "
                        + Sw.format(r.getSW()));
            }
        }

        P256.Point z = P256.scalarMult(ephemeral, P256.decode(chipPublicKeyW));
        byte[] ksEnc = deriveKey(P256.x(z), 1, aes);
        byte[] ksMac = deriveKey(P256.x(z), 2, aes);
        SecureMessaging sm = aes ? new Iso7816SmAes(ksEnc, ksMac, 0L)
                : new Iso7816Sm(ksEnc, ksMac, 0L);
        terminal.setSecureMessaging(sm);
        return new Result(sm, ephemeralW);
    }

    /** The DER content (no tag/length) of a dotted-decimal OID. */
    private static byte[] oidContent(String oid) {
        byte[] tlv = DerWriter.oid(oid);
        int length = tlv[1] & 0xFF;
        return Arrays.copyOfRange(tlv, 2, 2 + length);
    }

    /** 7C { 80 <ephemeral key> } for a GENERAL AUTHENTICATE command. */
    private static byte[] generalAuthenticate(int tag, byte[] value) {
        byte[] inner = new byte[value.length + 2];
        inner[0] = (byte) tag;
        inner[1] = (byte) value.length;
        System.arraycopy(value, 0, inner, 2, value.length);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x7C);
        out.write(inner.length);
        out.write(inner, 0, inner.length);
        return out.toByteArray();
    }

    /**
     * KDF(Z, counter) = SHA-1(Z || 00 00 00 counter), 16 bytes.  The 3DES
     * profile adjusts the DES parity; the AES profile does not
     * (BSI TR-03110-3 A.2.3.1/A.2.3.2).
     */
    public static byte[] deriveKey(byte[] z, int counter) throws Exception {
        return deriveKey(z, counter, false);
    }

    /** As {@link #deriveKey(byte[], int)} with an explicit AES/3DES profile. */
    public static byte[] deriveKey(byte[] z, int counter, boolean aes) {
        return Kdf.sha1Counter(z, counter, !aes);
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
