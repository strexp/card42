package card42.host.emrtd.access;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.Tags;
import card42.host.common.crypto.AesCmac;
import card42.host.common.crypto.Iso9797;
import card42.host.common.crypto.P256;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Terminal-side PACE, ECDH generic mapping with 3DES or AES-128 secure
 * messaging and the MRZ or CAN password (BSI TR-03110-3 A.3/B.1, ICAO Doc
 * 9303-11 §4.4, H7.1).  The mirror of the card's {@code card42.emrtd.Pace}.
 *
 * <p>The generic mapping point {@code G' = [s]G + H} is computed with the
 * self-contained {@link P256} arithmetic.  After step 3 the derived K_enc/K_mac
 * replace the session keys and the SSC restarts at zero.
 */
public final class Pace {

    /** id-PACE-ECDH-GM-3DES-CBC-CBC OID content (0.4.0.127.0.7.2.2.4.2.1). */
    public static final byte[] OID_3DES = {
        0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x01 };
    /** id-PACE-ECDH-GM-AES-CBC-CMAC-128 OID content (0.4.0.127.0.7.2.2.4.2.2). */
    public static final byte[] OID_AES_128 = {
        0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02 };

    /** PACE password reference DO'83' values (BSI TR-03110-3 A.2.3). */
    public static final byte PASSWORD_MRZ = 0x01;
    public static final byte PASSWORD_CAN = 0x02;
    private static final byte PARAM_ID_P256 = 0x0C;

    /** The PACE session: Ks_enc, Ks_mac and the initial SSC (0). */
    public static final class Session {
        public final byte[] ksEnc;
        public final byte[] ksMac;
        public final long ssc;
        private final boolean aes;

        Session(byte[] ksEnc, byte[] ksMac, long ssc, boolean aes) {
            this.ksEnc = ksEnc;
            this.ksMac = ksMac;
            this.ssc = ssc;
            this.aes = aes;
        }

        public SecureMessaging secureMessaging() {
            return aes ? new Iso7816SmAes(ksEnc, ksMac, ssc)
                    : new Iso7816Sm(ksEnc, ksMac, ssc);
        }
    }

    private Pace() {
    }

    /** Derives the PACE key seed {@code SHA-1(MRZ_information)} (20 bytes). */
    public static byte[] keySeed(String documentNumber, String dateOfBirth,
                                 String dateOfExpiry) throws Exception {
        byte[] mrz = MrzKeySeed.mrzInformation(documentNumber, dateOfBirth, dateOfExpiry);
        return MessageDigest.getInstance("SHA-1").digest(mrz);
    }

    /**
     * The PACE password encoding {@code f(CAN)} (BSI TR-03110-3 A.2.3 Table 5):
     * the raw 6-digit Card Access Number octets, <em>not</em> a hash.  The KDF
     * is applied to these bytes with counter 3, so
     * {@code K_pi = SHA-1(CAN || 00 00 00 03)}, the same as every compliant
     * reader (JMRTD/OpenPACE).  This is password reference {@code 0x02}.
     */
    public static byte[] canKeySeed(String can) {
        return can.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    /** Runs PACE with the MRZ password and the 3DES profile. */
    public static Session authenticate(EmrtdTerminal terminal, String documentNumber,
                                       String dateOfBirth, String dateOfExpiry) throws Exception {
        return authenticate(terminal, PASSWORD_MRZ,
                keySeed(documentNumber, dateOfBirth, dateOfExpiry), OID_3DES);
    }

    /** Runs PACE with the CAN password and the 3DES profile (password ref 0x02). */
    public static Session authenticateCan(EmrtdTerminal terminal, String can) throws Exception {
        return authenticate(terminal, PASSWORD_CAN, canKeySeed(can), OID_3DES);
    }

    /** Runs PACE from an already derived 20-byte key seed and an explicit OID (MRZ). */
    public static Session authenticate(EmrtdTerminal terminal, byte[] keySeed, byte[] oid)
            throws Exception {
        return authenticate(terminal, PASSWORD_MRZ, keySeed, oid);
    }

    /**
     * Runs PACE from an already derived 20-byte key seed, the DO'83' password
     * reference ({@link #PASSWORD_MRZ} or {@link #PASSWORD_CAN}) and an explicit
     * protocol OID.
     */
    public static Session authenticate(EmrtdTerminal terminal, byte passwordReference,
                                       byte[] keySeed, byte[] oid) throws Exception {
        // Validate the protocol OID: only ECDH generic mapping is implemented,
        // with the 3DES or AES-128 secure-messaging profile (BSI TR-03110-3
        // A.3/B.1).  The OID content ends with <mapping>,<cipher>.
        if (oid.length < 10 || (oid[oid.length - 2] & 0xFF) != 0x02) {
            throw new IllegalArgumentException(
                    "only PACE ECDH generic mapping is supported");
        }
        int cipher = oid[oid.length - 1] & 0xFF;
        if (cipher != 0x01 && cipher != 0x02) {
            throw new IllegalArgumentException(
                    "unsupported PACE cipher profile (3DES or AES-128 only)");
        }
        boolean aes = cipher == 0x02;
        SecureRandom random = new SecureRandom();
        byte[] kpi = kdf(keySeed, 3, aes);

        // MSE:Set AT: DO'80'(OID) || DO'83'(password reference) || DO'84'(P-256 param id).
        byte[] mse = concat(new byte[] { (byte) 0x80, (byte) oid.length }, oid,
                new byte[] { (byte) 0x83, 0x01, passwordReference,
                        (byte) 0x84, 0x01, PARAM_ID_P256 });
        check(terminal.base().transmit(new CommandAPDU(0x00, 0x22, 0xC1, 0xA4, mse)),
                "PACE MSE:Set AT");

        // Step 1: encrypted nonce E(K_pi, s) (8 bytes 3DES / 16 bytes AES).
        byte[] step1 = clearGa(terminal, new byte[] { (byte) 0x7C, 0x00 });
        byte[] encryptedNonce = Tags.find(step1, 0x80);
        if (encryptedNonce == null) {
            throw new IllegalStateException("PACE step 1: no encrypted nonce");
        }
        byte[] nonce = aes
                ? aesCbc(kpi, false, encryptedNonce)
                : Iso9797.des3CbcDecrypt(kpi, new byte[8], encryptedNonce);

        // Step 2: mapping keys, G' = [s]G + H.
        BigInteger skPcd = P256.randomScalar(random);
        P256.Point pkPcd = P256.scalarMult(skPcd, P256.generator());
        byte[] step2 = clearGa(terminal, ga(0x81, P256.encode(pkPcd)));
        byte[] pkIccBytes = Tags.find(step2, 0x82);
        if (pkIccBytes == null) {
            throw new IllegalStateException("PACE step 2: no PICC mapping key");
        }
        P256.Point h = P256.scalarMult(skPcd, P256.decode(pkIccBytes));
        P256.Point mapped = P256.add(
                P256.scalarMult(new BigInteger(1, nonce), P256.generator()), h);

        // Step 3: ephemeral keys on G', shared secret Z.
        BigInteger skPcd2 = P256.randomScalar(random);
        P256.Point pkPcd2 = P256.scalarMult(skPcd2, mapped);
        byte[] step3 = clearGa(terminal, ga(0x83, P256.encode(pkPcd2)));
        byte[] pkIcc2Bytes = Tags.find(step3, 0x84);
        if (pkIcc2Bytes == null) {
            throw new IllegalStateException("PACE step 3: no PICC ephemeral key");
        }
        P256.Point z = P256.scalarMult(skPcd2, P256.decode(pkIcc2Bytes));
        byte[] ksEnc = kdf(P256.x(z), 1, aes);
        byte[] ksMac = kdf(P256.x(z), 2, aes);

        // Step 4: mutual authentication tokens (sent in the clear).
        byte[] tPcd = Arrays.copyOf(tokenMac(ksMac, tokenInput(oid, pkIcc2Bytes), aes), 8);
        ResponseAPDU step4 = terminal.base().transmit(
                new CommandAPDU(0x00, 0x86, 0x00, 0x00, ga(0x85, tPcd), 256));
        if (step4.getSW() != 0x9000) {
            throw new IllegalStateException("PACE step 4 failed: "
                    + Integer.toHexString(step4.getSW()));
        }
        byte[] tPicc = Tags.find(step4.getData(), 0x86);
        byte[] expected = Arrays.copyOf(tokenMac(ksMac, tokenInput(oid, P256.encode(pkPcd2)), aes), 8);
        if (tPicc == null || !Arrays.equals(expected, tPicc)) {
            throw new IllegalStateException("PACE PICC token mismatch");
        }
        return new Session(ksEnc, ksMac, 0L, aes);
    }

    private static byte[] clearGa(EmrtdTerminal terminal, byte[] data) throws Exception {
        ResponseAPDU r = terminal.base().transmit(
                new CommandAPDU(0x10, 0x86, 0x00, 0x00, data, 256));
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException("PACE GENERAL AUTHENTICATE failed: "
                    + Integer.toHexString(r.getSW()));
        }
        return r.getData();
    }

    private static void check(ResponseAPDU r, String what) {
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException(what + " failed: "
                    + Integer.toHexString(r.getSW()));
        }
    }

    /** KDF(x, counter) = SHA-1(x || 00 00 00 counter), 16-byte key. */
    public static byte[] kdf(byte[] x, int counter, boolean aes) throws Exception {
        byte[] in = new byte[x.length + 4];
        System.arraycopy(x, 0, in, 0, x.length);
        in[in.length - 1] = (byte) counter;
        byte[] key = Arrays.copyOf(
                MessageDigest.getInstance("SHA-1").digest(in), 16);
        if (!aes) {
            // DES parity adjustment applies to 3DES keys only (BSI A.2.3.1).
            for (int i = 0; i < key.length; i++) {
                if ((Integer.bitCount(key[i] & 0xFF) & 1) == 0) {
                    key[i] ^= 0x01;
                }
            }
        }
        return key;
    }

    static byte[] tokenMac(byte[] ksMac, byte[] input, boolean aes) throws Exception {
        if (aes) {
            return AesCmac.mac(ksMac, input);
        }
        return Iso9797.mac(ksMac, input);
    }

    private static byte[] aesCbc(byte[] key, boolean encrypt, byte[] data) throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding");
        c.init(encrypt ? javax.crypto.Cipher.ENCRYPT_MODE : javax.crypto.Cipher.DECRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key, "AES"),
                new javax.crypto.spec.IvParameterSpec(new byte[16]));
        return c.doFinal(data);
    }

    /** 7F49 { 06 <OID> 86 <point> } for the authentication token MAC. */
    static byte[] tokenInput(byte[] oid, byte[] point) {
        byte[] inner = concat(new byte[] { 0x06, (byte) oid.length }, oid,
                new byte[] { (byte) 0x86, (byte) point.length }, point);
        return concat(new byte[] { 0x7F, 0x49, (byte) inner.length }, inner);
    }

    private static byte[] ga(int tag, byte[] value) {
        return concat(new byte[] { (byte) 0x7C, (byte) (value.length + 2), (byte) tag,
                (byte) value.length }, value);
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
