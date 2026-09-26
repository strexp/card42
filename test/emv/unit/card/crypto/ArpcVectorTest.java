package card42.test;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import card42.emv.Arpc;
import card42.emv.CryptoProfile;
import card42.emv.EMVCrypto;
import card42.emv.EMVProtocolState;
import card42.emv.EMVStaticData;

import card42.host.common.util.Hex;

/**
 * Independent external vectors for the card-side {@link Arpc} verification of
 * both ARPC methods and both cryptogram profiles (EMV v4.4 Book 2 §8.2.1/§8.2.2).
 *
 * <p>The card-side ARPC is otherwise only reached end to end through the
 * host-provided cryptogram, so a shared card/host mistake would pass.  Here the
 * expected values are recomputed with JCE only (ISO/IEC 9797-1 algorithm 3, the
 * A1.3.1 session-key derivation and an AES-CMAC), independently of the card
 * MAC/session-key classes.
 *
 * <ul>
 *   <li>Method 1, CV '5': {@code DES3_ECB(SK_AC)[ARQC xor (ARC || 00 x6)]}.</li>
 *   <li>Method 1, CV '6': leftmost 8 bytes of
 *       {@code AES_ECB(SK_AC)[Y || 00 x8]}, {@code Y} as above.</li>
 *   <li>Method 2, CV '5': leftmost 4 bytes of
 *       {@code Alg3(SK_AC)[ARQC || CSU || proprietary]}.</li>
 *   <li>Method 2, CV '6': leftmost 4 bytes of
 *       {@code CMAC(SK_AC)[ARQC || CSU || proprietary]}.</li>
 * </ul>
 */
final class ArpcVectorTest {

    private ArpcVectorTest() {
    }

    /** The card default ICC master key (card/emv/crypto/EMVCrypto.java). */
    private static final byte[] MK = Hex.parse("01020304050607080910111213141516");
    private static final byte[] ARQC = Hex.parse("0102030405060708");
    private static final byte[] ARC = Hex.parse("3030");
    private static final byte[] CSU = Hex.parse("00800000");

    static void run() throws Exception {
        System.out.println("ArpcVector");

        // --- CV '5' (Triple DES) --------------------------------------------
        EMVProtocolState state5 = new EMVProtocolState();
        EMVStaticData static5 = new EMVStaticData();
        EMVCrypto crypto5 = new EMVCrypto(state5, static5);
        state5.setATC((short) 0x0001);
        crypto5.computeFirstAC(new byte[16], (short) 0, new byte[8], (short) 0);
        state5.setArqc(ARQC, (short) 0);
        Arpc arpc5 = new Arpc(crypto5, state5);

        byte[] sk5 = sessionKey3des(MK, (short) 0x0001);
        byte[] y = ARQC.clone();
        y[0] ^= ARC[0];
        y[1] ^= ARC[1];

        byte[] method1 = des3Ecb(sk5, y);
        byte[] data1 = concat(method1, ARC);
        Asserts.check(arpc5.verifyMethod1(data1, (short) 0, (short) data1.length),
                "card ARPC method 1 (3DES) accepts the independent vector");
        Asserts.check(!arpc5.verifyMethod1(tamper(data1), (short) 0, (short) data1.length),
                "card ARPC method 1 (3DES) rejects a wrong ARPC");
        byte[] padded1 = concat(new byte[] { 0x00 }, data1);
        Asserts.check(arpc5.verifyMethod1(padded1, (short) 1, (short) padded1.length),
                "card ARPC method 1 (3DES) honours the offset");
        Asserts.check(!arpc5.verifyMethod1(padded1, (short) 0, (short) padded1.length),
                "card ARPC method 1 (3DES) rejects a shifted ARPC");

        byte[] expected2 = Arrays.copyOf(alg3(sk5, concat(ARQC, CSU)), 4);
        byte[] data2 = concat(expected2, CSU);
        Asserts.check(arpc5.verifyMethod2(data2, (short) 0, (short) data2.length),
                "card ARPC method 2 (3DES) accepts the independent vector");
        Asserts.check(!arpc5.verifyMethod2(tamper(data2), (short) 0, (short) data2.length),
                "card ARPC method 2 (3DES) rejects a wrong ARPC");

        // Proprietary byte 1 b8 clear: trailing bytes are not part of the MAC,
        // so an ARPC over ARQC || CSU still verifies with them appended.
        byte[] data2Extra = concat(expected2, CSU, Hex.parse("DEADBEEF"));
        Asserts.check(arpc5.verifyMethod2(data2Extra, (short) 0, (short) data2Extra.length),
                "card ARPC method 2 (3DES) ignores proprietary bytes when b8 = 0");

        // Proprietary byte 1 b8 set: the proprietary bytes take part in the MAC.
        byte[] csuProp = Hex.parse("80800000");
        byte[] proprietary = Hex.parse("A1B2C3D4");
        byte[] expected2Prop = Arrays.copyOf(
                alg3(sk5, concat(ARQC, csuProp, proprietary)), 4);
        byte[] data2Prop = concat(expected2Prop, csuProp, proprietary);
        Asserts.check(arpc5.verifyMethod2(data2Prop, (short) 0, (short) data2Prop.length),
                "card ARPC method 2 (3DES) covers proprietary data when b8 = 1");

        // --- CV '6' (AES) ---------------------------------------------------
        EMVProtocolState state6 = new EMVProtocolState();
        EMVStaticData static6 = new EMVStaticData();
        EMVCrypto crypto6 = new EMVCrypto(state6, static6);
        crypto6.selectAlgorithm(CryptoProfile.CV6);
        crypto6.setMasterKey(MK, (short) 0, (short) 16);
        state6.setATC((short) 0x0001);
        crypto6.computeFirstAC(new byte[16], (short) 0, new byte[8], (short) 0);
        state6.setArqc(ARQC, (short) 0);
        Arpc arpc6 = new Arpc(crypto6, state6);

        byte[] sk6 = sessionKeyAes(MK, (short) 0x0001);
        byte[] method1Aes = Arrays.copyOf(aesEcb(sk6, concat(y, new byte[8])), 8);
        byte[] data1Aes = concat(method1Aes, ARC);
        Asserts.check(arpc6.verifyMethod1(data1Aes, (short) 0, (short) data1Aes.length),
                "card ARPC method 1 (AES) accepts the independent vector");
        Asserts.check(!arpc6.verifyMethod1(tamper(data1Aes), (short) 0,
                        (short) data1Aes.length),
                "card ARPC method 1 (AES) rejects a wrong ARPC");

        byte[] expected2Aes = Arrays.copyOf(cmac(sk6, concat(ARQC, CSU)), 4);
        byte[] data2Aes = concat(expected2Aes, CSU);
        Asserts.check(arpc6.verifyMethod2(data2Aes, (short) 0, (short) data2Aes.length),
                "card ARPC method 2 (AES) accepts the independent vector");
        Asserts.check(!arpc6.verifyMethod2(tamper(data2Aes), (short) 0,
                        (short) data2Aes.length),
                "card ARPC method 2 (AES) rejects a wrong ARPC");

        byte[] expected2AesProp = Arrays.copyOf(
                cmac(sk6, concat(ARQC, csuProp, proprietary)), 4);
        byte[] data2AesProp = concat(expected2AesProp, csuProp, proprietary);
        Asserts.check(arpc6.verifyMethod2(data2AesProp, (short) 0, (short) data2AesProp.length),
                "card ARPC method 2 (AES) covers proprietary data when b8 = 1");
    }

    /** True when the ARPC at offset 1 (i.e. an unaligned field) is rejected. */
    private static byte[] tamper(byte[] data) {
        byte[] copy = data.clone();
        copy[0] ^= 0x01;
        return copy;
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int off = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, off, part.length);
            off += part.length;
        }
        return out;
    }

    // --- Independent computations (JCE only) --------------------------------

    /** EMV v4.4 Book 2 Annex A1.3.1 3DES session key, R = ATC || 00 x6. */
    private static byte[] sessionKey3des(byte[] mk, short atc) throws Exception {
        byte[] r = new byte[8];
        r[0] = (byte) (atc >> 8);
        r[1] = (byte) atc;
        byte[] f1 = r.clone();
        f1[2] = (byte) 0xF0;
        byte[] f2 = r.clone();
        f2[2] = (byte) 0x0F;
        return concat(des3Ecb(mk, f1), des3Ecb(mk, f2));
    }

    /** EMV v4.4 Book 2 Annex A1.3.1 AES-128 session key, R = ATC || 00 x14. */
    private static byte[] sessionKeyAes(byte[] mk, short atc) throws Exception {
        byte[] r = new byte[16];
        r[0] = (byte) (atc >> 8);
        r[1] = (byte) atc;
        return aesEcb(mk, r);
    }

    /** Single-block 3DES ECB (JCE), K1 || K2 || K1. */
    private static byte[] des3Ecb(byte[] key16, byte[] block8) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(Iso9797Expand.expand(key16), "DESede"));
        return cipher.doFinal(block8);
    }

    /** Single-block AES-128 ECB (JCE). */
    private static byte[] aesEcb(byte[] key16, byte[] block16) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key16, "AES"));
        return cipher.doFinal(block16);
    }

    /**
     * ISO/IEC 9797-1 algorithm 3 (padding method 2) with JCE: single-DES
     * CBC-MAC under K1, then DES_K2^-1 and DES_K1.
     */
    private static byte[] alg3(byte[] key16, byte[] msg) throws Exception {
        int pad = 8 - (msg.length % 8);
        byte[] padded = new byte[msg.length + pad];
        System.arraycopy(msg, 0, padded, 0, msg.length);
        padded[msg.length] = (byte) 0x80;
        byte[] k1 = Arrays.copyOfRange(key16, 0, 8);
        byte[] k2 = Arrays.copyOfRange(key16, 8, 16);
        Cipher des = Cipher.getInstance("DES/CBC/NoPadding");
        des.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k1, "DES"),
                new IvParameterSpec(new byte[8]));
        byte[] cbc = new byte[8];
        for (int i = 0; i < padded.length; i += 8) {
            for (int j = 0; j < 8; j++) {
                cbc[j] ^= padded[i + j];
            }
            cbc = des.doFinal(cbc);
        }
        Cipher dec = Cipher.getInstance("DES/ECB/NoPadding");
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k2, "DES"));
        byte[] h = dec.doFinal(cbc);
        Cipher enc = Cipher.getInstance("DES/ECB/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k1, "DES"));
        return enc.doFinal(h);
    }

    /** NIST SP 800-38B AES-CMAC with JCE AES-ECB (independent of the card). */
    private static byte[] cmac(byte[] key16, byte[] msg) throws Exception {
        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key16, "AES"));
        byte[] l = aes.doFinal(new byte[16]);
        byte[] k1 = shiftLeft(l);
        byte[] k2 = shiftLeft(k1);

        byte[] last = new byte[16];
        byte[] state = new byte[16];
        int full = msg.length / 16;
        boolean complete = msg.length != 0 && (msg.length % 16) == 0;
        int intermediates = complete ? full - 1 : full;
        for (int i = 0; i < intermediates; i++) {
            for (int j = 0; j < 16; j++) {
                last[j] = (byte) (msg[i * 16 + j] ^ state[j]);
            }
            state = aes.doFinal(last);
        }
        byte[] block = new byte[16];
        if (complete) {
            System.arraycopy(msg, (full - 1) * 16, block, 0, 16);
            for (int j = 0; j < 16; j++) {
                block[j] ^= k1[j];
            }
        } else {
            int rem = msg.length - full * 16;
            System.arraycopy(msg, full * 16, block, 0, rem);
            block[rem] = (byte) 0x80;
            for (int j = 0; j < 16; j++) {
                block[j] ^= k2[j];
            }
        }
        for (int j = 0; j < 16; j++) {
            block[j] ^= state[j];
        }
        return aes.doFinal(block);
    }

    /** CMAC subkey: left shift by one, xor 0x87 into the last byte on carry. */
    private static byte[] shiftLeft(byte[] in) {
        byte[] out = new byte[16];
        int carry = 0;
        for (int i = 15; i >= 0; i--) {
            int b = in[i] & 0xFF;
            out[i] = (byte) ((b << 1) | carry);
            carry = (b >> 7) & 1;
        }
        if ((in[0] & 0x80) != 0) {
            out[15] ^= (byte) 0x87;
        }
        return out;
    }

    /** Expands a 16-byte 2-key 3DES key to K1 || K2 || K1 for the JDK. */
    private static final class Iso9797Expand {
        private Iso9797Expand() {
        }

        static byte[] expand(byte[] key16) {
            byte[] key = new byte[24];
            System.arraycopy(key16, 0, key, 0, 16);
            System.arraycopy(key16, 0, key, 16, 8);
            return key;
        }
    }
}
