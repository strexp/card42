package card42.test;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import card42.host.emv.crypto.AcCrypto;
import card42.host.common.util.Hex;
import card42.host.emv.crypto.PersoMac;

/**
 * Spec vectors for the EMV v4.4 Book 2 CCD Cryptogram Version '5' application
 * cryptogram and session-key derivation (EMV v4.4 Book 2 §8.1.2).
 *
 * <p>The values are locked against an independent implementation of
 * ISO/IEC 9797-1 algorithm 3 (padding method 2) and of the EMV v4.4
 * section A1.3.1 common session-key derivation, so a regression in the card or
 * host crypto is caught here rather than only end to end.
 */
final class AcVectorTest {

    private AcVectorTest() {
    }

    /** ICC master key used by the vectors (matches sample.perso). */
    private static final byte[] MK =
            Hex.parse("0F0E0D0C0B0A09080706050403020100");

    static void run() throws Exception {
        System.out.println("AcVector");

        // --- ISO/IEC 9797-1 algorithm 3, padding method 2 --------------------
        // Classic ISO 9797-1 algorithm 3 test vector (28-byte message).
        Asserts.bytes(Hex.parse("863BE25DAF06098B"),
                PersoMac.mac(Hex.parse("0123456789ABCDEFFEDCBA9876543210"),
                        "7654321 Now is the time for ".getBytes()),
                "ISO 9797-1 algorithm 3 vector");

        // --- EMV v4.4 Book 2 A1.3.1 session key ------------------------------
        // R = ATC || 00 x6 (AC / ARPC session key).
        Asserts.bytes(Hex.parse("96FEE7669DB34AB5417A136CDA72550F"),
                AcCrypto.sessionKey(MK, 0x0001), "A1.3.1 session key (R = ATC)");
        // R = the first Application Cryptogram (secure-messaging keys): the
        // third byte of R is replaced by F0/0F in the two derivation blocks.
        byte[] ac = Hex.parse("AABBCCDDEEFF0011");
        Asserts.bytes(Hex.parse("5D7629457EB7E9BAD8B929AE23B4541E"),
                AcCrypto.sessionKey(MK, ac), "A1.3.1 session key (R = first AC)");

        // --- CCD CV '5' Application Cryptogram -------------------------------
        // AC = Alg3(SK_AC)[CDOL data || AIP || ATC || IAD]
        // (EMV v4.4 Book 2 Table CCD 3 / section 8.1.2).
        byte[] iad = Hex.parse("1122334455667788");
        byte[] expected = Hex.parse("E832EB637C70EA30");
        Asserts.bytes(expected,
                AcCrypto.expectedAc(MK, 0x5800, 0x0001, 43, iad),
                "CV '5' application cryptogram vector");

        // The vector must not be an algorithm 1 MAC: CV '5' mandates algorithm
        // 3 (EMV v4.4 Book 2 Annex A1.2), and a single 3DES CBC-MAC gives a
        // different value.
        byte[] acInput = new byte[43 + 2 + 2 + iad.length];
        acInput[43] = 0x58;
        acInput[45] = 0x00;
        acInput[46] = 0x01;
        System.arraycopy(iad, 0, acInput, 47, iad.length);
        Asserts.check(!Arrays.equals(expected,
                        alg1Mac(AcCrypto.sessionKey(MK, 0x0001), acInput)),
                "CV '5' AC is not an algorithm 1 MAC");

        // The same AC input hashed with an independent JCE retail MAC
        // (ISO/IEC 9797-1 algorithm 3) must give the vector, so a shared
        // card/host MAC bug cannot pass.
        Asserts.bytes(expected, retailMac(AcCrypto.sessionKey(MK, 0x0001), acInput),
                "CV '5' AC (independent JCE retail MAC)");
    }

    /**
     * ISO/IEC 9797-1 algorithm 3 (retail MAC) with padding method 2, computed
     * with JCE only: single-DES CBC-MAC under K1, then DES_K2^-1 and DES_K1.
     */
    private static byte[] retailMac(byte[] key16, byte[] msg) throws Exception {
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

    /** ISO/IEC 9797-1 algorithm 1 (3DES CBC-MAC) for the negative check. */
    private static byte[] alg1Mac(byte[] key16, byte[] msg) throws Exception {
        int pad = 8 - (msg.length % 8);
        byte[] padded = new byte[msg.length + pad];
        System.arraycopy(msg, 0, padded, 0, msg.length);
        padded[msg.length] = (byte) 0x80;
        byte[] key = new byte[24];
        System.arraycopy(key16, 0, key, 0, 16);
        System.arraycopy(key16, 0, key, 16, 8);
        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"),
                new IvParameterSpec(new byte[8]));
        byte[] out = cipher.doFinal(padded);
        return Arrays.copyOfRange(out, out.length - 8, out.length);
    }
}
