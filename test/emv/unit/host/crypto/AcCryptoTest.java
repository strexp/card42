package card42.test;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import card42.host.emv.crypto.AcCrypto;
import card42.host.common.crypto.AesCmac;
import card42.host.common.util.Bytes;
import card42.host.common.util.Hex;
import card42.host.emv.crypto.PersoMac;

/**
 * Pure-JVM tests for the host-side AC/PIN crypto helpers.
 *
 * <p>These exercise the host helper/oracle implementations; the spec vectors
 * live in {@link AcVectorTest} / {@link AesVectorTest}.  This suite is
 * tool/host coverage rather than a direct clause mapping.
 */
final class AcCryptoTest {

    private AcCryptoTest() {
    }

    /** Single-block AES-128 ECB encryption (JCE), for the independent AES ARPC vector. */
    private static byte[] aesEcb(byte[] key16, byte[] block16) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key16, "AES"));
        return cipher.doFinal(block16);
    }

    static void run() throws Exception {
        System.out.println("AcCrypto");

        // --- ISO 9564-1 format 2 PIN block ----------------------------------
        Asserts.bytes(new byte[] { 0x24, 0x12, 0x34,
                        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
                AcCrypto.iso9564Format2("1234"), "iso9564 format 2 block");
        // Odd digit count: the low nibble is padded with 0xF.
        Asserts.bytes(new byte[] { 0x25, 0x12, 0x34, 0x5F,
                        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
                AcCrypto.iso9564Format2("12345"), "iso9564 format 2 5-digit block");
        // 12 digits: the control byte 0x2C encodes the length, the six BCD
        // bytes follow, and the block is completed with one 0xFF fill byte.
        Asserts.bytes(new byte[] { 0x2C, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, 0x12,
                        (byte) 0xFF },
                AcCrypto.iso9564Format2("123456789012"), "iso9564 format 2 12-digit block");

        // --- session key derivation -----------------------------------------
        byte[] mk = Hex.parse("0F0E0D0C0B0A09080706050403020100");
        byte[] k1 = AcCrypto.sessionKey(mk, 0x0001);
        byte[] k1b = AcCrypto.sessionKey(mk, 0x0001);
        byte[] k2 = AcCrypto.sessionKey(mk, 0x0002);
        Asserts.eq(16, k1.length, "session key length");
        Asserts.bytes(k1, k1b, "session key deterministic");
        Asserts.check(!Arrays.equals(k1, k2), "session key varies with ATC");
        // Known vector: locks the derivation used by the card-side EMVCrypto.
        Asserts.bytes(Hex.parse("96FEE7669DB34AB5417A136CDA72550F"), k1,
                "session key known vector");

        // --- AC recomputation -----------------------------------------------
        byte[] iad = new byte[18];
        byte[] ac = AcCrypto.expectedAc(mk, 0x5800, 0x0001, 43, iad);
        Asserts.eq(8, ac.length, "expected AC length");
        byte[] acInput = new byte[43 + 2 + 2 + iad.length];
        acInput[43] = 0x58;
        acInput[44] = 0x00;
        acInput[45] = 0x00;
        acInput[46] = 0x01;
        System.arraycopy(iad, 0, acInput, 47, iad.length);
        Asserts.bytes(PersoMac.mac(k1, acInput), ac,
                "expected AC matches a manual MAC over AIP/ATC/IAD");

        // --- DOL helpers (DDA/CDA) ------------------------------------------
        byte[] cdol1 = Hex.parse(
                "9F02 06 9F03 06 9F1A 02 95 05 5F2A 02 9A 03 9C 01 "
                + "9F37 04");
        Asserts.eq(29, AcCrypto.dolDataLength(cdol1), "dolDataLength CDOL1");
        Asserts.eq(25, AcCrypto.dolValueOffset(cdol1, 0x9F37),
                "dolValueOffset finds 9F37");
        Asserts.eq(-1, AcCrypto.dolValueOffset(cdol1, 0x1234),
                "dolValueOffset missing tag");

        // --- ISO/IEC 9797-1 algorithm 3 and ARPC (EMV v4.4 Book 2 §8.2, §9.2/§9.3) ------------
        // Classic ISO 9797-1 algorithm 3 test vector (28-byte message).
        Asserts.bytes(Hex.parse("863BE25DAF06098B"),
                AcCrypto.macAlg3(Hex.parse("0123456789ABCDEFFEDCBA9876543210"),
                        "7654321 Now is the time for ".getBytes(), 8),
                "ISO 9797-1 algorithm 3 vector");
        // ARPC Method 1: DES3_ECB(SK)[ARQC xor (ARC || 00 x6)].
        Asserts.bytes(Hex.parse("DB231531869AFBDE"),
                AcCrypto.computeArpcMethod1(
                        Hex.parse("11111111111111111111111111111111"),
                        Hex.parse("AABBCCDDEEFF0011"), Hex.parse("3030")),
                "ARPC method 1 vector");
        // ARPC Method 2: leftmost 4 bytes of Alg3(SK)[ARQC || CSU].
        byte[] arpcKey = Hex.parse("0F0E0D0C0B0A09080706050403020100");
        byte[] arqc = Hex.parse("0102030405060708");
        byte[] csu = Hex.parse("00800000");
        Asserts.bytes(Hex.parse("CDE2B93D"),
                AcCrypto.computeArpcMethod2(arpcKey, arqc, csu, new byte[0]),
                "ARPC method 2 vector");
        // With non-empty proprietary data the message is ARQC || CSU ||
        // proprietary (EMV v4.4 Book 2 §8.2.2).
        byte[] proprietary = Hex.parse("A1B2C3D4");
        Asserts.bytes(Arrays.copyOf(AcCrypto.macAlg3(arpcKey,
                        Bytes.concat(arqc, csu, proprietary), 8), 4),
                AcCrypto.computeArpcMethod2(arpcKey, arqc, csu, proprietary),
                "ARPC method 2 with proprietary data");

        // --- CV '6' (AES) ARPC (EMV v4.4 Book 2 §8.2.1/§8.2.2) --------------
        // ARPC Method 1 with AES: the leftmost 8 bytes of
        // AES_ECB(SK_AC)[ (ARQC xor (ARC || 00 x6)) || 00 x8 ] (EMV v4.4 Book 2 §8.2.1).
        // Computed here with JCE, independently of the card/host code.
        byte[] aesSk = AcCrypto.sessionKeyAes(arpcKey, 0x0001);
        byte[] aesArqc = Hex.parse("AABBCCDDEEFF0011");
        byte[] aesArc = Hex.parse("3030");
        byte[] yAes = aesArqc.clone();
        yAes[0] ^= aesArc[0];
        yAes[1] ^= aesArc[1];
        Asserts.bytes(Hex.parse("0098123763F758D5"),
                Arrays.copyOf(aesEcb(aesSk, Bytes.concat(yAes, new byte[8])), 8),
                "ARPC method 1 AES vector");

        // ARPC Method 2 with AES-CMAC: the leftmost 4 bytes of
        // CMAC(SK_AC)[ARQC || CSU || proprietary] (EMV v4.4 Book 2 §8.2.2).  CSU byte 1
        // b8 "Proprietary Authentication Data Included" decides whether the
        // proprietary bytes participate in the ARPC.
        byte[] aesArqcM2 = Hex.parse("0102030405060708");
        Asserts.bytes(Hex.parse("66FBE2F5"),
                AesCmac.mac(aesSk, Bytes.concat(aesArqcM2, Hex.parse("80000000"),
                        Hex.parse("A1B2C3D4")), 4),
                "ARPC method 2 AES with proprietary data (CSU byte1 b8 = 1)");
        Asserts.bytes(Hex.parse("772B7AEA"),
                AesCmac.mac(aesSk, Bytes.concat(aesArqcM2, Hex.parse("00000000")), 4),
                "ARPC method 2 AES without proprietary data (CSU byte1 b8 = 0)");
    }
}
