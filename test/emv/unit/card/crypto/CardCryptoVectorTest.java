package card42.test;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

import card42.common.AesCmac;
import card42.common.RetailMac;
import card42.emv.SessionKey;

import card42.host.common.util.Hex;

/**
 * Direct card-side vectors for the MAC and session-key derivation classes:
 * {@link RetailMac}, {@link AesCmac} and
 * {@link SessionKey} are run on a plain JVM (against the JCE-backed
 * {@code javacardx.crypto.Cipher} stub) and locked against independent JCE
 * computations and published spec vectors, so a regression in the card crypto
 * is caught directly rather than only end to end through the same-source host
 * helpers.
 *
 * <ul>
 *   <li>{@code RetailMac}: ISO/IEC 9797-1 algorithm 3 (padding method 2) with
 *       the classic ISO test vector and an independent JCE retail MAC, plus the
 *       aligned form used by Format 1 secure messaging.</li>
 *   <li>{@code AesCmac}: ISO/IEC 9797-1 algorithm 5 against the NIST SP 800-38B
 *       AES-CMAC vectors.</li>
 *   <li>{@code SessionKey}: the EMV v4.4 Book 2 Annex A1.3.1 common session-key
 *       derivation (3DES) and the AES-128 form.</li>
 * </ul>
 */
final class CardCryptoVectorTest {

    private CardCryptoVectorTest() {
    }

    private static final byte[] MK3DES =
            Hex.parse("0F0E0D0C0B0A09080706050403020100");
    private static final byte[] MKAES =
            Hex.parse("0F0E0D0C0B0A09080706050403020100");

    static void run() throws Exception {
        System.out.println("CardCryptoVector");

        // The same RetailMac source must produce the spec vector on the
        // platform-native MAC engine and on the manual fallback used when the
        // platform reports NO_SUCH_ALGORITHM (the simulator).
        retailMacSoftwareFallback();

        // --- RetailMac: ISO/IEC 9797-1 algorithm 3, padding method 2 --------
        byte[] alg3Key = Hex.parse("0123456789ABCDEFFEDCBA9876543210");
        byte[] alg3Msg = "7654321 Now is the time for ".getBytes();
        RetailMac retailMac = new RetailMac();
        byte[] out = new byte[16];
        short n = retailMac.mac(alg3Key, (short) 0, (short) 16, alg3Msg, (short) 0,
                (short) alg3Msg.length, out, (short) 0);
        Asserts.eq(8, n, "RetailMac.mac length");
        Asserts.bytes(Hex.parse("863BE25DAF06098B"), Arrays.copyOf(out, n),
                "RetailMac ISO 9797-1 Alg3 vector");
        Asserts.bytes(retailMacJce(alg3Key, alg3Msg), Arrays.copyOf(out, n),
                "RetailMac agrees with independent JCE retail MAC");

        // Streaming update in three segments must give the same MAC.
        byte[] streamed = new byte[16];
        retailMac.start(alg3Key, (short) 0, (short) 16);
        retailMac.update(alg3Msg, (short) 0, (short) 10);
        retailMac.update(alg3Msg, (short) 10, (short) 0);
        retailMac.update(alg3Msg, (short) 10, (short) (alg3Msg.length - 10));
        n = retailMac.doFinal(streamed, (short) 0);
        Asserts.bytes(Arrays.copyOf(out, 8), Arrays.copyOf(streamed, n),
                "RetailMac streaming equals one-shot");

        // macAligned: a block-aligned message is MACed without extra padding
        // (EMV v4.4 Book 2 Annex D2.3.1).
        byte[] aligned = Hex.parse("00112233445566778899AABBCCDDEEFF");
        n = retailMac.macAligned(alg3Key, (short) 0, (short) 16, aligned, (short) 0,
                (short) aligned.length, out, (short) 0);
        Asserts.eq(8, n, "RetailMac.macAligned length");
        Asserts.bytes(retailMacAlignedJce(alg3Key, aligned),
                Arrays.copyOf(out, n),
                "RetailMac.macAligned agrees with independent JCE retail MAC");

        Asserts.sw((short) 0x6700, () -> retailMac.mac(alg3Key, (short) 0, (short) 8,
                        alg3Msg, (short) 0, (short) alg3Msg.length, new byte[8],
                        (short) 0),
                "RetailMac wrong key length -> 6700");
        Asserts.sw((short) 0x6700, () -> retailMac.macAligned(alg3Key, (short) 0,
                        (short) 16, alg3Msg, (short) 0, (short) alg3Msg.length,
                        new byte[8], (short) 0),
                "RetailMac.macAligned unaligned message -> 6700");

        // --- AesCmac: NIST SP 800-38B AES-CMAC vectors ----------------------
        byte[] cmacKey = Hex.parse("2B7E151628AED2A6ABF7158809CF4F3C");
        AesCmac cmac = new AesCmac();
        byte[] cmacOut = new byte[16];

        n = cmac.mac(cmacKey, (short) 0, (short) 16, new byte[0], (short) 0,
                (short) 0, cmacOut, (short) 0);
        Asserts.eq(16, n, "AesCmac.mac length");
        Asserts.bytes(Hex.parse("BB1D6929E95937287FA37D129B756746"),
                Arrays.copyOf(cmacOut, n), "AES-CMAC NIST empty message");

        byte[] msg128 = Hex.parse("6BC1BEE22E409F96E93D7E117393172A");
        n = cmac.mac(cmacKey, (short) 0, (short) 16, msg128, (short) 0,
                (short) msg128.length, cmacOut, (short) 0);
        Asserts.bytes(Hex.parse("070A16B46B4D4144F79BDD9DD04A287C"),
                Arrays.copyOf(cmacOut, n), "AES-CMAC NIST 128-bit message");

        byte[] msg320 = Hex.parse("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411");
        n = cmac.mac(cmacKey, (short) 0, (short) 16, msg320, (short) 0,
                (short) msg320.length, cmacOut, (short) 0);
        Asserts.bytes(Hex.parse("DFA66747DE9AE63030CA32611497C827"),
                Arrays.copyOf(cmacOut, n), "AES-CMAC NIST 320-bit message");
        Asserts.bytes(cmacJce(cmacKey, msg320), Arrays.copyOf(cmacOut, n),
                "AesCmac agrees with independent JCE CMAC");

        // Streaming update in two segments must give the same CMAC.
        byte[] cmacStreamed = new byte[16];
        cmac.start(cmacKey, (short) 0, (short) 16);
        cmac.update(msg320, (short) 0, (short) 20);
        cmac.update(msg320, (short) 20, (short) (msg320.length - 20));
        n = cmac.doFinal(cmacStreamed, (short) 0);
        Asserts.bytes(Arrays.copyOf(cmacOut, 16), Arrays.copyOf(cmacStreamed, n),
                "AesCmac streaming equals one-shot");

        // macAligned adds no padding to a block-aligned message.
        byte[] cmacAligned = Hex.parse("00112233445566778899AABBCCDDEEFF");
        n = cmac.macAligned(cmacKey, (short) 0, (short) 16, cmacAligned, (short) 0,
                (short) cmacAligned.length, cmacOut, (short) 0);
        Asserts.bytes(cmacJce(cmacKey, cmacAligned), Arrays.copyOf(cmacOut, n),
                "AesCmac.macAligned agrees with independent JCE CMAC");
        byte[] unaligned = Hex.parse("00112233445566778899AABBCCDDEE");
        Asserts.sw((short) 0x6700, () -> cmac.macAligned(cmacKey, (short) 0, (short) 16,
                        unaligned, (short) 0, (short) unaligned.length, new byte[16],
                        (short) 0),
                "AesCmac.macAligned unaligned message -> 6700");
        Asserts.sw((short) 0x6700, () -> cmac.start(cmacKey, (short) 0, (short) 8),
                "AesCmac wrong key length -> 6700");

        // B4: zeroize clears the session key and CMAC subkeys; a later MAC
        // re-derives them (EMV v4.4 Book 2 §A1.2.2).
        Asserts.check(cmac.isInitialized(), "AesCmac holds a session key after mac");
        cmac.zeroize();
        Asserts.check(!cmac.isInitialized(), "AesCmac.zeroize clears the session key");
        byte[] cmacMsg = Hex.parse("00112233445566778899AABBCCDDEEFF");
        n = cmac.mac(cmacKey, (short) 0, (short) 16, cmacMsg, (short) 0,
                (short) cmacMsg.length, cmacOut, (short) 0);
        Asserts.bytes(cmacJce(cmacKey, cmacMsg), Arrays.copyOf(cmacOut, n),
                "AesCmac still MACs after zeroize");
        Asserts.check(retailMac.isInitialized(), "RetailMac holds a session key after mac");
        retailMac.zeroize();
        Asserts.check(!retailMac.isInitialized(), "RetailMac.zeroize clears the session keys");
        n = retailMac.mac(alg3Key, (short) 0, (short) 16, alg3Msg, (short) 0,
                (short) alg3Msg.length, out, (short) 0);
        Asserts.bytes(retailMacJce(alg3Key, alg3Msg), Arrays.copyOf(out, n),
                "RetailMac still MACs after zeroize");

        // --- SessionKey: EMV v4.4 Book 2 Annex A1.3.1 ------------------------
        DESKey mkDes = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
                KeyBuilder.LENGTH_DES3_2KEY, false);
        mkDes.setKey(MK3DES, (short) 0);
        SessionKey sk = new SessionKey();
        byte[] skOut = new byte[16];

        sk.derive(mkDes, (short) 0x0001, skOut, (short) 0);
        Asserts.bytes(Hex.parse("96FEE7669DB34AB5417A136CDA72550F"), skOut,
                "3DES session key (R = ATC || 00 x6)");

        byte[] firstAc = Hex.parse("AABBCCDDEEFF0011");
        sk.derive(mkDes, firstAc, (short) 0, skOut, (short) 0);
        Asserts.bytes(Hex.parse("5D7629457EB7E9BAD8B929AE23B4541E"), skOut,
                "3DES session key (R = first AC)");

        AESKey mkAes = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
                KeyBuilder.LENGTH_AES_128, false);
        mkAes.setKey(MKAES, (short) 0);
        sk.deriveAes(mkAes, (short) 16, (short) 0x0001, skOut, (short) 0);
        Asserts.bytes(Hex.parse("F06C204C70D2AD0CD1FA3B8CE15958F8"), skOut,
                "AES-128 session key (R = ATC || 00 x14)");
        Asserts.bytes(aesEcb(MKAES, Hex.parse("00010000000000000000000000000000")),
                skOut, "AES-128 session key agrees with independent JCE AES-ECB");

        byte[] rAes = Hex.parse("AABBCCDDEEFF00110000000000000000");
        sk.deriveAes(mkAes, (short) 16, rAes, (short) 0, skOut, (short) 0);
        Asserts.bytes(Hex.parse("C1994753F99E6196418C14F7DD5F1AF9"), skOut,
                "AES-128 session key (R = first AC || 00 x8)");
        Asserts.sw((short) 0x6700, () -> sk.deriveAes(mkAes, (short) 8, rAes,
                        (short) 0, new byte[16], (short) 0),
                "SessionKey.deriveAes non-128 length -> 6700");
    }

    /**
     * The same vectors with the platform DES MAC reported unavailable, which
     * forces {@link RetailMac}'s manual CBC-MAC path — the one the simulator
     * uses (docs/specs/common/cryptography.md §4).  The source is the same, so both
     * paths must agree with the independent JCE construction.
     */
    private static void retailMacSoftwareFallback() throws Exception {
        byte[] key = Hex.parse("0123456789ABCDEFFEDCBA9876543210");
        byte[] msg = "7654321 Now is the time for ".getBytes();
        byte[] out = new byte[16];
        System.setProperty(Signature.SOFTWARE_DES_MAC_PROPERTY, "1");
        try {
            RetailMac mac = new RetailMac();
            short n = mac.mac(key, (short) 0, (short) 16, msg, (short) 0,
                    (short) msg.length, out, (short) 0);
            Asserts.bytes(Hex.parse("863BE25DAF06098B"), Arrays.copyOf(out, n),
                    "RetailMac software fallback Alg3 vector");

            mac.start(key, (short) 0, (short) 16);
            mac.update(msg, (short) 0, (short) 10);
            mac.update(msg, (short) 10, (short) (msg.length - 10));
            n = mac.doFinal(out, (short) 0);
            Asserts.bytes(Hex.parse("863BE25DAF06098B"), Arrays.copyOf(out, n),
                    "RetailMac software fallback streaming");

            byte[] aligned = Hex.parse("00112233445566778899AABBCCDDEEFF");
            n = mac.macAligned(key, (short) 0, (short) 16, aligned, (short) 0,
                    (short) aligned.length, out, (short) 0);
            Asserts.bytes(retailMacAlignedJce(key, aligned), Arrays.copyOf(out, n),
                    "RetailMac software fallback macAligned");
        } finally {
            System.clearProperty(Signature.SOFTWARE_DES_MAC_PROPERTY);
        }
    }

    /**
     * ISO/IEC 9797-1 algorithm 3 (retail MAC) with padding method 2, computed
     * with JCE only: single-DES CBC-MAC under K1, then DES_K2^-1 and DES_K1.
     */
    private static byte[] retailMacJce(byte[] key16, byte[] msg) throws Exception {
        int pad = 8 - (msg.length % 8);
        byte[] padded = new byte[msg.length + pad];
        System.arraycopy(msg, 0, padded, 0, msg.length);
        padded[msg.length] = (byte) 0x80;
        return retailMacAlignedJce(key16, padded);
    }

    /** Algorithm 3 over an already block-aligned message (no padding added). */
    private static byte[] retailMacAlignedJce(byte[] key16, byte[] aligned)
            throws Exception {
        if ((aligned.length & 7) != 0) {
            throw new IllegalArgumentException("not block aligned");
        }
        byte[] k1 = Arrays.copyOfRange(key16, 0, 8);
        byte[] k2 = Arrays.copyOfRange(key16, 8, 16);
        Cipher des = Cipher.getInstance("DES/CBC/NoPadding");
        des.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k1, "DES"),
                new IvParameterSpec(new byte[8]));
        byte[] cbc = new byte[8];
        for (int i = 0; i < aligned.length; i += 8) {
            for (int j = 0; j < 8; j++) {
                cbc[j] ^= aligned[i + j];
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
    private static byte[] cmacJce(byte[] key16, byte[] msg) throws Exception {
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

    /** AES-128 ECB encryption of one block (JCE, independent of the card). */
    private static byte[] aesEcb(byte[] key16, byte[] block) throws Exception {
        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key16, "AES"));
        return aes.doFinal(block);
    }
}
