package card42.test;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;

import card42.emv.SecureMessaging;

import card42.host.emv.crypto.SmCrypto;
import card42.host.emv.crypto.AcCrypto;
import card42.host.common.crypto.AesCmac;
import card42.host.common.util.Bytes;
import card42.host.common.util.Hex;

/**
 * Pure-JVM spec vectors for the EMV Format 1 secure-messaging MAC input
 * (EMV v4.4 Book 2 §9.2.3 / Annex D2.3.1).
 *
 * <p>The card-side construction is exposed by
 * {@link SecureMessaging#format1MacInput} precisely so it can be checked here:
 * the padded input is {@code ICV || CLA INS P1 P2 80 00 00 00 || <each data
 * object padded with 80 00.. to a multiple of 8>}.  The same vectors are then
 * cross-checked against the host-side {@link SmCrypto} so the two sides cannot
 * drift apart.
 */
final class SecureMessagingTest {

    private SecureMessagingTest() {
    }

    private static final byte[] ICV = Hex.parse("AABBCCDDEEFF0011");
    private static final byte[] HEADER = Hex.parse("8C240000");
    private static final byte[] HEADER_PAD = Hex.parse("80000000");
    private static final byte[] MAC_KEY = Hex.parse("11111111111111111111111111111111");

    static void run() throws Exception {
        System.out.println("SecureMessaging");

        // --- No command data: the header alone is padded with 80 00 00 00 ----
        byte[] out = new byte[64];
        byte[] apdu = Bytes.concat(HEADER, new byte[0]);
        short len = SecureMessaging.format1MacInput(apdu, (short) 4, (short) 0,
                ICV, out, (short) 0);
        Asserts.eq(16, len, "no-data MAC input length");
        Asserts.bytes(Bytes.concat(ICV, HEADER, HEADER_PAD),
                Arrays.copyOf(out, len), "no-data MAC input");

        // --- '81' plaintext object: 81 02 12 34 -> padded to 8 bytes --------
        byte[] plain = Hex.parse("81021234");
        apdu = Bytes.concat(HEADER, plain, Hex.parse("8E0400000000"));
        len = SecureMessaging.format1MacInput(apdu, (short) 4,
                (short) (apdu.length - 4), ICV, out, (short) 0);
        Asserts.eq(24, len, "81 object MAC input length");
        Asserts.bytes(Bytes.concat(ICV, HEADER, HEADER_PAD,
                        Hex.parse("8102123480000000")),
                Arrays.copyOf(out, len), "81 object MAC input");

        // --- '87' confidentiality object: 87 03 01 11 22 -> padded to 8 -----
        byte[] enc = Hex.parse("8703011122");
        apdu = Bytes.concat(HEADER, enc, Hex.parse("8E0400000000"));
        len = SecureMessaging.format1MacInput(apdu, (short) 4,
                (short) (apdu.length - 4), ICV, out, (short) 0);
        Asserts.eq(24, len, "87 object MAC input length");
        Asserts.bytes(Bytes.concat(ICV, HEADER, HEADER_PAD,
                        Hex.parse("8703011122800000")),
                Arrays.copyOf(out, len), "87 object MAC input");

        // A MAC object that is not the last object is malformed.
        byte[] trailing = Hex.parse("8C2400008E0400000000810212 34".replace(" ", ""));
        Asserts.sw((short) 0x6A80, () -> SecureMessaging.format1MacInput(trailing,
                        (short) 4, (short) (trailing.length - 4), ICV, new byte[64],
                        (short) 0),
                "MAC object not last -> 6A80");

        // --- Cross-check with the host-side Format 1 MAC ---------------------
        byte[] macSessionKey = AcCrypto.sessionKey(MAC_KEY, ICV);
        SmCrypto.ScriptSession session = new SmCrypto.ScriptSession(MAC_KEY, null);
        session.start(ICV);
        CommandAPDU command = session.command(0x24, 0x00, 0x00);
        byte[] hostMac = Arrays.copyOfRange(command.getData(),
                command.getData().length - 8, command.getData().length);

        byte[] cardInput = new byte[64];
        short cardLen = SecureMessaging.format1MacInput(
                Hex.parse("8C240000"), (short) 4, (short) 0, ICV,
                cardInput, (short) 0);
        Asserts.bytes(hostMac, AcCrypto.macAlg3Padded(macSessionKey,
                        Arrays.copyOf(cardInput, cardLen), 8),
                "card MAC input matches the host construction");

        // An independent, self-contained ISO/IEC 9797-1 Algorithm 3 computation
        // (JCE DES, not the host AcCrypto/SmCrypto helpers) locks the concrete
        // MAC of a self-chosen input (ICV + padded Format 1 header), so the
        // expected bytes do not come from the same construction that produces
        // them.  EMV v4.4 Book 2 Annex D2 has no numeric example, so the input
        // is chosen here, not taken from D2.3.1.
        byte[] d231Input = Bytes.concat(ICV, HEADER, HEADER_PAD);
        byte[] d231Mac = iso9797Alg3Padded(macSessionKey, d231Input);
        Asserts.bytes(Hex.parse("E99B14DE69EC0CA8"), d231Mac,
                "ISO 9797-1 Alg3 MAC (independent JCE, self-chosen input)");
        Asserts.bytes(d231Mac, AcCrypto.macAlg3Padded(macSessionKey, d231Input, 8),
                "independent Alg3 MAC agrees with the host Alg3 helper");

        // --- CV '6' (AES): 16-byte ICV, AES-CMAC, AES-CBC '87' --------------
        // EMV v4.4 Book 2 §9.2.3.1: the first AC is right-padded to the 16-byte block.
        byte[] firstAc = Hex.parse("AABBCCDDEEFF0011");
        byte[] icvAes = Bytes.concat(firstAc, new byte[8]);
        byte[] aesMacKey = Hex.parse("11111111111111111111111111111111");
        byte[] aesEncKey = Hex.parse("22222222222222222222222222222222");

        // A1.3.1 session keys: R = first AC || 00 x8.
        byte[] aesMacSk = AcCrypto.sessionKeyAesSm(aesMacKey, firstAc);
        Asserts.bytes(Hex.parse("101F9A2D865CB4C5F04DF810E2063D8A"), aesMacSk,
                "CV6 MAC session key (R = first AC || 00 x8)");
        byte[] aesEncSk = AcCrypto.sessionKeyAesSm(aesEncKey, firstAc);
        Asserts.bytes(Hex.parse("B49FF1985C07384B45A27DA1499654A1"), aesEncSk,
                "CV6 ENC session key");

        // '87' confidentiality object: padding indicator 01 || AES-CBC(ENC SK)
        // of the ISO 7816-4 padded PIN block (EMV v4.4 Book 2 §9.3.1.1/§9.3.3).  The
        // ciphertext is computed here with JCE, independently of the card code.
        byte[] pinBlock = Hex.parse("241234FFFFFFFFFF");
        byte[] ciphertext = aesCbcEncrypt(aesEncSk, padIso7816To16(pinBlock));
        Asserts.bytes(Hex.parse("66BF3EAEE484A39148DCDB28D95E786D"), ciphertext,
                "CV6 87 AES-CBC ciphertext");
        Asserts.bytes(padIso7816To16(pinBlock), aesCbcDecrypt(aesEncSk, ciphertext),
                "CV6 87 AES-CBC decrypts to the padded PIN block");

        byte[] obj = Bytes.concat(Hex.parse("8711"), new byte[] { 0x01 }, ciphertext);
        byte[] cmd = Bytes.concat(Hex.parse("8C240000"), obj, Hex.parse("8E08"),
                new byte[8]);
        byte[] outAes = new byte[96];
        short macInLen = SecureMessaging.format1MacInput(cmd, (short) 4,
                (short) (cmd.length - 4), icvAes, (short) 16, (short) 16, outAes,
                (short) 0);
        Asserts.bytes(Bytes.concat(icvAes,
                        Hex.parse("8C240000800000000000000000000000"),
                        padIso7816To16(obj)),
                Arrays.copyOf(outAes, macInLen), "CV6 MAC input (16-byte ICV)");

        // The MAC is the full 16-byte AES-CMAC; only its leftmost 8 bytes are
        // transmitted (EMV v4.4 Book 2 §9.2.3).  Locked against an independent CMAC.
        byte[] fullMac1 = AesCmac.mac(aesMacSk, Arrays.copyOf(outAes, macInLen));
        Asserts.bytes(Hex.parse("346FDAC65189C7E927C8A9C9C4DAF827"), fullMac1,
                "CV6 AES-CMAC full block");
        Asserts.bytes(Hex.parse("346FDAC65189C7E9"), Arrays.copyOf(fullMac1, 8),
                "CV6 transmitted MAC (leftmost 8 bytes)");

        // Chaining: the next ICV is the full 16-byte MAC of the previous command
        // (EMV v4.4 Book 2 §9.2.3.1).
        byte[] cmd2 = Bytes.concat(Hex.parse("8C180000"), Hex.parse("8E08"),
                new byte[8]);
        short macInLen2 = SecureMessaging.format1MacInput(cmd2, (short) 4,
                (short) (cmd2.length - 4), fullMac1, (short) 16, (short) 16, outAes,
                (short) 0);
        Asserts.bytes(Hex.parse("12090342118B5B0BCD6F7538D60CE515"),
                AesCmac.mac(aesMacSk, Arrays.copyOf(outAes, macInLen2)),
                "CV6 chained AES-CMAC (16-byte ICV)");
    }

    /** ISO/IEC 7816-4 padding to the 16-byte AES block size. */
    private static byte[] padIso7816To16(byte[] data) {
        int pad = 16 - (data.length % 16);
        byte[] padded = new byte[data.length + pad];
        System.arraycopy(data, 0, padded, 0, data.length);
        padded[data.length] = (byte) 0x80;
        return padded;
    }

    /**
     * Self-contained ISO/IEC 9797-1 Algorithm 3 (ANSI X9.19 retail MAC) over a
     * block-aligned message: single-DES CBC-MAC with K1, then
     * {@code E(K1, D(K2, H))}.  Implemented directly with JCE DES so it is
     * independent of the card {@code RetailMac} and the host {@code AcCrypto}
     * helper (EMV v4.4 Book 2 Annex A1.2 / §9.2.3).
     */
    private static byte[] iso9797Alg3Padded(byte[] key16, byte[] padded)
            throws Exception {
        if ((padded.length & 7) != 0) {
            throw new IllegalArgumentException("message is not block aligned");
        }
        byte[] k1 = Arrays.copyOfRange(key16, 0, 8);
        byte[] k2 = Arrays.copyOfRange(key16, 8, 16);
        Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
        byte[] h = new byte[8];
        des.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k1, "DES"));
        for (int i = 0; i < padded.length; i += 8) {
            byte[] block = new byte[8];
            for (int j = 0; j < 8; j++) {
                block[j] = (byte) (padded[i + j] ^ h[j]);
            }
            h = des.doFinal(block);
        }
        des.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k2, "DES"));
        h = des.doFinal(h);
        des.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k1, "DES"));
        return des.doFinal(h);
    }

    /** AES-128 CBC encryption with a zero IV (JCE, independent of the card). */
    private static byte[] aesCbcEncrypt(byte[] key16, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key16, "AES"),
                new IvParameterSpec(new byte[16]));
        return cipher.doFinal(data);
    }

    /** AES-128 CBC decryption with a zero IV (JCE, independent of the card). */
    private static byte[] aesCbcDecrypt(byte[] key16, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key16, "AES"),
                new IvParameterSpec(new byte[16]));
        return cipher.doFinal(data);
    }
}
