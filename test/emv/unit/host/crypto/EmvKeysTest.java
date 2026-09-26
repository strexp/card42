package card42.test;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import card42.host.common.util.Bytes;
import card42.host.emv.crypto.EmvKeys;
import card42.host.common.util.Hex;

/**
 * Independent vectors for the host ICC master-key derivation (EMV v4.4 Book 2
 * Annex A1.4, Options A/B/C) and the AC/MAC/ENC key hierarchy.
 *
 * <p>The expected values come from external reference implementations, not from
 * this code base, so the card and host cannot share a derivation bug:
 *
 * <ul>
 *   <li>Option A: EFTlab EMV cryptographic calculator and the pyEMV README.</li>
 *   <li>Option B: the pyEMV README (PAN longer than 16 digits).</li>
 *   <li>Option C: the CV '6' sample master key already locked by
 *       {@link AesVectorTest}.</li>
 * </ul>
 */
final class EmvKeysTest {

    private EmvKeysTest() {
    }

    /** Triple DES ECB over one block with a double-length key (JCE). */
    private static byte[] des3Ecb(byte[] key16, byte[] block8) throws Exception {
        byte[] key = new byte[24];
        System.arraycopy(key16, 0, key, 0, 16);
        System.arraycopy(key16, 0, key, 16, 8);
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"));
        return cipher.doFinal(block8);
    }

    static void run() throws Exception {
        System.out.println("EmvKeys");

        // --- Option A (EMV v4.4 Book 2 §A1.4.1) -----------------------------
        // EFTlab EMV calculator: MDK 0123456789ABCDEF0123456789ABCDEF,
        // PAN 43219876543210987, PAN sequence 00 -> UDK C8B5...
        byte[] eftlabMdk = Hex.parse("0123456789ABCDEF0123456789ABCDEF");
        byte[] eftlab = EmvKeys.optionA(eftlabMdk, "43219876543210987", 0x00);
        Asserts.bytes(Hex.parse("C8B507136D921FD05864C81F79F2D30B"), eftlab,
                "Option A EFTlab vector");
        // EFTlab also prints KCV 0DA897 (leftmost 3 bytes of DES3(UDK)[00 x8]).
        Asserts.bytes(Hex.parse("0DA897"),
                java.util.Arrays.copyOf(des3Ecb(eftlab, new byte[8]), 3),
                "Option A EFTlab KCV");

        // pyEMV: iss_mk 0123456789ABCDEFFEDCBA9876543210, PAN 99012345678901234,
        // PSN 45 -> 67F8...; PAN 12345678901234567, PSN 01 -> 73AD...
        byte[] pyemvImk = Hex.parse("0123456789ABCDEFFEDCBA9876543210");
        Asserts.bytes(Hex.parse("67F8292358083E5EA7AB7FDA58D53B6B"),
                EmvKeys.optionA(pyemvImk, "99012345678901234", 0x45),
                "Option A pyEMV 17-digit vector");
        Asserts.bytes(Hex.parse("73AD54688CEF2934B0979857E3C719F1"),
                EmvKeys.optionA(pyemvImk, "12345678901234567", 0x01),
                "Option A pyEMV 17-digit vector 2");

        // A PAN of exactly 16 digits is still Option A (16 rightmost digits).
        Asserts.bytes(EmvKeys.optionA(pyemvImk, "1234567890123456", 0x00),
                EmvKeys.optionB(pyemvImk, "1234567890123456", 0x00),
                "Option B falls back to Option A for a 16-digit PAN");

        // --- Option B (EMV v4.4 Book 2 §A1.4.2) -----------------------------
        Asserts.bytes(Hex.parse("985EC4FD3EDF6162E31AF1C7D0543416"),
                EmvKeys.optionB(pyemvImk, "99012345678901234", 0x45),
                "Option B pyEMV vector");
        Asserts.bytes(Hex.parse("AD406D7F6D7570916D75E5DCAB8CF737"),
                EmvKeys.optionB(pyemvImk, "12345678901234567", 0x01),
                "Option B pyEMV vector 2");

        // desMasterKey selects Option B, the CV '5' method (CCD §8.3).
        Asserts.bytes(EmvKeys.optionB(pyemvImk, "99012345678901234", 0x45),
                EmvKeys.desMasterKey(pyemvImk, "99012345678901234", 0x45),
                "desMasterKey uses Option B");

        // --- Option C (EMV v4.4 Book 2 §A1.4.3) -----------------------------
        byte[] aesImk = Hex.parse("0F0E0D0C0B0A09080706050403020100");
        Asserts.bytes(Hex.parse("F5C0A799FFBED1DB4F9BD2E54BF2CFD9"),
                EmvKeys.aesMasterKey(aesImk, "1234567890", 0x00, 16),
                "Option C AES-128 sample vector");

        // --- AC / MAC / ENC hierarchy ---------------------------------------
        byte[] imkAc = Hex.parse("0F0E0D0C0B0A09080706050403020100");
        byte[] imkMac = Hex.parse("11111111111111111111111111111111");
        byte[] imkEnc = Hex.parse("22222222222222222222222222222222");
        EmvKeys.IccMasterKeys cv5 =
                EmvKeys.iccMasterKeys(imkAc, imkMac, imkEnc, "1234567890", 0x00, false);
        Asserts.bytes(EmvKeys.desMasterKey(imkAc, "1234567890", 0x00), cv5.ac,
                "hierarchy AC key");
        Asserts.bytes(EmvKeys.desMasterKey(imkMac, "1234567890", 0x00), cv5.mac,
                "hierarchy MAC key");
        Asserts.bytes(EmvKeys.desMasterKey(imkEnc, "1234567890", 0x00), cv5.enc,
                "hierarchy ENC key");
        Asserts.check(!java.util.Arrays.equals(cv5.ac, cv5.mac)
                && !java.util.Arrays.equals(cv5.mac, cv5.enc)
                && !java.util.Arrays.equals(cv5.ac, cv5.enc),
                "hierarchy keys are independent");

        EmvKeys.IccMasterKeys cv6 =
                EmvKeys.iccMasterKeys(imkAc, imkMac, imkEnc, "1234567890", 0x00, true);
        Asserts.bytes(EmvKeys.aesMasterKey(imkAc, "1234567890", 0x00, 16), cv6.ac,
                "hierarchy AES AC key");
        Asserts.bytes(EmvKeys.aesMasterKey(imkMac, "1234567890", 0x00, 16), cv6.mac,
                "hierarchy AES MAC key");
        Asserts.bytes(EmvKeys.aesMasterKey(imkEnc, "1234567890", 0x00, 16), cv6.enc,
                "hierarchy AES ENC key");

        // Option C uses the 16-byte diversification value; Option A/B the
        // 16-digit form.  A 16-byte BCD Y and a 16-digit BCD Y differ.
        Asserts.check(!java.util.Arrays.equals(
                EmvKeys.diversificationValue("1234567890", 0x00),
                Bytes.concat(new byte[8], new byte[8])),
                "Option C diversification value is 16 bytes");
    }
}
