package card42.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import card42.emrtd.AaCrypto;
import card42.emrtd.BacCrypto;
import card42.emrtd.EmrtdTags;
import card42.emrtd.LdsCatalog;
import card42.emrtd.LdsFile;
import card42.emrtd.LdsFileSystem;
import card42.emrtd.MrzKeySeed;
import card42.host.common.crypto.P256;
import card42.host.common.util.Hex;
import card42.host.emrtd.aa.ActiveAuthentication;

/**
 * Pure-JVM tests for the eMRTD card-side crypto and LDS file system.
 * The BAC vectors are the ICAO Doc 9303-11 sample
 * (document number L898902C&lt;, DOB 690806, DOE 940623); the AA test generates
 * a fresh RSA key so the JCE-backed {@code Signature} stub signs and an
 * independent JDK verifier checks the result.
 */
final class EmrtdCryptoTest {

    private static final byte[] MRZ_INFO =
            "L898902C<369080619406236".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private EmrtdCryptoTest() {
    }

    static void run() throws Exception {
        System.out.println("EmrtdCrypto");

        checkDigits();
        bacKeyDerivation();
        bacSessionVectors();
        ldsFileSystem();
        ldsCatalogComIndex();
        activeAuthentication();
        secureMessaging();
        smResponseWindow();
        chipAuthPeerValidation();
    }

    /**
     * Card-side Chip Authentication validates the terminal's ephemeral point
     * before the ECDH (BSI TR-03110-3 A.3.4.1) and returns 6A80 on a bad point
     * (ICAO Doc 9303-11 §6.2.4.1).
     */
    private static void chipAuthPeerValidation() throws Exception {
        java.security.SecureRandom random = new java.security.SecureRandom();
        BigInteger d = P256.randomScalar(random);
        P256.Point staticPub = P256.scalarMult(d, P256.generator());

        card42.emrtd.ChipAuth cardCa = new card42.emrtd.ChipAuth();
        byte[] scalar = toFixed(d, 32);
        cardCa.setPrivateKey(scalar, (short) 0, (short) scalar.length);
        Asserts.check(cardCa.isInitialized(), "card CA private key initialized");

        BigInteger e = P256.randomScalar(random);
        byte[] peerW = P256.encode(P256.scalarMult(e, P256.generator()));
        byte[] enc = new byte[16];
        byte[] mac = new byte[16];
        cardCa.deriveSessionKeys(peerW, (short) 0, (short) peerW.length,
                enc, (short) 0, mac, (short) 0);

        byte[] z = P256.x(P256.scalarMult(e, staticPub));
        Asserts.bytes(card42.host.emrtd.access.ChipAuth.deriveKey(z, 1), enc,
                "card CA Ks_enc matches host ECDH");
        Asserts.bytes(card42.host.emrtd.access.ChipAuth.deriveKey(z, 2), mac,
                "card CA Ks_mac matches host ECDH");

        byte[] offCurve = peerW.clone();
        offCurve[64] ^= 0x01;
        Asserts.sw((short) 0x6A80, () -> cardCa.deriveSessionKeys(offCurve, (short) 0,
                (short) offCurve.length, new byte[16], (short) 0, new byte[16], (short) 0),
                "card CA off-curve peer -> 6A80");

        byte[] wrongLength = new byte[64];
        Asserts.sw((short) 0x6A80, () -> cardCa.deriveSessionKeys(wrongLength, (short) 0,
                (short) wrongLength.length, new byte[16], (short) 0, new byte[16], (short) 0),
                "card CA wrong-length peer -> 6A80");

        byte[] unreduced = new byte[65];
        unreduced[0] = 0x04;
        System.arraycopy(toFixed(P256.P, 32), 0, unreduced, 1, 32);
        Asserts.sw((short) 0x6A80, () -> cardCa.deriveSessionKeys(unreduced, (short) 0,
                (short) unreduced.length, new byte[16], (short) 0, new byte[16], (short) 0),
                "card CA unreduced peer -> 6A80");
    }

    /** Big-endian fixed-width copy of a non-negative value. */
    private static byte[] toFixed(BigInteger value, int width) {
        byte[] out = new byte[width];
        byte[] raw = value.toByteArray();
        int start = raw.length > width ? raw.length - width : 0;
        int len = raw.length - start;
        System.arraycopy(raw, start, out, width - len, len);
        return out;
    }

    /** The card-side COM index builds EF.COM from the stored data groups (E1.6). */
    private static void ldsCatalogComIndex() {
        LdsCatalog catalog = new LdsCatalog();
        byte[] dg1 = Hex.parse("61585F1F5850");
        byte[] dg15 = Hex.parse("6F00"); // presence marker only, never parsed
        catalog.store(EmrtdTags.FID_DG1, dg1, (short) 0, (short) dg1.length);
        catalog.store(EmrtdTags.FID_DG15, dg15, (short) 0, (short) dg15.length);
        catalog.finalizeCatalog();

        catalog.select(EmrtdTags.FID_COM);
        LdsFile com = catalog.getSelected();
        byte[] out = new byte[64];
        short n = com.read((short) 0, com.getLength(), out, (short) 0);
        card42.host.emrtd.lds.Com parsed = card42.host.emrtd.lds.Com.parse(
                java.util.Arrays.copyOf(out, n));
        Asserts.eq("0107", parsed.ldsVersion, "COM index LDS version");
        Asserts.eq("040001", parsed.unicodeVersion, "COM index Unicode version");
        Asserts.eq(2, parsed.dataGroupTags.length, "COM index data group count");
        Asserts.eq(0x61, parsed.dataGroupTags[0], "COM index DG1 tag");
        Asserts.eq(0x6F, parsed.dataGroupTags[1], "COM index DG15 tag");
    }

    /**
     * The plaintext READ BINARY window must depend on the SM block size: an
     * AES envelope is larger than a 3DES one, so a single 0xE7 cap made the
     * card return 6700 on a large DG read under AES PACE (found with JMRTD).
     */
    private static void smResponseWindow() throws Exception {
        byte[] ksEnc = Hex.parse("AB94FDECF2674FDFB9B391F85D7F76F2");
        byte[] ksMac = Hex.parse("7962D9ECE03D1ACD4C76089DCE131543");

        card42.emrtd.Iso7816Sm sm3 = new card42.emrtd.Iso7816Sm();
        Asserts.eq(231, sm3.maxResponseData(), "3DES SM plaintext window is 0xE7");
        Asserts.check(envelope(sm3, ksEnc, ksMac, sm3.maxResponseData()) <= 256,
                "3DES SM envelope fits a 256-byte APDU");
        Asserts.check(envelope(sm3, ksEnc, ksMac, (short) (sm3.maxResponseData() + 1)) > 256,
                "3DES window + 1 overflows a 256-byte APDU");

        card42.emrtd.Iso7816SmAes aes = new card42.emrtd.Iso7816SmAes();
        Asserts.eq(223, aes.maxResponseData(), "AES SM plaintext window is 0xDF");
        Asserts.check(envelope(aes, ksEnc, ksMac, aes.maxResponseData()) <= 256,
                "AES SM envelope fits a 256-byte APDU");
        Asserts.check(envelope(aes, ksEnc, ksMac, (short) (aes.maxResponseData() + 1)) > 256,
                "AES window + 1 overflows a 256-byte APDU");
    }

    /** The wrapped-response length for a plaintext window of {@code len} bytes. */
    private static int envelope(card42.emrtd.SecureMessaging sm, byte[] ksEnc, byte[] ksMac,
                                short len) {
        byte[] resp = new byte[len];
        byte[] out = new byte[512];
        return sm.wrap(ksEnc, ksMac, new byte[8], resp, len, (short) 0x9000, out, (short) 0);
    }

    /**
     * Cross-checks the card-side SM wrapper against the independent host-side
     * implementation: card wrap -&gt; host unwrap and host wrap -&gt; card unwrap.
     */
    private static void secureMessaging() throws Exception {
        byte[] ksEnc = Hex.parse("AB94FDECF2674FDFB9B391F85D7F76F2");
        byte[] ksMac = Hex.parse("7962D9ECE03D1ACD4C76089DCE131543");
        byte[] payload = Hex.parse("0102030405");

        card42.emrtd.Iso7816Sm cardSm = new card42.emrtd.Iso7816Sm();
        byte[] ssc = new byte[8];
        byte[] wrapped = new byte[256];
        short n = cardSm.wrap(ksEnc, ksMac, ssc, payload, (short) payload.length,
                (short) 0x9000, wrapped, (short) 0);

        card42.host.emrtd.access.Iso7816Sm hostSm =
                new card42.host.emrtd.access.Iso7816Sm(ksEnc, ksMac, 0L);
        short[] sw = new short[1];
        byte[] plain = hostSm.unwrapResponse(java.util.Arrays.copyOf(wrapped, n), sw);
        Asserts.bytes(payload, plain, "SM card wrap -> host unwrap");
        Asserts.eq(0x9000, sw[0] & 0xFFFF, "SM response status word");

        byte[] cmd = hostSm.wrapCommand(0x00, 0xB0, 0x00, 0x00, payload, 0x10);
        byte[] apdu = new byte[256];
        apdu[0] = (byte) 0x0C;
        apdu[1] = (byte) 0xB0;
        System.arraycopy(cmd, 0, apdu, 4, cmd.length);
        byte[] out = new byte[64];
        short len = cardSm.unwrap(ksEnc, ksMac, ssc, apdu, (short) 4,
                (short) cmd.length, out, (short) 0);
        Asserts.bytes(payload, java.util.Arrays.copyOf(out, len), "SM host wrap -> card unwrap");
        Asserts.eq(0x10, cardSm.getLe(), "SM unwrapped Le");

        // Odd INS carries plain command data in DO'85' (Doc 9303-11 §9.8.4);
        // a >127-byte field forces the BER long form on both sides.
        byte[] big = new byte[200];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) i;
        }
        byte[] oddCmd = hostSm.wrapCommand(0x00, 0xD7, 0x00, 0x00, big, 0);
        Asserts.check((oddCmd[0] & 0xFF) == 0x85, "odd INS command uses DO85");
        byte[] oddApdu = new byte[512];
        oddApdu[0] = (byte) 0x0C;
        oddApdu[1] = (byte) 0xD7;
        System.arraycopy(oddCmd, 0, oddApdu, 4, oddCmd.length);
        byte[] oddOut = new byte[256];
        short oddLen = cardSm.unwrap(ksEnc, ksMac, ssc, oddApdu, (short) 4,
                (short) oddCmd.length, oddOut, (short) 0);
        Asserts.bytes(big, java.util.Arrays.copyOf(oddOut, oddLen),
                "SM odd-INS DO85 + BER long form host wrap -> card unwrap");

        // AES secure messaging: the same framing with AES-CMAC (BSI TR-03110-3
        // §4.5).  The card-side AES wrapper is otherwise untested.
        card42.emrtd.Iso7816SmAes cardAes = new card42.emrtd.Iso7816SmAes();
        card42.host.emrtd.access.Iso7816SmAes hostAes =
                new card42.host.emrtd.access.Iso7816SmAes(ksEnc, ksMac, 0L);
        byte[] aesSsc = new byte[8];
        byte[] aesWrapped = new byte[256];
        short an = cardAes.wrap(ksEnc, ksMac, aesSsc, payload, (short) payload.length,
                (short) 0x9000, aesWrapped, (short) 0);
        short[] asw = new short[1];
        byte[] aplain = hostAes.unwrapResponse(java.util.Arrays.copyOf(aesWrapped, an), asw);
        Asserts.bytes(payload, aplain, "AES SM card wrap -> host unwrap");
        Asserts.eq(0x9000, asw[0] & 0xFFFF, "AES SM response status word");

        byte[] aesOdd = hostAes.wrapCommand(0x00, 0xD7, 0x00, 0x00, big, 0);
        Asserts.check((aesOdd[0] & 0xFF) == 0x85, "AES odd INS command uses DO85");
        byte[] aesApdu = new byte[512];
        aesApdu[0] = (byte) 0x0C;
        aesApdu[1] = (byte) 0xD7;
        System.arraycopy(aesOdd, 0, aesApdu, 4, aesOdd.length);
        byte[] aesOut = new byte[256];
        short alen = cardAes.unwrap(ksEnc, ksMac, aesSsc, aesApdu, (short) 4,
                (short) aesOdd.length, aesOut, (short) 0);
        Asserts.bytes(big, java.util.Arrays.copyOf(aesOut, alen),
                "AES SM odd-INS DO85 + BER long form host wrap -> card unwrap");
    }

    private static void checkDigits() {
        byte[] out = new byte[1];
        MrzKeySeed.checkDigit("L898902C<".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                (short) 0, (short) 9, out, (short) 0);
        Asserts.eq(3, out[0] & 0xFF, "MRZ document-number check digit");
        MrzKeySeed.checkDigit("690806".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                (short) 0, (short) 6, out, (short) 0);
        Asserts.eq(1, out[0] & 0xFF, "MRZ date-of-birth check digit");
        MrzKeySeed.checkDigit("940623".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                (short) 0, (short) 6, out, (short) 0);
        Asserts.eq(6, out[0] & 0xFF, "MRZ date-of-expiry check digit");
    }

    private static void bacKeyDerivation() {
        byte[] seed = new byte[20];
        short n = MrzKeySeed.seed(MRZ_INFO, (short) 0, seed, (short) 0);
        Asserts.eq(16, n, "BAC seed length");
        Asserts.bytes(Hex.parse("239AB9CB282DAF66231DC5A4DF6BFBAE"),
                java.util.Arrays.copyOf(seed, 16), "BAC K_seed (Doc 9303-11 sample)");

        BacCrypto bac = new BacCrypto();
        byte[] kenc = new byte[16];
        byte[] kmac = new byte[16];
        bac.deriveKey(seed, (short) 0, BacCrypto.DERIVE_ENC, kenc, (short) 0);
        bac.deriveKey(seed, (short) 0, BacCrypto.DERIVE_MAC, kmac, (short) 0);
        Asserts.bytes(Hex.parse("AB94FDECF2674FDFB9B391F85D7F76F2"), kenc, "BAC K_enc");
        Asserts.bytes(Hex.parse("7962D9ECE03D1ACD4C76089DCE131543"), kmac, "BAC K_mac");

        // 3DES round trip and the retail MAC of an empty message (padding only).
        byte[] plain = Hex.parse("11223344556677889900AABBCCDDEEFF");
        byte[] cipher = new byte[16];
        byte[] back = new byte[16];
        bac.encrypt(kenc, plain, (short) 0, cipher, (short) 0, (short) 16);
        bac.decrypt(kenc, cipher, (short) 0, back, (short) 0, (short) 16);
        Asserts.bytes(plain, back, "BAC 3DES-CBC round trip");
    }

    /**
     * ICAO Doc 9303-11 Appendix D.3/D.4 worked example on the card side: the
     * session keys come from KDF(K_IFD XOR K_IC) and the secure-messaging MAC
     * is algorithm 3 over the already M2-padded N (no extra padding block).
     */
    private static void bacSessionVectors() {
        byte[] kifd = Hex.parse("0B795240CB7049B01C19B33E32804F0B");
        byte[] kic = Hex.parse("0B4F80323EB3191CB04970CB4052790B");
        byte[] seed = new byte[16];
        BacCrypto.sessionSeed(kifd, (short) 0, kic, (short) 0, seed, (short) 0);
        Asserts.bytes(Hex.parse("0036D272F5C350ACAC50C3F572D23600"), seed,
                "card BAC session seed = K_IFD XOR K_IC");

        BacCrypto bac = new BacCrypto();
        byte[] ksEnc = new byte[16];
        byte[] ksMac = new byte[16];
        bac.deriveKey(seed, (short) 0, BacCrypto.DERIVE_ENC, ksEnc, (short) 0);
        bac.deriveKey(seed, (short) 0, BacCrypto.DERIVE_MAC, ksMac, (short) 0);
        Asserts.bytes(Hex.parse("979EC13B1CBFE9DCD01AB0FED307EAE5"), ksEnc,
                "card KS_enc (Doc 9303-11 D.3)");
        Asserts.bytes(Hex.parse("F1CB1F1FB5ADF208806B89DC579DC1F8"), ksMac,
                "card KS_mac (Doc 9303-11 D.3)");

        card42.emrtd.Iso7816Sm sm = new card42.emrtd.Iso7816Sm();
        byte[] apdu = new byte[256];
        apdu[0] = (byte) 0x0C;
        apdu[1] = (byte) 0xA4;
        apdu[2] = 0x02;
        apdu[3] = 0x0C;
        byte[] cmd = Hex.parse("8709016375432908C044F68E08BF8B92D635FF24F8");
        System.arraycopy(cmd, 0, apdu, 4, cmd.length);
        byte[] ssc = Hex.parse("887022120C06C226");
        byte[] plain = new byte[64];
        short plen = sm.unwrap(ksEnc, ksMac, ssc, apdu, (short) 4, (short) cmd.length,
                plain, (short) 0);
        Asserts.bytes(Hex.parse("011E"), java.util.Arrays.copyOf(plain, plen),
                "card SM SELECT command MAC (Doc 9303-11 D.4)");

        card42.emrtd.Iso7816Sm sm2 = new card42.emrtd.Iso7816Sm();
        byte[] ssc2 = Hex.parse("887022120C06C227");
        byte[] out = new byte[256];
        short n = sm2.wrap(ksEnc, ksMac, ssc2, new byte[0], (short) 0, (short) 0x9000,
                out, (short) 0);
        Asserts.bytes(Hex.parse("990290008E08FA855A5D4C50A8ED"),
                java.util.Arrays.copyOf(out, n),
                "card SM SELECT response MAC (Doc 9303-11 D.4)");
    }

    private static void ldsFileSystem() {
        LdsFileSystem fs = new LdsFileSystem();
        fs.select(EmrtdTags.FID_DG1);
        LdsFile dg1 = fs.getSelected();
        Asserts.check(dg1 != null && dg1.getFid() == EmrtdTags.FID_DG1, "DG1 selectable");

        // A small payload; only the file mechanics matter here.
        byte[] content = Hex.parse("61585F1F5850");
        dg1.set(content, (short) 0, (short) content.length);
        byte[] out = new byte[16];
        short len = dg1.read((short) 0, (short) content.length, out, (short) 0);
        Asserts.eq(content.length, len, "DG1 read length");
        Asserts.bytes(content, java.util.Arrays.copyOf(out, content.length), "DG1 read content");

        final LdsFileSystem fs2 = new LdsFileSystem();
        Asserts.sw((short) 0x6A82, () -> fs2.select((short) 0x9999),
                "unknown FID -> 6A82");

        // Master file selection (Doc 9303-10 §3.11.3): the flat LDS1 set clears
        // the current EF, so a reader can SELECT MF then SELECT 011C to read
        // EF.CardAccess before selecting the eMRTD application.
        fs.select(EmrtdTags.FID_DG1);
        fs.selectMf();
        Asserts.check(fs.getSelected() == null, "SELECT MF clears the current EF");
        fs.select(EmrtdTags.FID_CARD_ACCESS);
        Asserts.check(fs.getSelected() != null
                && fs.getSelected().getFid() == EmrtdTags.FID_CARD_ACCESS,
                "EF.CardAccess selectable after SELECT MF");

        // Short EF identifier lookup (Doc 9303-10 §4.7/Table 38: SFI = low 5
        // bits of the FID); backs the mandatory SFI READ BINARY form.
        Asserts.check(fs.getBySfi((short) 0x01) == dg1, "DG1 resolvable by SFI 0x01");
        Asserts.check(fs.getBySfi((short) 0x10) != null
                && fs.getBySfi((short) 0x10).getFid() == EmrtdTags.FID_DG16,
                "DG16 resolvable by SFI 0x10");
        Asserts.check(fs.getBySfi((short) 0x1E) != null
                && fs.getBySfi((short) 0x1E).getFid() == EmrtdTags.FID_COM,
                "EF.COM resolvable by SFI 0x1E");
        Asserts.check(fs.getBySfi((short) 0x1C) != null
                && fs.getBySfi((short) 0x1C).getFid() == EmrtdTags.FID_CVCA,
                "EF.CVCA resolvable by SFI 0x1C");
        Asserts.check(fs.getBySfi((short) 0x1F) == null, "unknown SFI -> null");

        // ISO/IEC 7816-4 §6.1.2: a valid SFI READ BINARY sets the current EF.
        Asserts.check(fs.selectBySfi((short) 0x1E) == fs.getSelected()
                && fs.getSelected().getFid() == EmrtdTags.FID_COM,
                "SFI read sets the current EF");
        Asserts.check(fs.selectBySfi((short) 0x1F) == null
                && fs.getSelected().getFid() == EmrtdTags.FID_COM,
                "unknown SFI leaves the current EF unchanged");
    }

    /**
     * Active Authentication uses ISO/IEC 9796-2 Digital Signature Scheme 1 with
     * M = RND.IC || RND.IFD (Doc 9303-11 §6.1.2.2).  The known-answer vector was
     * produced with an independent BouncyCastle {@code ISO9796d2Signer}
     * (implicit trailer, SHA-1) on a fixed 1024-bit key and RND.IC.
     */
    private static void activeAuthentication() throws Exception {
        byte[] katMod = Hex.parse(KAT_MOD);
        byte[] katExp = Hex.parse(KAT_EXP);
        byte[] katRndIc = Hex.parse(KAT_RND_IC);
        byte[] katRndIfd = Hex.parse("0102030405060708");
        byte[] katSig = Hex.parse(KAT_SIG);

        AaCrypto kat = new AaCrypto((short) 1024, AaCrypto.AA_SHA1);
        kat.setPrivateKey(katMod, (short) 0, (short) katMod.length,
                katExp, (short) 0, (short) katExp.length);
        Asserts.check(kat.isInitialized(), "AA KAT private key initialized");
        byte[] katOut = new byte[128];
        short katLen = kat.sign(katRndIc, (short) 0, katRndIfd, (short) 0, (short) 8,
                katOut, (short) 0);
        Asserts.eq(128, katLen, "AA KAT signature length");
        Asserts.bytes(katSig, java.util.Arrays.copyOf(katOut, katLen),
                "AA ISO 9796-2 Scheme 1 known answer (BouncyCastle)");

        // Round trip on a fresh 2048-bit key: the card signs, the host recovers
        // RND.IC and checks H(RND.IC || RND.IFD) with the DG15 public key.
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();
        RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();

        AaCrypto aa = new AaCrypto((short) 2048, AaCrypto.AA_SHA1);
        byte[] mod = unsigned(priv.getModulus());
        byte[] exp = unsigned(priv.getPrivateExponent());
        aa.setPrivateKey(mod, (short) 0, (short) mod.length, exp, (short) 0, (short) exp.length);
        Asserts.check(aa.isInitialized(), "AA private key initialized");

        byte[] challenge = Hex.parse("0102030405060708");
        byte[] sig = new byte[256];
        short sigLen = aa.sign(challenge, (short) 0, (short) 8, sig, (short) 0);
        Asserts.eq(256, sigLen, "AA signature length");
        Asserts.check(ActiveAuthentication.verifySignature(pub, challenge,
                        java.util.Arrays.copyOf(sig, sigLen)),
                "AA signature recovers and verifies with the DG15 public key");

        // Negative: the recovered hash binds the exact RND.IFD.
        Asserts.check(!ActiveAuthentication.verifySignature(pub, Hex.parse("0102030405060709"),
                        java.util.Arrays.copyOf(sig, sigLen)),
                "AA signature rejects a different challenge");
    }

    // BouncyCastle ISO9796d2Signer KAT (1024-bit key, SHA-1, M = RND.IC || RND.IFD).
    private static final String KAT_MOD =
            "8B3341E2FFE36D2EF95F5D2447BFB6CABAE0A88C250683D0553AD87672541816" +
            "D2B92203D3ABBFC96D0DEAF8EBB9FD0D9F2FEA572071C1F26BB1AB6FD519E6BB" +
            "C04533772F43D25A20A328F9FB95A828C6E16AEA1EBB15B988E68EE1ED26D833" +
            "5A405277BB2C6B385AA9D52EE9279A9338F3A22D229749CA5491487FCF96F587";
    private static final String KAT_EXP =
            "26AAD569964579C5EBB5C6ECD6157654787701BAF46A0BE1AA5B4F580FC8366C" +
            "D89A5ECD8B56114F85C0B0FDF69552AB1F0633658278B7347D1FFC8C7338DFB3" +
            "EC289E2A382E13CC4C7307811A8A3EDFA31D62ED0E87FE61E05C886A261E4DFF" +
            "6A962A328BDB49751174047239B1F1BAB76581260C84693039BD5530C1AED679";
    private static final String KAT_RND_IC =
            "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20" +
            "2122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40" +
            "4142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60" +
            "6162636465666768696A";
    private static final String KAT_SIG =
            "64640E5566F5284B75E51A8112AA8088C9F68CB0A50431600EA8FCC70FBD0720" +
            "B4157367568566911B92E6809B9C05D7CDE00B9E2C03B63EAB054FE3BF4BD694" +
            "9DFA5B0ABB445DBAE8B5D17FDB67E754A208A2EC60CDD1858B70BA6239182F44" +
            "12476EF789C583E0D7CC2B766FAD40CD21A17055845A01FA144EBD9D3E109210";

    /** Big-endian magnitude without a leading zero byte (BigInteger.toByteArray). */
    private static byte[] unsigned(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            return java.util.Arrays.copyOfRange(raw, 1, raw.length);
        }
        return raw;
    }
}
