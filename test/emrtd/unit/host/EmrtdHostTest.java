package card42.test;

import java.io.ByteArrayOutputStream;

import card42.host.common.codec.DerWriter;
import card42.host.common.codec.TlvWriter;
import card42.host.common.crypto.P256;
import card42.host.common.util.Hex;
import card42.host.emrtd.access.Bac;
import card42.host.emrtd.access.Iso7816Sm;
import card42.host.emrtd.access.MrzKeySeed;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.aa.ActiveAuthentication;
import card42.host.emrtd.lds.Com;
import card42.host.emrtd.lds.Dg1;
import card42.host.emrtd.lds.Dg15;
import card42.host.emrtd.lds.Dg2;
import card42.host.emrtd.lds.LdsSecurityObject;
import card42.host.emrtd.perso.Dg2Builder;
import card42.host.emrtd.perso.LdsScript;
import card42.host.emrtd.report.PassportReport;

/**
 * Pure-JVM tests for the host eMRTD modules: the MRZ key
 * seed and BAC key derivation against the ICAO Doc 9303-11 sample, and the
 * DG1/DG15/COM parsers against constructed objects.
 */
final class EmrtdHostTest {

    private static final String LINE1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    private static final String LINE2 = "L898902C<3UTO6908061F9406236ZE184226B<<<<<10";

    private EmrtdHostTest() {
    }

    static void run() throws Exception {
        System.out.println("EmrtdHost");
        mrzAndBacKeys();
        bacSessionVectors();
        dg1Parsing();
        dg1Layouts();
        dg15Parsing();
        comParsing();
        comTruncatedTag();
        ldsSecurityObjectVersion();
        paceOidValidation();
        dg2AndScript();
        p256();
        paceKdf();
    }

    /**
     * PACE KDF (BSI TR-03110-3 A.2.3 defines the KDF only, with no published
     * test vector): KDF(x, c) = SHA-1(x || 00 00 00 c), 16 bytes; 3DES keys get
     * odd DES parity, AES keys do not.  These values are computed from that
     * definition, not BSI known answers; see TODO.emrtd.md T5.1.
     */
    private static void paceKdf() throws Exception {
        byte[] seed = Pace.keySeed("L898902C<", "690806", "940623");
        Asserts.bytes(Hex.parse("239AB9CB282DAF66231DC5A4DF6BFBAEDF477565"), seed,
                "PACE key seed = SHA-1(MRZ_info)");
        Asserts.bytes(Hex.parse("313233343536"), Pace.canKeySeed("123456"),
                "PACE password encoding f(CAN) is the raw ASCII CAN");
        Asserts.bytes(Hex.parse("591468CDA83D65219CCCB8560233600F"),
                Pace.kdf(Pace.canKeySeed("123456"), 3, true),
                "PACE CAN K_pi = SHA-1(CAN || 00 00 00 03)");
        Asserts.bytes(Hex.parse("7CF7B5706BBC94CD58E6D3549D3701C8"),
                Pace.kdf(seed, 3, false), "PACE K_pi 3DES (parity adjusted)");
        Asserts.bytes(Hex.parse("7DF6B4716ABD95CC58E7D2559D3600C8"),
                Pace.kdf(seed, 3, true), "PACE K_pi AES");
        byte[] x = new byte[32];
        for (int i = 0; i < 32; i++) {
            x[i] = (byte) i;
        }
        Asserts.bytes(Hex.parse("A98FFB7CAEF3BD518FB7BC1B6CC89DBD"),
                Pace.kdf(x, 1, true), "PACE K_enc AES");
        Asserts.bytes(Hex.parse("E6B6E6B5E405EB5E6FFB080C390C2CD8"),
                Pace.kdf(x, 2, true), "PACE K_mac AES");
    }

    /** Known-answer tests for the self-written P-256 arithmetic (H7.1). */
    private static void p256() {
        P256.Point g = P256.generator();
        Asserts.check(P256.isOnCurve(g), "P-256 generator on curve");
        Asserts.check(P256.scalarMult(java.math.BigInteger.ONE, g).x.equals(P256.GX)
                && P256.scalarMult(java.math.BigInteger.ONE, g).y.equals(P256.GY),
                "1*G = G");

        P256.Point twoG = P256.scalarMult(java.math.BigInteger.valueOf(2), g);
        Asserts.check(twoG.x.equals(new java.math.BigInteger(
                        "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978", 16))
                && twoG.y.equals(new java.math.BigInteger(
                        "07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1", 16)),
                "2*G known answer");
        Asserts.check(P256.add(g, g).x.equals(twoG.x) && P256.add(g, g).y.equals(twoG.y),
                "G + G = 2*G");

        Asserts.check(P256.scalarMult(P256.N, g).infinity, "n*G = infinity");
        P256.Point negG = P256.scalarMult(P256.N.subtract(java.math.BigInteger.ONE), g);
        Asserts.check(negG.x.equals(P256.GX)
                && negG.y.equals(P256.P.subtract(P256.GY)), "(n-1)*G = -G");
        Asserts.check(P256.add(g, negG).infinity, "G + (-G) = infinity");

        P256.Point p = P256.scalarMult(new java.math.BigInteger("1234567890"), g);
        P256.Point q = P256.decode(P256.encode(p));
        Asserts.check(p.x.equals(q.x) && p.y.equals(q.y), "P-256 encode/decode round trip");

        // A received point must be a valid affine P-256 point (BSI TR-03110-3
        // A.3.4.1): an off-curve point, an unreduced coordinate and a bad
        // encoding are all rejected before any ECDH is performed.
        byte[] offCurve = P256.encode(p);
        offCurve[64] ^= 0x01;
        Asserts.rejects(() -> P256.decode(offCurve), "P-256 off-curve point rejected");

        byte[] unreduced = new byte[65];
        unreduced[0] = 0x04;
        copyFixed(P256.P, unreduced, 1);
        Asserts.rejects(() -> P256.decode(unreduced), "P-256 unreduced coordinate rejected");

        Asserts.rejects(() -> P256.decode(new byte[64]), "P-256 bad encoding rejected");
    }

    /** Big-endian 32-byte copy of a non-negative value (test helper). */
    private static void copyFixed(java.math.BigInteger value, byte[] out, int off) {
        byte[] raw = value.toByteArray();
        int start = raw.length > 32 ? raw.length - 32 : 0;
        int len = raw.length - start;
        System.arraycopy(raw, start, out, off + 32 - len, len);
    }

    /**
     * ICAO Doc 9303-11 Appendix D.3/D.4 worked example: session key derivation
     * and secure-messaging MACs.  These catch the two interop bugs that only
     * show up against a conformant eMRTD (the simulator's card and host shared
     * the same mistake).
     */
    private static void bacSessionVectors() throws Exception {
        byte[] kifd = Hex.parse("0B795240CB7049B01C19B33E32804F0B");
        byte[] kic = Hex.parse("0B4F80323EB3191CB04970CB4052790B");

        byte[] seed = Bac.sessionSeed(kifd, kic);
        Asserts.bytes(Hex.parse("0036D272F5C350ACAC50C3F572D23600"), seed,
                "BAC session seed = K_IFD XOR K_IC");
        byte[] ksEnc = Bac.deriveKey(seed, 1);
        byte[] ksMac = Bac.deriveKey(seed, 2);
        Asserts.bytes(Hex.parse("979EC13B1CBFE9DCD01AB0FED307EAE5"), ksEnc,
                "BAC KS_enc (Doc 9303-11 D.3)");
        Asserts.bytes(Hex.parse("F1CB1F1FB5ADF208806B89DC579DC1F8"), ksMac,
                "BAC KS_mac (Doc 9303-11 D.3)");

        Iso7816Sm sm = new Iso7816Sm(ksEnc, ksMac, 0x887022120C06C226L);
        byte[] select = sm.wrapCommand(0x00, 0xA4, 0x02, 0x0C, Hex.parse("011E"), 0);
        Asserts.bytes(Hex.parse("8709016375432908C044F68E08BF8B92D635FF24F8"), select,
                "SM SELECT EF.COM command MAC (Doc 9303-11 D.4)");

        short[] sw = new short[1];
        sm.unwrapResponse(Hex.parse("990290008E08FA855A5D4C50A8ED"), sw);
        Asserts.eq(0x9000, sw[0] & 0xFFFF, "SM SELECT EF.COM response MAC");

        byte[] read = sm.wrapCommand(0x00, 0xB0, 0x00, 0x00, null, 4);
        Asserts.bytes(Hex.parse("9701048E08ED6705417E96BA55"), read,
                "SM READ BINARY command MAC (Doc 9303-11 D.4)");
    }

    private static void dg2AndScript() throws Exception {
        byte[] bdb = Hex.parse("010203FFD8FFE000104A4649460001");
        byte[] dg2 = tlv(0x75, tlv(0x7F61, tlv(0x7F60, bdb)));
        Dg2 parsed = Dg2.parse(dg2);
        Asserts.check(parsed.image != null && (parsed.image[0] & 0xFF) == 0xFF
                && (parsed.image[1] & 0xFF) == 0xD8, "DG2 extracts the JPEG image");

        // The personalization builder wraps the input portrait in a CBEFF/ISO
        // 19794-5 record; the parser must recover exactly that JPEG.  The
        // portrait is cropped to the portrait ratio and scaled so its longest
        // side is MAX_SIDE, so the DG2 is a realistic multi-kilobyte image.
        java.io.File portraitFile = new java.io.File(Dg2Builder.DEFAULT_PORTRAIT);
        java.awt.image.BufferedImage face = Dg2Builder.portrait(portraitFile);
        Asserts.eq(Dg2Builder.MAX_SIDE,
                Math.max(face.getWidth(), face.getHeight()),
                "portrait longest side");
        byte[] built = Dg2Builder.buildFromImage(portraitFile);
        Asserts.check(built.length > 4096,
                "portrait DG2 exceeds the old single personalization buffer");
        Dg2 builtParsed = Dg2.parse(built);
        Asserts.check(builtParsed.image != null
                        && (builtParsed.image[0] & 0xFF) == 0xFF
                        && (builtParsed.image[1] & 0xFF) == 0xD8,
                "DG2 carries the portrait JPEG");
        Asserts.check(java.util.Arrays.equals(Dg2Builder.faceJpeg(portraitFile), builtParsed.image),
                "Dg2Builder round-trips the JPEG");
        Asserts.check(PassportReport.text(null, null, null, builtParsed).contains("Face image"),
                "report shows the face image");

        LdsScript script = LdsScript.parse(
                "@doc L898902C<\n@dob 690806\n@doe 940623\n@dg 1 615B\n");
        Asserts.eq("L898902C<", script.documentNumber(), "LdsScript document number");
        Asserts.check(script.dataGroups().containsKey(1), "LdsScript data group 1");
    }

    private static void mrzAndBacKeys() {
        byte[] info = MrzKeySeed.mrzInformation("L898902C<", "690806", "940623");
        Asserts.eq(24, info.length, "MRZ information length");
        byte[] seed = MrzKeySeed.seed(info);
        Asserts.bytes(Hex.parse("239AB9CB282DAF66231DC5A4DF6BFBAE"), seed, "host K_seed");
        Asserts.bytes(Hex.parse("AB94FDECF2674FDFB9B391F85D7F76F2"),
                Bac.deriveKey(seed, 1), "host K_enc");
        Asserts.bytes(Hex.parse("7962D9ECE03D1ACD4C76089DCE131543"),
                Bac.deriveKey(seed, 2), "host K_mac");
        Asserts.eq(3, MrzKeySeed.checkDigit("L898902C<"), "host document check digit");
    }

    private static void dg1Parsing() {
        byte[] mrz = (LINE1 + LINE2).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        ByteArrayOutputStream dg1 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(dg1, 0x5F1F, mrz);
        byte[] wrapped = tlv(0x61, dg1.toByteArray());

        Dg1 parsed = Dg1.parse(wrapped);
        Asserts.eq("L898902C<", parsed.documentNumber, "DG1 document number");
        Asserts.eq("ERIKSSON", parsed.surname, "DG1 surname");
        Asserts.eq("ANNA MARIA", parsed.givenNames, "DG1 given names");
        Asserts.eq("UTO", parsed.issuingState, "DG1 issuing state");
        Asserts.eq("690806", parsed.dateOfBirth, "DG1 date of birth");
        Asserts.eq("940623", parsed.dateOfExpiry, "DG1 date of expiry");
        Asserts.eq("F", parsed.sex, "DG1 sex");
    }

    private static void dg1Layouts() {
        // TD1: three 30-character lines.
        String td1 = pad("I<UTOD231458907", 30) + pad("7408122F1204159UTO", 30)
                + pad("ERIKSSON<<ANNA<MARIA", 30);
        Dg1 parsed1 = Dg1.parse(mrzDg1(td1));
        Asserts.eq("UTO", parsed1.issuingState, "TD1 issuing state");
        Asserts.eq("D23145890", parsed1.documentNumber, "TD1 document number");
        Asserts.eq("ERIKSSON", parsed1.surname, "TD1 surname");
        Asserts.eq("ANNA MARIA", parsed1.givenNames, "TD1 given names");
        Asserts.eq("740812", parsed1.dateOfBirth, "TD1 date of birth");
        Asserts.eq("F", parsed1.sex, "TD1 sex");
        Asserts.eq("120415", parsed1.dateOfExpiry, "TD1 date of expiry");
        Asserts.eq("UTO", parsed1.nationality, "TD1 nationality");

        // TD2: two 36-character lines.
        String td2 = pad("I<UTOERIKSSON<<ANNA<MARIA", 36)
                + pad("L898902C<3UTO6908061F9406236", 36);
        Dg1 parsed2 = Dg1.parse(mrzDg1(td2));
        Asserts.eq("L898902C<", parsed2.documentNumber, "TD2 document number");
        Asserts.eq("ERIKSSON", parsed2.surname, "TD2 surname");
        Asserts.eq("ANNA MARIA", parsed2.givenNames, "TD2 given names");
        Asserts.eq("690806", parsed2.dateOfBirth, "TD2 date of birth");
        Asserts.eq("F", parsed2.sex, "TD2 sex");
        Asserts.eq("940623", parsed2.dateOfExpiry, "TD2 date of expiry");
    }

    private static byte[] mrzDg1(String mrz) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x5F1F, mrz.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return tlv(0x61, body.toByteArray());
    }

    private static String pad(String s, int length) {
        StringBuilder b = new StringBuilder(s);
        while (b.length() < length) {
            b.append('<');
        }
        return b.toString();
    }

    private static void dg15Parsing() {
        byte[] modulus = Hex.parse("C5B7D8E1F0A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C"
                + "5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D"
                + "6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E"
                + "7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F");
        byte[] subjectPublicKeyInfo = DerWriter.sequence(
                DerWriter.sequence(DerWriter.oid("1.2.840.113549.1.1.1"),
                        DerWriter.nullValue()),
                DerWriter.tlv(0x03, DerWriter.concat(new byte[] { 0x00 },
                        DerWriter.sequence(
                                DerWriter.integer(new java.math.BigInteger(1, modulus)),
                                DerWriter.integer(65537)))));
        byte[] wrapped = tlv(0x6F, subjectPublicKeyInfo);

        Dg15 parsed = Dg15.parse(wrapped);
        Asserts.check(parsed.modulus.signum() > 0, "DG15 modulus present");
        Asserts.eq(65537, parsed.exponent.intValue(), "DG15 exponent");

        // ECDSA DG15 + ECDSA Active Authentication (M = RND.IFD, plain r||s).
        try {
            java.security.KeyPairGenerator generator =
                    java.security.KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
            java.security.KeyPair ec = generator.generateKeyPair();
            Dg15 ecDg15 = Dg15.parse(tlv(0x6F, ec.getPublic().getEncoded()));
            Asserts.check(ecDg15.ecdsa, "DG15 detects an ECDSA key");

            byte[] challenge = Hex.parse("0102030405060708");
            java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA");
            signer.initSign(ec.getPrivate());
            signer.update(challenge);
            byte[] plain = derToPlainEcdsa(signer.sign(), 32);
            Asserts.check(ActiveAuthentication.verifyEcdsa(ec.getPublic(), challenge, plain, "SHA-256"),
                    "ECDSA AA verifies over RND.IFD");
            Asserts.check(!ActiveAuthentication.verifyEcdsa(ec.getPublic(),
                            Hex.parse("0102030405060709"), plain, "SHA-256"),
                    "ECDSA AA rejects a different challenge");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Converts a DER ECDSA signature to the plain r||s form (TR-03111). */
    private static byte[] derToPlainEcdsa(byte[] der, int coordinate) {
        card42.host.common.codec.Der.Tlv sequence = card42.host.common.codec.Der.read(der, 0);
        java.util.List<card42.host.common.codec.Der.Tlv> parts =
                card42.host.common.codec.Der.children(der, sequence);
        byte[] out = new byte[2 * coordinate];
        copyFixed(new java.math.BigInteger(1,
                card42.host.common.codec.Der.value(der, parts.get(0))), out, 0, coordinate);
        copyFixed(new java.math.BigInteger(1,
                card42.host.common.codec.Der.value(der, parts.get(1))), out, coordinate, coordinate);
        return out;
    }

    private static void copyFixed(java.math.BigInteger value, byte[] out, int off, int width) {
        byte[] raw = value.toByteArray();
        int start = raw.length > width ? raw.length - width : 0;
        int len = raw.length - start;
        System.arraycopy(raw, start, out, off + width - len, len);
    }

    private static void comParsing() {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x5F01, "0107".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        TlvWriter.writeTlv(body, 0x5F36, "040001".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        TlvWriter.writeTlv(body, 0x5C, Hex.parse("6175"));
        byte[] wrapped = tlv(0x60, body.toByteArray());

        Com parsed = Com.parse(wrapped);
        Asserts.eq("0107", parsed.ldsVersion, "COM LDS version");
        Asserts.eq("040001", parsed.unicodeVersion, "COM unicode version");
        Asserts.eq(2, parsed.dataGroupTags.length, "COM data group count");
        Asserts.eq(0x61, parsed.dataGroupTags[0], "COM first data group");
        Asserts.check(PassportReport.text(Dg1.parse(
                tlv(0x61, tlv(0x5F1F, (LINE1 + LINE2)
                        .getBytes(java.nio.charset.StandardCharsets.US_ASCII)))),
                parsed, null, null).contains("L898902C<"), "report contains document number");
    }

    /** A truncated two-byte tag in the 5C list must not overrun the buffer. */
    private static void comTruncatedTag() {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x5C, new byte[] { (byte) 0x9F });
        Com parsed = Com.parse(tlv(0x60, body.toByteArray()));
        Asserts.eq(0, parsed.dataGroupTags.length, "COM truncated two-byte tag ignored");
    }

    /** LDSSecurityObjectVersion is v0/v1 and gates ldsVersionInfo (§4.6.2.3). */
    private static void ldsSecurityObjectVersion() {
        Asserts.eq(0, LdsSecurityObject.parse(ldsSecurityObject(0, false)).version,
                "SOD v0 without ldsVersionInfo accepted");
        LdsSecurityObject v1 = LdsSecurityObject.parse(ldsSecurityObject(1, true));
        Asserts.eq(1, v1.version, "SOD v1 accepted");
        Asserts.eq("0107", v1.ldsVersion, "SOD v1 LDS version");
        Asserts.eq("040001", v1.unicodeVersion, "SOD v1 Unicode version");
        Asserts.rejects(() -> LdsSecurityObject.parse(ldsSecurityObject(1, false)),
                "SOD v1 without ldsVersionInfo rejected");
        Asserts.rejects(() -> LdsSecurityObject.parse(ldsSecurityObject(0, true)),
                "SOD v0 with ldsVersionInfo rejected");
        Asserts.rejects(() -> LdsSecurityObject.parse(ldsSecurityObject(2, false)),
                "SOD unsupported version rejected");
    }

    private static byte[] ldsSecurityObject(int version, boolean versionInfo) {
        byte[] alg = DerWriter.sequence(DerWriter.oid("2.16.840.1.101.3.4.2.1"),
                DerWriter.nullValue());
        byte[] entry = DerWriter.sequence(DerWriter.integer(1),
                DerWriter.octetString(new byte[32]));
        if (versionInfo) {
            return DerWriter.sequence(DerWriter.integer(version), alg,
                    DerWriter.sequence(entry),
                    DerWriter.sequence(
                            DerWriter.tlv(0x13, "0107".getBytes(
                                    java.nio.charset.StandardCharsets.US_ASCII)),
                            DerWriter.tlv(0x13, "040001".getBytes(
                                    java.nio.charset.StandardCharsets.US_ASCII))));
        }
        return DerWriter.sequence(DerWriter.integer(version), alg, DerWriter.sequence(entry));
    }

    /** PACE accepts only ECDH generic mapping with 3DES/AES-128 (BSI A.3/B.1). */
    private static void paceOidValidation() {
        byte[] seed = new byte[20];
        byte[] dhGm = { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x01 };
        byte[] ecdhAes256 = { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04 };
        Asserts.rejects(() -> callPace(seed, dhGm), "PACE rejects DH generic mapping");
        Asserts.rejects(() -> callPace(seed, ecdhAes256), "PACE rejects AES-256 profile");
    }

    private static void callPace(byte[] seed, byte[] oid) {
        try {
            Pace.authenticate(null, seed, oid);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, value);
        return out.toByteArray();
    }
}
