package card42.host.emrtd.perso;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;

import card42.host.common.codec.DerWriter;
import card42.host.common.codec.TlvWriter;
import card42.host.common.util.Hex;
import card42.host.emrtd.access.MrzKeySeed;
import card42.host.emrtd.lds.security.SecurityInfo;
import card42.host.emrtd.ta.TaChain;

/**
 * The demo sample data of the card42 eMRTD personalization: the ICAO TD3 MRZ
 * fixtures, the deterministic DG1-DG16 data groups (DG6 reserved), the demo
 * PACE/CA/TA SecurityInfos and trust points, and the small DER/TLV and key
 * helpers they need.
 *
 * <p>It was the fixture half of {@code EmrtdPersoExporter}; separating it keeps
 * the DGI/script encoding and the CLI free of the (large) sample-data bulk.
 * This is host tooling, so the card-side heap rules do not apply.
 *
 * @author card42
 */

final class SampleData {

    /** The ICAO sample TD3 MRZ (Doc 9303-11 sample). */
    static final String LINE1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    static final String LINE2 = "L898902C<3UTO6908061F9406236ZE184226B<<<<<10";
    static final String DOCUMENT_NUMBER = "L898902C<";
    static final String DATE_OF_BIRTH = "690806";
    static final String DATE_OF_EXPIRY = "940623";
    /** Demo Card Access Number for PACE with password reference 0x02. */
    static final String CARD_ACCESS_NUMBER = "123456";

    /** Demo pre-personalization date, earlier than the demo certificates' Effective Date. */
    static final String TA_CURRENT_DATE = "240101";

    /** DGI FF0A value: RSA ISO/IEC 9796-2 Scheme 1 + SHA-1 (trailer option 1). */
    static final byte AA_ALGORITHM_SHA1 = (byte) 0x01;
    /** DGI FF0A value: RSA ISO/IEC 9796-2 Scheme 1 + SHA-256 (trailer option 2). */
    static final byte AA_ALGORITHM_SHA256 = (byte) 0x02;
    /** DGI FF0A value: ECDSA-SHA-256 (P-256, plain r||s). */
    static final byte AA_ALGORITHM_ECDSA = (byte) 0x03;

    private SampleData() {
    }

    // --- LDS1 data groups ----------------------------------------------------

    /** All deterministic demo data groups (DG1..DG16 except the reserved DG6). */
    static Map<Integer, byte[]> dataGroups(File portrait) throws Exception {
        Map<Integer, byte[]> dgs = new LinkedHashMap<Integer, byte[]>();
        dgs.put(1, dg1());
        dgs.put(2, dg2(portrait));
        dgs.put(3, dg3());
        dgs.put(4, dg4());
        dgs.put(5, dg5());
        dgs.put(7, dg7());
        dgs.put(8, dg8());
        dgs.put(9, dg9());
        dgs.put(10, dg10());
        dgs.put(11, dg11());
        dgs.put(12, dg12());
        dgs.put(13, dg13());
        dgs.put(16, dg16());
        // DG14/DG15 depend on the CA/AA keys and are added by the caller.
        return dgs;
    }

    /** A fresh P-256 (secp256r1) key pair. */
    static KeyPair generateP256Key() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    /**
     * EF.CardAccess SecurityInfos: PACE ECDH-GM 3DES + AES-128 and CA ECDH
     * 3DES + AES-128 always; for the ECDSA AA variant also
     * {@code ActiveAuthenticationInfo} (ICAO Doc 9303-11 §9.2.4, which is
     * REQUIRED only for ECDSA AA).
     */
    static byte[] cardAccessInfos(String aaAlgorithm) {
        byte[] set = DerWriter.set(
                paceInfo(SecurityInfo.ID_PACE_ECDH_GM_3DES),
                paceInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_128),
                caInfo(SecurityInfo.ID_CA_ECDH_3DES),
                caInfo(SecurityInfo.ID_CA_ECDH_AES_128),
                taInfo());
        if ("ecdsa".equalsIgnoreCase(aaAlgorithm)) {
            set = DerWriter.set(
                    paceInfo(SecurityInfo.ID_PACE_ECDH_GM_3DES),
                    paceInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_128),
                    caInfo(SecurityInfo.ID_CA_ECDH_3DES),
                    caInfo(SecurityInfo.ID_CA_ECDH_AES_128),
                    aaInfo("0.4.0.127.0.7.1.1.4.1.3"), // id-ecdsa-plain-SHA256
                    taInfo());
        }
        return set;
    }

    /** TerminalAuthenticationInfo SEQUENCE { id-TA, version 1 } (ICAO Doc 9303-11 §9.2.8). */
    static byte[] taInfo() {
        return DerWriter.sequence(DerWriter.oid(SecurityInfo.ID_TA), DerWriter.integer(1));
    }

    /** ActiveAuthenticationInfo SEQUENCE { id-AA, version 1, signatureAlgorithm } (§9.2.4). */
    static byte[] aaInfo(String signatureAlgorithmOid) {
        return DerWriter.sequence(DerWriter.oid(SecurityInfo.ID_AA), DerWriter.integer(1),
                DerWriter.oid(signatureAlgorithmOid));
    }

    /**
     * The demo ECDSA CVCA trust point used by {@link TaChain#demo}: the CVCA
     * public key W(65) || CAR || Effective Date || relative authorization.
     */
    static LdsScript.TrustPoint demoTrustPoint() {
        TaChain.Chain chain = TaChain.demo(new java.security.SecureRandom());
        byte[] w = chain.cvca.ecPublicKey();
        byte[] car = chain.cvca.certificateHolderReference().encode();
        return new LdsScript.TrustPoint(w, new String(car,
                java.nio.charset.StandardCharsets.US_ASCII), TA_CURRENT_DATE,
                new byte[] { 0x03, 0x0F, 0x0F, 0x0F }, false);
    }

    /** The demo RSA-PSS CVCA trust point used by {@link TaChain#demoRsa}. */
    static LdsScript.TrustPoint demoRsaTrustPoint() {
        return new LdsScript.TrustPoint(TaChain.demoRsaModulus(), TaChain.demoRsaExponent(),
                TaChain.DEMO_RSA_CAR, TA_CURRENT_DATE, new byte[] { 0x03, 0x0F, 0x0F, 0x0F },
                false);
    }

    /** A demo Additional Biometrics EF.Biometrics1 content (transparent EF 0201). */
    static byte[] sampleBiometric() {
        return Hex.parse("7F611002010102020304050608010A0B0C0D0E0F10");
    }

    static KeyPair generateAaKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    static byte[] dg1() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, 0x5F1F, (LINE1 + LINE2)
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return tlv(0x61, out.toByteArray());
    }

    /**
     * DG2 = {@code 75 { 7F61 { 7F60 { ISO 19794-5 face record } } }} around the
     * portrait input image ({@link Dg2Builder}).
     */
    static byte[] dg2(File portrait) throws Exception {
        return Dg2Builder.buildFromImage(portrait);
    }

    /** DG3 = {@code 63 { 7F61 { 7F60 { 5F2E <fingerprint> } } }} (fingerprints). */
    static byte[] dg3() {
        byte[] bir = tlv(0x7F60, tlv(0x5F2E,
                Hex.parse("0102030405060708090A0B0C0D0E0F1011121314")));
        return tlv(0x63, tlv(0x7F61, bir));
    }

    /** DG4 = {@code 76 { 7F61 { 7F60 { 5F2E <iris> } } }} (irises). */
    static byte[] dg4() {
        byte[] bir = tlv(0x7F60, tlv(0x5F2E,
                Hex.parse("2122232425262728292A2B2C2D2E2F30")));
        return tlv(0x76, tlv(0x7F61, bir));
    }

    /** DG5 = {@code 65 { 5F2E <portrait> }} (displayed portrait). */
    static byte[] dg5() {
        return tlv(0x65, tlv(0x5F2E, Hex.parse("FFD8FFE000104A4649460001")));
    }

    /** DG7 = {@code 67 { 7F61 { 5F2E <signature image> } }} (signature). */
    static byte[] dg7() {
        return tlv(0x67, tlv(0x7F61, tlv(0x5F2E, Hex.parse("FFD8FFE000104A4649460002"))));
    }

    /** DG8 = {@code 68 { 5F2B..5F2E }} (data features). */
    static byte[] dg8() {
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        TlvWriter.writeTlv(inner, 0x5F2B, Hex.parse("01010101"));
        TlvWriter.writeTlv(inner, 0x5F2C, Hex.parse("02020202"));
        TlvWriter.writeTlv(inner, 0x5F2D, Hex.parse("03030303"));
        TlvWriter.writeTlv(inner, 0x5F2E, Hex.parse("04040404"));
        return tlv(0x68, inner.toByteArray());
    }

    /** DG9 = {@code 69 { 5F2B <structure feature points> }}. */
    static byte[] dg9() {
        return tlv(0x69, tlv(0x5F2B, Hex.parse("000102030405060708090A0B")));
    }

    /** DG10 = {@code 6A { 5F2B <substance feature points> }}. */
    static byte[] dg10() {
        return tlv(0x6A, tlv(0x5F2B, Hex.parse("101112131415161718191A1B")));
    }

    /**
     * DG11 = {@code 6B { 5C <tag list> 5F0E <full name> 5F11 <place of birth>
     * 5F42 <address> 5F12 <telephone> }} (ICAO Doc 9303-10 §4.7.11).
     */
    static byte[] dg11() {
        byte[] tags = { 0x5F, 0x0E, 0x5F, 0x11, 0x5F, 0x42, 0x5F, 0x12 };
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        TlvWriter.writeTlv(inner, 0x5C, tags);
        ascii(inner, 0x5F0E, "ERIKSSON<<ANNA<MARIA");
        ascii(inner, 0x5F11, "UTO");
        ascii(inner, 0x5F42, "UTOPIA");
        ascii(inner, 0x5F12, "+4680000000");
        return tlv(0x6B, inner.toByteArray());
    }

    /**
     * DG12 = {@code 6C { 5C <tag list> 5F19 <issuing authority> 5F26 <date of
     * issue> 5F55 <date/time of personalization> 5F56 <personalization system
     * serial> }} (ICAO Doc 9303-10 §4.7.12).
     */
    static byte[] dg12() {
        byte[] tags = { 0x5F, 0x19, 0x5F, 0x26, 0x5F, 0x55, 0x5F, 0x56 };
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        TlvWriter.writeTlv(inner, 0x5C, tags);
        ascii(inner, 0x5F19, "UTO");
        ascii(inner, 0x5F26, "20260101");
        ascii(inner, 0x5F55, "20260101120000");
        ascii(inner, 0x5F56, "card42");
        return tlv(0x6C, inner.toByteArray());
    }

    /** DG13 = {@code 6D { 5F2B <optional details> }} (ICAO Doc 9303-10 §4.7.13). */
    static byte[] dg13() {
        return tlv(0x6D, tlv(0x5F2B, Hex.parse("2021222324252627")));
    }

    /** DG16 = {@code 70 { 61 { 5F0E <name> } }} (persons to notify, §4.7.16). */
    static byte[] dg16() {
        return tlv(0x70, tlv(0x61, tlv(0x5F0E,
                "UTOPIA<CONTACT".getBytes(java.nio.charset.StandardCharsets.US_ASCII))));
    }

    /**
     * DG14 = {@code 6E { SecurityInfos }} (ICAO Doc 9303-10 §4.7.14): the same
     * DER {@code SET OF SecurityInfo} that EF.CardSecurity signs.
     */
    static byte[] dg14(byte[] securityInfos) {
        return tlv(0x6E, securityInfos);
    }

    /**
     * DG15 = {@code 6F { SubjectPublicKeyInfo } } for an RSA AA key
     * (ICAO Doc 9303-11 §6.1.5).
     */
    static byte[] dg15Rsa(BigInteger modulus) {
        byte[] rsaPublicKey = DerWriter.sequence(
                DerWriter.integer(modulus),
                DerWriter.integer(BigInteger.valueOf(65537)));
        byte[] subjectPublicKey = DerWriter.tlv(0x03,
                DerWriter.concat(new byte[] { 0x00 }, rsaPublicKey));
        byte[] algorithm = DerWriter.sequence(
                DerWriter.oid("1.2.840.113549.1.1.1"),
                DerWriter.nullValue());
        return tlv(0x6F, DerWriter.sequence(algorithm, subjectPublicKey));
    }

    /** DG15 = {@code 6F { SubjectPublicKeyInfo } } for an EC AA key (RFC 5480). */
    static byte[] dg15Ec(byte[] subjectPublicKeyInfo) {
        return tlv(0x6F, subjectPublicKeyInfo);
    }

    /** Appends {@code tag || len || US-ASCII(value)} to {@code out}. */
    static void ascii(ByteArrayOutputStream out, int tag, String value) {
        TlvWriter.writeTlv(out, tag,
                value.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    static byte[] aaPrivateKey(BigInteger modulus, BigInteger privateExponent) {
        byte[] mod = unsigned(modulus);
        byte[] exp = unsigned(privateExponent);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((mod.length >> 8) & 0xFF);
        out.write(mod.length & 0xFF);
        out.write(mod, 0, mod.length);
        out.write((exp.length >> 8) & 0xFF);
        out.write(exp.length & 0xFF);
        out.write(exp, 0, exp.length);
        return out.toByteArray();
    }

    static byte aaAlgorithmByte(String algorithm) {
        if ("ecdsa".equalsIgnoreCase(algorithm)) {
            return AA_ALGORITHM_ECDSA;
        }
        return "sha256".equalsIgnoreCase(algorithm) ? AA_ALGORITHM_SHA256 : AA_ALGORITHM_SHA1;
    }

    static byte[] sha256(byte[] data) throws Exception {
        return java.security.MessageDigest.getInstance("SHA-256").digest(data);
    }

    /**
     * The 20-byte PACE key seed SHA-1(MRZ_information) (DGI FF04).
     */
    static byte[] paceSeed(String documentNumber, String dateOfBirth,
                           String dateOfExpiry) throws Exception {
        return java.security.MessageDigest.getInstance("SHA-1").digest(
                MrzKeySeed.mrzInformation(documentNumber, dateOfBirth, dateOfExpiry));
    }

    /** The PACE password encoding {@code f(CAN)} (DGI FF06, password reference 0x02). */
    static byte[] canSeed(String can) {
        return can.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, value);
        return out.toByteArray();
    }

    static byte[] unsigned(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            return java.util.Arrays.copyOfRange(raw, 1, raw.length);
        }
        return raw;
    }

    /** ChipAuthenticationInfo SEQUENCE { OID, version 1, key id 1 } (ICAO Doc 9303-11 §9.2.5). */
    private static byte[] caInfo(String oid) {
        return DerWriter.sequence(DerWriter.oid(oid), DerWriter.integer(1),
                DerWriter.integer(1));
    }

    /** PACEInfo SEQUENCE { OID, version 2, parameterId 12 (P-256) }. */
    private static byte[] paceInfo(String oid) {
        return DerWriter.sequence(DerWriter.oid(oid), DerWriter.integer(2),
                DerWriter.integer(12));
    }
}
