package card42.host.emrtd.perso;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;

import card42.host.common.codec.DerWriter;
import card42.host.common.codec.TlvWriter;
import card42.host.common.util.Hex;
import card42.host.emrtd.access.MrzKeySeed;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.lds.SecurityInfo;

/**
 * Builds the GP STORE DATA DGI sequence that personalizes a card42-emrtd LDS1
 * instance (H5.2/H5.4).  The DGI number is the target FID; the project DGIs
 * carry the key material: {@code FF01} = BAC K_seed, {@code FF02} = the AA
 * private key (modulus length || modulus || exponent length || exponent),
 * {@code FF03} = the Chip Authentication P-256 scalar, {@code FF04} =
 * SHA-1(MRZ_information) and {@code FF06} = raw CAN PACE password encodings,
 * and {@code FF05} = the master-file EF.CardSecurity.  The card's
 * {@code EmrtdApplet.applyPerso} consumes exactly this sequence.
 *
 * <p>{@code main} emits {@code <AID> <hex>} lines for GPPro
 * {@code --personalize}.  With {@code -script=<path>} it personalizes the
 * documents of an {@link LdsScript} (A2); without it, it uses the built-in
 * ICAO Doc 9303-11 sample passport and a freshly generated RSA-2048 AA key.
 * {@code -emit} prints the built-in sample in script form.
 */
public final class EmrtdPersoExporter {

    /** The ICAO sample TD3 MRZ (Doc 9303-11 sample). */
    public static final String LINE1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    public static final String LINE2 = "L898902C<3UTO6908061F9406236ZE184226B<<<<<10";
    public static final String DOCUMENT_NUMBER = "L898902C<";
    public static final String DATE_OF_BIRTH = "690806";
    public static final String DATE_OF_EXPIRY = "940623";
    /** Demo Card Access Number for PACE with password reference 0x02. */
    public static final String CARD_ACCESS_NUMBER = "123456";

    private static final String DEFAULT_DSC = "perso/emrtd/dsc.crt";
    private static final String DEFAULT_DSC_KEY = "perso/emrtd/dsc.key";

    /** LDS1 project DGI: Chip Authentication static P-256 private scalar. */
    private static final int DGI_CA_KEY = 0xFF03;
    /** LDS1 project DGI: master-file EF.CardSecurity CMS SignedData. */
    private static final int DGI_CARD_SECURITY = 0xFF05;
    /** LDS1 project DGI: PACE password encoding f(CAN) = raw CAN (ref 0x02). */
    private static final int DGI_PACE_CAN_SEED = 0xFF06;

    private EmrtdPersoExporter() {
    }

    /**
     * The complete DGI sequence for the demo passport and AA key.  The SOD is
     * built from the SHA-256 hashes of DG1, DG2, DG11, DG12, DG14 and DG15 and
     * signed by the DSC.
     */
    public static byte[] dgiSequence(KeyPair aaKey, X509Certificate dscCertificate,
                                     PrivateKey dscKey, File portrait) throws Exception {
        BigInteger modulus = ((java.security.interfaces.RSAPublicKey) aaKey.getPublic()).getModulus();
        BigInteger privateExponent = ((RSAPrivateKey) aaKey.getPrivate()).getPrivateExponent();

        byte[] dg1 = dg1();
        byte[] dg2 = dg2(portrait);
        byte[] dg11 = dg11();
        byte[] dg12 = dg12();
        byte[] dg15 = dg15(modulus);

        // Chip Authentication: the static P-256 scalar (DGI FF03) and the
        // matching master-file EF.CardSecurity (DGI FF05).  EF.CardSecurity
        // contains the EF.CardAccess SecurityInfos plus the CA public key
        // (Doc 9303-10 §3.11.4); EF.DG14 carries the same SecurityInfos
        // (Doc 9303-10 §4.7.14).
        KeyPair caKeyPair = generateP256Key();
        byte[] caScalar = unsigned(((ECPrivateKey) caKeyPair.getPrivate()).getS());
        byte[] cardAccess = cardAccessInfos();
        byte[] securityInfos = CardSecurityBuilder.securityInfos(
                caKeyPair.getPublic().getEncoded(), 1, cardAccess);
        byte[] dg14 = dg14(securityInfos);
        byte[] cardSecurity = CardSecurityBuilder.build(securityInfos, dscKey, dscCertificate);

        Map<Integer, byte[]> hashes = new LinkedHashMap<Integer, byte[]>();
        hashes.put(1, sha256(dg1));
        hashes.put(2, sha256(dg2));
        hashes.put(11, sha256(dg11));
        hashes.put(12, sha256(dg12));
        hashes.put(14, sha256(dg14));
        hashes.put(15, sha256(dg15));
        byte[] sod = SodBuilder.build(hashes, dscKey, dscCertificate);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeDgi(out, 0xFF01,
                MrzKeySeed.seed(DOCUMENT_NUMBER, DATE_OF_BIRTH, DATE_OF_EXPIRY));
        writeDgi(out, 0xFF04, paceSeed(DOCUMENT_NUMBER, DATE_OF_BIRTH, DATE_OF_EXPIRY));
        writeDgi(out, DGI_PACE_CAN_SEED, canSeed(CARD_ACCESS_NUMBER));
        writeDgi(out, LdsFileUtil.FID_DG1, dg1);
        writeDgi(out, LdsFileUtil.FID_DG2, dg2);
        writeDgi(out, LdsFileUtil.FID_DG11, dg11);
        writeDgi(out, LdsFileUtil.FID_DG12, dg12);
        writeDgi(out, LdsFileUtil.FID_DG14, dg14);
        writeDgi(out, LdsFileUtil.FID_DG15, dg15);
        // EF.CardAccess in the master file (Doc 9303-10 §3.11.3): the LDS1
        // instance advertises PACE and Chip Authentication.
        writeDgi(out, LdsFileUtil.FID_CARD_ACCESS, cardAccess);
        writeDgi(out, DGI_CA_KEY, caScalar);
        writeDgi(out, DGI_CARD_SECURITY, cardSecurity);
        // EF.COM is generated by the card's LdsCatalog data-group index.
        writeDgi(out, LdsFileUtil.FID_SOD, sod);
        writeDgi(out, 0xFF02, aaPrivateKey(modulus, privateExponent));
        return out.toByteArray();
    }

    /**
     * The DGI sequence for one script entry (A2).  The BAC seed comes from
     * {@code @doc/@dob/@doe}, every {@code @dg} becomes its EF, {@code @sod} is
     * used verbatim (or built from the DG hashes when absent), and {@code @aa}
     * carries the AA private key.
     */
    public static byte[] dgiSequence(LdsScript.Entry entry, X509Certificate dscCertificate,
                                     PrivateKey dscKey) throws Exception {
        if (entry.isLds2()) {
            return lds2Sequence(entry);
        }
        if (entry.documentNumber == null || entry.dateOfBirth == null
                || entry.dateOfExpiry == null) {
            throw new IllegalArgumentException(
                    "entry " + entry.aid + " needs @doc, @dob and @doe");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeDgi(out, 0xFF01,
                MrzKeySeed.seed(entry.documentNumber, entry.dateOfBirth, entry.dateOfExpiry));
        writeDgi(out, 0xFF04, paceSeed(entry.documentNumber, entry.dateOfBirth,
                entry.dateOfExpiry));
        if (entry.can != null) {
            writeDgi(out, DGI_PACE_CAN_SEED, canSeed(entry.can));
        }
        for (Map.Entry<Integer, byte[]> dg : entry.dataGroups.entrySet()) {
            writeDgi(out, LdsFileUtil.dgFid(dg.getKey()), dg.getValue());
        }
        // EF.CardAccess in the master file (Doc 9303-10 §3.11.3): PACE and,
        // when the entry carries CA material, Chip Authentication.
        writeDgi(out, LdsFileUtil.FID_CARD_ACCESS,
                entry.cardAccess != null ? entry.cardAccess : cardAccessInfos());
        // Chip Authentication static scalar (FF03) and the master-file
        // EF.CardSecurity (FF05) that publishes the matching public key.
        if (entry.caKey != null) {
            writeDgi(out, DGI_CA_KEY, entry.caKey);
        }
        if (entry.cardSecurity != null) {
            writeDgi(out, DGI_CARD_SECURITY, entry.cardSecurity);
        }
        if (entry.sod != null) {
            writeDgi(out, LdsFileUtil.FID_SOD, entry.sod);
        } else if (!entry.dataGroups.isEmpty()) {
            Map<Integer, byte[]> hashes = new LinkedHashMap<Integer, byte[]>();
            for (Map.Entry<Integer, byte[]> dg : entry.dataGroups.entrySet()) {
                hashes.put(dg.getKey(), sha256(dg.getValue()));
            }
            writeDgi(out, LdsFileUtil.FID_SOD, SodBuilder.build(hashes, dscKey, dscCertificate));
        }
        if (entry.aaKey != null) {
            writeDgi(out, 0xFF02, entry.aaKey);
        }
        return out.toByteArray();
    }

    /**
     * The LDS2 DGI sequence for one script entry: EF.CardAccess/EF.CardSecurity
     * as transparent FIDs and each record appended to its record EF (the DGI
     * high bit marks an append).  The PACE key seed (FF04) and the Chip
     * Authentication static private scalar (FF03) make the PACE/CA advertised by
     * EF.CardAccess usable.
     */
    public static byte[] lds2Sequence(LdsScript.Entry entry) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (entry.documentNumber != null && entry.dateOfBirth != null
                && entry.dateOfExpiry != null) {
            // DGI FF04 = PACE key seed SHA-1(MRZ_information) (card LdsPerso).
            writeDgi(out, 0xFF04,
                    paceSeed(entry.documentNumber, entry.dateOfBirth, entry.dateOfExpiry));
        }
        if (entry.can != null) {
            // DGI FF06 = PACE password encoding f(CAN) = raw CAN (ref 0x02).
            writeDgi(out, 0xFF06, canSeed(entry.can));
        }
        if (entry.caKey != null) {
            // DGI FF03 = Chip Authentication static P-256 private scalar.
            writeDgi(out, 0xFF03, entry.caKey);
        }
        if (entry.cardAccess != null) {
            writeDgi(out, LdsFileUtil.FID_CARD_ACCESS, entry.cardAccess);
        }
        if (entry.cardSecurity != null) {
            writeDgi(out, LdsFileUtil.FID_CARD_SECURITY, entry.cardSecurity);
        }
        for (Map.Entry<Integer, java.util.List<byte[]>> file : entry.records.entrySet()) {
            for (byte[] record : file.getValue()) {
                writeDgi(out, 0x7000 | file.getKey(), record);
            }
        }
        for (Map.Entry<Integer, byte[]> file : entry.transparent.entrySet()) {
            writeDgi(out, file.getKey(), file.getValue());
        }
        return out.toByteArray();
    }

    /** The built-in ICAO sample as an {@link LdsScript} text. */
    public static String script(KeyPair aaKey, X509Certificate dscCertificate,
                                PrivateKey dscKey, File portrait) throws Exception {
        BigInteger modulus = ((java.security.interfaces.RSAPublicKey) aaKey.getPublic()).getModulus();
        BigInteger privateExponent = ((RSAPrivateKey) aaKey.getPrivate()).getPrivateExponent();

        byte[] dg1 = dg1();
        byte[] dg2 = dg2(portrait);
        byte[] dg11 = dg11();
        byte[] dg12 = dg12();
        byte[] dg15 = dg15(modulus);

        // One Chip Authentication key pair and its SecurityInfos are shared by
        // EF.DG14, the LDS1 EF.CardSecurity and the LDS2 Travel application:
        // EF.CardAccess and EF.CardSecurity live in the master file (Doc 9303-10
        // §3.11.3/§3.11.4), so a card hosts a single EF.CardSecurity.
        KeyPair caKeyPair = generateP256Key();
        byte[] caScalar = unsigned(((ECPrivateKey) caKeyPair.getPrivate()).getS());
        byte[] cardAccessInfos = cardAccessInfos();
        byte[] securityInfos = CardSecurityBuilder.securityInfos(
                caKeyPair.getPublic().getEncoded(), 1, cardAccessInfos);
        byte[] dg14 = dg14(securityInfos);
        byte[] caCardSecurity = CardSecurityBuilder.build(securityInfos, dscKey, dscCertificate);

        Map<Integer, byte[]> hashes = new LinkedHashMap<Integer, byte[]>();
        hashes.put(1, sha256(dg1));
        hashes.put(2, sha256(dg2));
        hashes.put(11, sha256(dg11));
        hashes.put(12, sha256(dg12));
        hashes.put(14, sha256(dg14));
        hashes.put(15, sha256(dg15));
        byte[] sod = SodBuilder.build(hashes, dscKey, dscCertificate);

        StringBuilder sb = new StringBuilder();
        sb.append("# card42 eMRTD personalization script - demo set (ICAO Doc 9303-11 sample).\n");
        sb.append("#\n");
        sb.append("# One section per LDS1 instance (EmrtdPersoExporter):\n");
        sb.append("#\n");
        sb.append("#   @instance <AID-hex>          start a section (default ")
                .append(LdsScript.DEFAULT_AID).append(")\n");
        sb.append("#   @doc <MRZ document number>   BAC document number\n");
        sb.append("#   @dob <YYMMDD>                BAC date of birth\n");
        sb.append("#   @doe <YYMMDD>                BAC date of expiry\n");
        sb.append("#   @can <6 digits>              Card Access Number for PACE (password ref 0x02)\n");
        sb.append("#   @dg <n> <hex>                EF.DG<n> content (DG1 mandatory)\n");
        sb.append("#   @sod <hex>                   EF.SOD content (built from the DG hashes when absent)\n");
        sb.append("#   @aa <hex>                    AA private key (modLen || modulus || expLen || exponent)\n");
        sb.append("#   @ca <hex>                    CA static P-256 private scalar (DGI FF03)\n");
        sb.append("#   @cardsecurity <hex>          master-file EF.CardSecurity CMS SignedData (DGI FF05)\n");
        sb.append("#\n");
        sb.append("# The EF.SOD is signed by the DSC fixture (perso/emrtd/dsc.crt + dsc.key);\n");
        sb.append("# the AA key pair is a throwaway demo key.  These keys are printed on purpose\n");
        sb.append("# and MUST NEVER be used on a real card.\n");
        sb.append("#\n");
        sb.append("# Regenerate with `EmrtdPersoExporter -emit`.\n");
        sb.append("@instance ").append(LdsScript.DEFAULT_AID).append('\n');
        sb.append("@doc ").append(DOCUMENT_NUMBER).append('\n');
        sb.append("@dob ").append(DATE_OF_BIRTH).append('\n');
        sb.append("@doe ").append(DATE_OF_EXPIRY).append('\n');
        sb.append("@can ").append(CARD_ACCESS_NUMBER).append('\n');
        sb.append("@dg 1 ").append(Hex.format(dg1)).append('\n');
        sb.append("@dg 2 ").append(Hex.format(dg2)).append('\n');
        sb.append("@dg 11 ").append(Hex.format(dg11)).append('\n');
        sb.append("@dg 12 ").append(Hex.format(dg12)).append('\n');
        sb.append("@dg 14 ").append(Hex.format(dg14)).append('\n');
        sb.append("@dg 15 ").append(Hex.format(dg15)).append('\n');
        sb.append("@sod ").append(Hex.format(sod)).append('\n');
        sb.append("@aa ").append(Hex.format(aaPrivateKey(modulus, privateExponent))).append('\n');

        // One Chip Authentication key pair and one EF.CardSecurity are shared
        // by the LDS1 DF and the LDS2 Travel application: EF.CardAccess and
        // EF.CardSecurity live in the master file (Doc 9303-10 §3.11.3/§3.11.4),
        // so a card hosts a single EF.CardSecurity.  The private scalar is
        // personalized as DGI FF03 and the public key published in
        // EF.CardSecurity (DGI FF05 for LDS1, FID 011D for LDS2) and EF.DG14.
        sb.append("@cardaccess ").append(Hex.format(cardAccessInfos)).append('\n');
        sb.append("@ca ").append(Hex.format(caScalar)).append('\n');
        sb.append("@cardsecurity ").append(Hex.format(caCardSecurity)).append('\n');

        // --- LDS2 Travel Records instance -----------------------------------
        sb.append("\n# LDS2 Travel Records instance: EF.CardAccess advertises PACE\n");
        sb.append("# (ECDH generic mapping) and Chip Authentication (ECDH 3DES);\n");
        sb.append("# @ca is the CA static P-256 private scalar (DGI FF03), @cardsecurity\n");
        sb.append("# publishes the matching public key, @record appends a record.\n");
        sb.append("@instance ").append(LdsFileUtil.AID_TRAVEL).append('\n');
        sb.append("@lds2 travel\n");
        sb.append("@doc ").append(DOCUMENT_NUMBER).append('\n');
        sb.append("@dob ").append(DATE_OF_BIRTH).append('\n');
        sb.append("@doe ").append(DATE_OF_EXPIRY).append('\n');
        sb.append("@cardaccess ").append(Hex.format(cardAccessInfos)).append('\n');
        sb.append("@cardsecurity ").append(Hex.format(caCardSecurity)).append('\n');
        sb.append("@ca ").append(Hex.format(caScalar)).append('\n');
        sb.append("@record 0101 ").append(Hex.format(sampleTravelRecord("USA", "20260101")))
                .append('\n');
        sb.append("@record 0101 ").append(Hex.format(sampleTravelRecord("NLD", "20260215")))
                .append('\n');

        // --- LDS2 Visa Records instance -------------------------------------
        sb.append("\n# LDS2 Visa Records instance: EF.VisaRecords 0103.\n");
        sb.append("@instance ").append(LdsFileUtil.AID_VISA).append('\n');
        sb.append("@lds2 visa\n");
        sb.append("@doc ").append(DOCUMENT_NUMBER).append('\n');
        sb.append("@dob ").append(DATE_OF_BIRTH).append('\n');
        sb.append("@doe ").append(DATE_OF_EXPIRY).append('\n');
        sb.append("@record 0103 ").append(Hex.format(sampleVisaRecord("JPN", "20260401")))
                .append('\n');

        // --- LDS2 Additional Biometrics instance ----------------------------
        sb.append("\n# LDS2 Additional Biometrics instance: EF.Biometrics1 0201\n");
        sb.append("# (a transparent EF, Doc 9303-10 §5.3.3).\n");
        sb.append("@instance ").append(LdsFileUtil.AID_BIOMETRICS).append('\n');
        sb.append("@lds2 biometrics\n");
        sb.append("@doc ").append(DOCUMENT_NUMBER).append('\n');
        sb.append("@dob ").append(DATE_OF_BIRTH).append('\n');
        sb.append("@doe ").append(DATE_OF_EXPIRY).append('\n');
        sb.append("@transparent 0201 ").append(Hex.format(sampleBiometric())).append('\n');
        return sb.toString();
    }

    /** A fresh P-256 (secp256r1) key pair for Chip Authentication. */
    private static KeyPair generateP256Key() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    /** EF.CardAccess SecurityInfos: PACE ECDH-GM 3DES + AES-128, CA ECDH 3DES. */
    private static byte[] cardAccessInfos() {
        return DerWriter.set(
                paceInfo(SecurityInfo.ID_PACE_ECDH_GM_3DES),
                paceInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_128),
                caInfo(SecurityInfo.ID_CA_ECDH_3DES));
    }

    /** ChipAuthenticationInfo SEQUENCE { OID, version 2, key id 1 }. */
    private static byte[] caInfo(String oid) {
        return DerWriter.sequence(DerWriter.oid(oid), DerWriter.integer(2),
                DerWriter.integer(1));
    }

    /** PACEInfo SEQUENCE { OID, version 2, parameterId 12 (P-256) }. */
    private static byte[] paceInfo(String oid) {
        return DerWriter.sequence(DerWriter.oid(oid), DerWriter.integer(2),
                DerWriter.integer(12));
    }

    /** A demo LDS2 travel record: 5F44 (state) || 5F37 (date). */
    private static byte[] sampleTravelRecord(String state, String date) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, 0x5F44,
                state.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        TlvWriter.writeTlv(out, 0x5F37,
                date.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return out.toByteArray();
    }

    /** A demo LDS2 visa record: 5F44 (state) || 5F37 (date). */
    private static byte[] sampleVisaRecord(String state, String date) {
        return sampleTravelRecord(state, date);
    }

    /** A demo Additional Biometrics EF.Biometrics1 content (transparent EF 0201). */
    private static byte[] sampleBiometric() {
        return Hex.parse("7F6108020101020203040506");
    }

    /** Loads an X.509 certificate from a PEM/DER file. */
    public static X509Certificate loadCertificate(String path) throws Exception {
        java.security.cert.CertificateFactory factory =
                java.security.cert.CertificateFactory.getInstance("X.509");
        try (java.io.InputStream in = new java.io.FileInputStream(path)) {
            return (X509Certificate) factory.generateCertificate(in);
        }
    }

    /** Loads a PKCS#8 RSA private key from a PEM/DER file. */
    public static PrivateKey loadPrivateKey(String path) throws Exception {
        String pem = new String(java.nio.file.Files.readAllBytes(
                java.nio.file.Paths.get(path)), java.nio.charset.StandardCharsets.US_ASCII);
        String base64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        byte[] der = java.util.Base64.getDecoder().decode(base64);
        return java.security.KeyFactory.getInstance("RSA")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(der));
    }

    private static KeyPair generateAaKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static byte[] dg1() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, 0x5F1F, (LINE1 + LINE2)
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return tlv(0x61, out.toByteArray());
    }

    /**
     * DG2 = {@code 75 { 7F61 { 7F60 { ISO 19794-5 face record } } }} around the
     * portrait input image ({@link Dg2Builder}).
     */
    private static byte[] dg2(File portrait) throws Exception {
        return Dg2Builder.buildFromImage(portrait);
    }

    /**
     * DG15 = 6F { SubjectPublicKeyInfo } (ICAO Doc 9303-11 §6.1.5, RFC 5280):
     * a SEQUENCE of the rsaEncryption AlgorithmIdentifier and a BIT STRING
     * holding the DER RSAPublicKey.
     */
    private static byte[] dg15(BigInteger modulus) {
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

    /**
     * DG11 = {@code 6B { 5C <tag list> 5F0E <full name> 5F11 <place of birth>
     * 5F42 <address> 5F12 <telephone> }} (ICAO Doc 9303-10 §4.7.11).  The tag
     * list mirrors the optional-group form an issuing State normally writes;
     * the values follow the ICAO Doc 9303-11 sample passport.
     */
    private static byte[] dg11() {
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
     * serial> }} (ICAO Doc 9303-10 §4.7.12).  The last two mirror the metadata
     * a personalization system normally stamps.
     */
    private static byte[] dg12() {
        byte[] tags = { 0x5F, 0x19, 0x5F, 0x26, 0x5F, 0x55, 0x5F, 0x56 };
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        TlvWriter.writeTlv(inner, 0x5C, tags);
        ascii(inner, 0x5F19, "UTO");
        ascii(inner, 0x5F26, "20260101");
        ascii(inner, 0x5F55, "20260101120000");
        ascii(inner, 0x5F56, "card42");
        return tlv(0x6C, inner.toByteArray());
    }

    /**
     * DG14 = {@code 6E { SecurityInfos }} (ICAO Doc 9303-10 §4.7.14): the same
     * DER {@code SET OF SecurityInfo} that EF.CardSecurity signs, i.e. the
     * EF.CardAccess SecurityInfos plus the chip's Chip Authentication public
     * key.  The value is supplied by {@link CardSecurityBuilder#securityInfos}.
     */
    private static byte[] dg14(byte[] securityInfos) {
        return tlv(0x6E, securityInfos);
    }

    /** Appends {@code tag || len || US-ASCII(value)} to {@code out}. */
    private static void ascii(ByteArrayOutputStream out, int tag, String value) {
        TlvWriter.writeTlv(out, tag,
                value.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    private static byte[] aaPrivateKey(BigInteger modulus, BigInteger privateExponent) {
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

    private static byte[] sha256(byte[] data) throws Exception {
        return java.security.MessageDigest.getInstance("SHA-256").digest(data);
    }

    /**
     * The 20-byte PACE key seed SHA-1(MRZ_information) (DGI FF04).  The card
     * derives K_pi = KDF(seed, 3) from it (BSI TR-03110-3 A.3/B.1,
     * ICAO Doc 9303-11 §9.7.3).
     */
    private static byte[] paceSeed(String documentNumber, String dateOfBirth,
                                   String dateOfExpiry) throws Exception {
        return java.security.MessageDigest.getInstance("SHA-1").digest(
                MrzKeySeed.mrzInformation(documentNumber, dateOfBirth, dateOfExpiry));
    }

    /**
     * The PACE password encoding {@code f(CAN)} (DGI FF06, password reference
     * 0x02, BSI TR-03110-3 A.2.3 Table 5): the raw CAN octets, not a hash.  The
     * card applies the KDF with counter 3, giving {@code SHA-1(CAN || 00 00 00 03)}.
     */
    private static byte[] canSeed(String can) {
        return can.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    private static void writeDgi(ByteArrayOutputStream out, int dgi, byte[] value) {
        out.write((dgi >> 8) & 0xFF);
        out.write(dgi & 0xFF);
        if (value.length < 0xFF) {
            out.write(value.length);
        } else {
            out.write(0xFF);
            out.write((value.length >> 8) & 0xFF);
            out.write(value.length & 0xFF);
        }
        out.write(value, 0, value.length);
    }

    private static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, value);
        return out.toByteArray();
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            return java.util.Arrays.copyOfRange(raw, 1, raw.length);
        }
        return raw;
    }

    public static void main(String[] args) throws Exception {
        String scriptPath = null;
        String dscPath = DEFAULT_DSC;
        String dscKeyPath = DEFAULT_DSC_KEY;
        String facePath = Dg2Builder.DEFAULT_PORTRAIT;
        boolean emit = false;
        for (String arg : args) {
            if (arg.startsWith("-script=")) {
                scriptPath = arg.substring("-script=".length());
            } else if (arg.startsWith("-dsc=")) {
                dscPath = arg.substring("-dsc=".length());
            } else if (arg.startsWith("-dsc-key=")) {
                dscKeyPath = arg.substring("-dsc-key=".length());
            } else if (arg.startsWith("-face=")) {
                facePath = arg.substring("-face=".length());
            } else if (arg.equals("-emit")) {
                emit = true;
            } else {
                throw new IllegalArgumentException("unknown option: " + arg);
            }
        }
        X509Certificate dsc = loadCertificate(dscPath);
        PrivateKey dscKey = loadPrivateKey(dscKeyPath);
        File portrait = new File(facePath);
        if (emit) {
            System.out.print(script(generateAaKey(), dsc, dscKey, portrait));
            return;
        }
        if (scriptPath != null) {
            LdsScript parsed = LdsScript.parse(new File(scriptPath));
            for (LdsScript.Entry entry : parsed.entries) {
                System.out.println(entry.aid + " " + Hex.format(dgiSequence(entry, dsc, dscKey)));
            }
            return;
        }
        System.out.println(LdsScript.DEFAULT_AID + " "
                + Hex.format(dgiSequence(generateAaKey(), dsc, dscKey, portrait)));
    }
}
