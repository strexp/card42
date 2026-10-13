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
import card42.host.emrtd.ta.TaChain;

/**
 * Builds the GP STORE DATA DGI sequence that personalizes a card42-emrtd LDS1
 * instance (H5.2/H5.4).  The DGI number is the target FID; the project DGIs
 * carry the key material: {@code FF01} = BAC K_seed, {@code FF02} = the RSA AA
 * private key (modulus length || modulus || exponent length || exponent),
 * {@code FF03} = the Chip Authentication P-256 scalar, {@code FF04} =
 * SHA-1(MRZ_information), {@code FF06} = raw CAN PACE password encodings,
 * {@code FF0A} = the AA algorithm, {@code FF0B}/{@code FF0C} = RSA CVCA trust
 * points, {@code FF0D} = the ECDSA AA scalar, and {@code FF05} = the
 * master-file EF.CardSecurity.
 *
 * <p>The demo data is comprehensive: DG1, DG2 and DG3–DG16 (DG6 reserved),
 * the LDS2 Travel/Visa/Additional Biometrics applications with several records,
 * Chip Authentication (ECDH 3DES + AES-128), PACE (3DES + AES-128) and Terminal
 * Authentication with <em>both</em> an ECDSA and an RSA-PSS CVCA trust point, so
 * every mutually-compatible algorithm is present at once (docs/specs/emrtd/
 * algorithm-support.md).  Only the AA signature algorithm is mutually exclusive
 * and selected by the sample suffix ({@code -aa=sha1|sha256|ecdsa}).
 *
 * <p>{@code main} emits {@code <AID> <hex>} lines for GPPro
 * {@code --personalize}.  With {@code -script=<path>} it personalizes the
 * documents of an {@link LdsScript} (A2); with {@code -emit} it prints the
 * built-in sample in script form.
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

    /** LDS1 project DGI: AA signature algorithm (1 = SHA-1, 2 = SHA-256, 3 = ECDSA). */
    private static final int DGI_AA_ALGORITHM = 0xFF0A;
    /** LDS1 project DGI: Chip Authentication static P-256 private scalar. */
    private static final int DGI_CA_KEY = 0xFF03;
    /** LDS1 project DGI: master-file EF.CardSecurity CMS SignedData. */
    private static final int DGI_CARD_SECURITY = 0xFF05;
    /** LDS1 project DGI: PACE password encoding f(CAN) = raw CAN (ref 0x02). */
    private static final int DGI_PACE_CAN_SEED = 0xFF06;
    /** Terminal Authentication EC CVCA trust point (W || refLen || CAR || auth). */
    private static final int DGI_TA_TRUST_POINT = 0xFF07;
    /** Terminal Authentication RSA CVCA trust point (mod/exp + refLen + CAR + auth). */
    private static final int DGI_TA_TRUST_POINT_RSA = 0xFF0B;
    /** Terminal Authentication current date (6 octets, unpacked BCD YYMMDD). */
    private static final int DGI_TA_CURRENT_DATE = 0xFF08;
    /** DGI FF0D: ECDSA AA private scalar (P-256). */
    private static final int DGI_AA_EC_KEY = 0xFF0D;

    /** Demo pre-personalization date, earlier than the demo certificates' Effective Date. */
    private static final String TA_CURRENT_DATE = "240101";

    /** DGI FF0A value: RSA ISO/IEC 9796-2 Scheme 1 + SHA-1 (trailer option 1). */
    private static final byte AA_ALGORITHM_SHA1 = (byte) 0x01;
    /** DGI FF0A value: RSA ISO/IEC 9796-2 Scheme 1 + SHA-256 (trailer option 2). */
    private static final byte AA_ALGORITHM_SHA256 = (byte) 0x02;
    /** DGI FF0A value: ECDSA-SHA-256 (P-256, plain r||s). */
    private static final byte AA_ALGORITHM_ECDSA = (byte) 0x03;
    /** The default sample AA algorithm. */
    public static final String DEFAULT_AA = "sha256";

    private EmrtdPersoExporter() {
    }

    /** An algorithm combination for the sample data. */
    public static final class Variant {
        /** {@code sha1}, {@code sha256} or {@code ecdsa}. */
        public final String aa;
        /**
         * {@code ec}, {@code rsa} or {@code both}.  Since the card holds two CVCA
         * trust-point slots, {@code both} seeds an ECDSA and an RSA-PSS trust
         * point at once and every sample uses it.
         */
        public final String ta;

        public Variant(String aa, String ta) {
            this.aa = aa;
            this.ta = ta;
        }

        /** The sample suffix, e.g. {@code sha256} (default) or {@code sha1}. */
        public String suffix() {
            return aa;
        }
    }

    /** The default variant (AA = RSA ISO/IEC 9796-2 + SHA-256). */
    public static final Variant DEFAULT_VARIANT = new Variant(DEFAULT_AA, "both");

    // --- Public entry points -------------------------------------------------

    /**
     * The complete DGI sequence for one script entry.  The BAC seed comes from
     * {@code @doc/@dob/@doe}, every {@code @dg} becomes its EF, {@code @sod} is
     * used verbatim (or built from the DG hashes when absent), {@code @aa} (RSA)
     * or {@code @aa-ec} (ECDSA) carries the AA private key, and {@code @cvca} /
     * {@code @cvca-rsa} the TA trust points.
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
        // EF.CardAccess in the master file (Doc 9303-10 §3.11.3): PACE, Chip
        // Authentication and, for the ECDSA AA variant, ActiveAuthenticationInfo.
        writeDgi(out, LdsFileUtil.FID_CARD_ACCESS,
                entry.cardAccess != null ? entry.cardAccess : cardAccessInfos(entry.aaAlgorithm));
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
        // Active Authentication key material + algorithm (mutually exclusive).
        writeDgi(out, DGI_AA_ALGORITHM, new byte[] { aaAlgorithmByte(entry.aaAlgorithm) });
        if (entry.aaKey != null) {
            writeDgi(out, 0xFF02, entry.aaKey);
        }
        if (entry.aaEcKey != null) {
            writeDgi(out, DGI_AA_EC_KEY, entry.aaEcKey);
        }
        writeTrustPoints(out, entry);
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
            writeDgi(out, 0xFF04,
                    paceSeed(entry.documentNumber, entry.dateOfBirth, entry.dateOfExpiry));
        }
        if (entry.can != null) {
            writeDgi(out, 0xFF06, canSeed(entry.can));
        }
        if (entry.caKey != null) {
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

    /**
     * The built-in ICAO sample as an {@link LdsScript} text for the given AA
     * variant.  Every simultaneously-compatible algorithm is present: PACE and
     * Chip Authentication advertise 3DES and AES-128, and Terminal
     * Authentication gets an ECDSA and an RSA-PSS CVCA trust point.
     */
    public static String script(String aa, File portrait) throws Exception {
        return script(aa, DEFAULT_DSC, DEFAULT_DSC_KEY, portrait);
    }

    public static String script(String aa, String dscPath, String dscKeyPath, File portrait)
            throws Exception {
        X509Certificate dscCertificate = loadCertificate(dscPath);
        PrivateKey dscKey = loadPrivateKey(dscKeyPath);

        Map<Integer, byte[]> dgs = dataGroups(portrait);
        // AA material: RSA (SHA-1/256) or ECDSA.
        byte[] aaKey = null;
        byte[] aaEcKey = null;
        if ("ecdsa".equalsIgnoreCase(aa)) {
            KeyPair ecAa = generateP256Key();
            aaEcKey = unsigned(((ECPrivateKey) ecAa.getPrivate()).getS());
            dgs.put(15, dg15Ec(ecAa.getPublic().getEncoded()));
        } else {
            KeyPair rsaAa = generateAaKey();
            BigInteger modulus = ((java.security.interfaces.RSAPublicKey) rsaAa.getPublic())
                    .getModulus();
            BigInteger privateExponent = ((RSAPrivateKey) rsaAa.getPrivate()).getPrivateExponent();
            aaKey = aaPrivateKey(modulus, privateExponent);
            dgs.put(15, dg15Rsa(modulus));
        }

        // One Chip Authentication key pair and its SecurityInfos are shared by
        // EF.DG14, EF.CardSecurity and the LDS2 Travel application.
        KeyPair caKeyPair = generateP256Key();
        byte[] caScalar = unsigned(((ECPrivateKey) caKeyPair.getPrivate()).getS());
        byte[] cardAccess = cardAccessInfos(aa);
        byte[] securityInfos = CardSecurityBuilder.securityInfos(
                caKeyPair.getPublic().getEncoded(), 1, cardAccess);
        dgs.put(14, dg14(securityInfos));
        byte[] cardSecurity = CardSecurityBuilder.build(securityInfos, dscKey, dscCertificate);

        Map<Integer, byte[]> hashes = new LinkedHashMap<Integer, byte[]>();
        for (Map.Entry<Integer, byte[]> dg : dgs.entrySet()) {
            hashes.put(dg.getKey(), sha256(dg.getValue()));
        }
        byte[] sod = SodBuilder.build(hashes, dscKey, dscCertificate);

        StringBuilder sb = new StringBuilder();
        sb.append("# card42 eMRTD personalization script - demo set (ICAO Doc 9303-11 sample).\n");
        sb.append("#\n");
        sb.append("# One section per instance (EmrtdPersoExporter).  The demo data is\n");
        sb.append("# comprehensive (DG1..DG16 except the reserved DG6) and every algorithm\n");
        sb.append("# that can be present at once is: PACE and Chip Authentication advertise\n");
        sb.append("# 3DES + AES-128; Terminal Authentication carries an ECDSA and an RSA-PSS\n");
        sb.append("# CVCA trust point.  Only AA is mutually exclusive and chosen by suffix\n");
        sb.append("# (@aa-alg), e.g. sample-").append(aa).append(".perso.\n");
        sb.append("#\n");
        sb.append("#   @instance <AID-hex>          start a section\n");
        sb.append("#   @doc/@dob/@doe               BAC MRZ fields\n");
        sb.append("#   @can <6 digits>              Card Access Number for PACE (ref 0x02)\n");
        sb.append("#   @dg <n> <hex>                EF.DG<n> content\n");
        sb.append("#   @sod <hex>                   EF.SOD content\n");
        sb.append("#   @aa <hex>                    RSA AA private key (modLen||mod||expLen||exp)\n");
        sb.append("#   @aa-ec <hex>                 ECDSA AA private scalar (P-256)\n");
        sb.append("#   @aa-alg sha1|sha256|ecdsa    AA signature algorithm\n");
        sb.append("#   @ca <hex>                    CA static P-256 private scalar (DGI FF03)\n");
        sb.append("#   @cardsecurity <hex>          master-file EF.CardSecurity (DGI FF05)\n");
        sb.append("#   @ta-date <YYMMDD>            ICC current date (DGI FF08)\n");
        sb.append("#   @cvca <W> <CAR> <date> <auth> [secondary]        EC CVCA trust point\n");
        sb.append("#   @cvca-rsa <n> <e> <CAR> <date> <auth> [secondary] RSA CVCA trust point\n");
        sb.append("#   @lds2 <role> / @record <fid> <hex> / @transparent <fid> <hex>\n");
        sb.append("#\n");
        sb.append("# The EF.SOD is signed by the DSC fixture (perso/emrtd/dsc.crt + dsc.key);\n");
        sb.append("# the AA/CA keys are throwaway demo keys.  NEVER use them on a real card.\n");
        sb.append("# Regenerate with `EmrtdPersoExporter -emit [-aa=<sha1|sha256|ecdsa>]`.\n");
        sb.append("@instance ").append(LdsScript.DEFAULT_AID).append('\n');
        sb.append("@doc ").append(DOCUMENT_NUMBER).append('\n');
        sb.append("@dob ").append(DATE_OF_BIRTH).append('\n');
        sb.append("@doe ").append(DATE_OF_EXPIRY).append('\n');
        sb.append("@can ").append(CARD_ACCESS_NUMBER).append('\n');
        for (Map.Entry<Integer, byte[]> dg : dgs.entrySet()) {
            sb.append("@dg ").append(dg.getKey()).append(' ')
                    .append(Hex.format(dg.getValue())).append('\n');
        }
        sb.append("@sod ").append(Hex.format(sod)).append('\n');
        if (aaEcKey != null) {
            sb.append("@aa-ec ").append(Hex.format(aaEcKey)).append('\n');
        } else {
            sb.append("@aa ").append(Hex.format(aaKey)).append('\n');
        }
        sb.append("@aa-alg ").append(aa).append('\n');

        // Terminal Authentication: an ECDSA and an RSA-PSS CVCA trust point.
        LdsScript.TrustPoint ecTp = demoTrustPoint();
        sb.append("@ta-date ").append(TA_CURRENT_DATE).append('\n');
        sb.append("@cvca ").append(Hex.format(ecTp.publicKey)).append(' ')
                .append(ecTp.car).append(' ').append(ecTp.effective).append(' ')
                .append(Hex.format(ecTp.authorization)).append('\n');
        LdsScript.TrustPoint rsaTp = demoRsaTrustPoint();
        sb.append("@cvca-rsa ").append(Hex.format(rsaTp.modulus)).append(' ')
                .append(Hex.format(rsaTp.exponent)).append(' ').append(rsaTp.car).append(' ')
                .append(rsaTp.effective).append(' ').append(Hex.format(rsaTp.authorization))
                .append('\n');

        sb.append("@cardaccess ").append(Hex.format(cardAccess)).append('\n');
        sb.append("@ca ").append(Hex.format(caScalar)).append('\n');
        sb.append("@cardsecurity ").append(Hex.format(cardSecurity)).append('\n');

        appendLds2Sections(sb, cardAccess, caScalar, cardSecurity, dscCertificate);
        return sb.toString();
    }

    // --- LDS2 demo sections --------------------------------------------------

    private static void appendLds2Sections(StringBuilder sb, byte[] cardAccess, byte[] caScalar,
                                           byte[] cardSecurity, X509Certificate dscCertificate)
            throws Exception {
        String certHex = Hex.format(dscCertificate.getEncoded());

        sb.append("\n# LDS2 Travel Records: EntryRecords 0101, ExitRecords 0102,\n");
        sb.append("# EF.Certificates 011A; EF.CardAccess advertises PACE + CA (3DES/AES).\n");
        sb.append("@instance ").append(LdsFileUtil.AID_TRAVEL).append('\n');
        sb.append("@lds2 travel\n");
        sb.append("@doc ").append(DOCUMENT_NUMBER).append('\n');
        sb.append("@dob ").append(DATE_OF_BIRTH).append('\n');
        sb.append("@doe ").append(DATE_OF_EXPIRY).append('\n');
        sb.append("@cardaccess ").append(Hex.format(cardAccess)).append('\n');
        sb.append("@cardsecurity ").append(Hex.format(cardSecurity)).append('\n');
        sb.append("@ca ").append(Hex.format(caScalar)).append('\n');
        sb.append("@record 0101 ").append(Hex.format(sampleTravelRecord("USA", "20260101")))
                .append('\n');
        sb.append("@record 0101 ").append(Hex.format(sampleTravelRecord("NLD", "20260215")))
                .append('\n');
        sb.append("@record 0101 ").append(Hex.format(sampleTravelRecord("JPN", "20260320")))
                .append('\n');
        sb.append("@record 0102 ").append(Hex.format(sampleTravelRecord("DEU", "20260601")))
                .append('\n');
        sb.append("@record 011A ").append(certHex).append('\n');

        sb.append("\n# LDS2 Visa Records: EF.VisaRecords 0103, EF.Certificates 011A.\n");
        sb.append("@instance ").append(LdsFileUtil.AID_VISA).append('\n');
        sb.append("@lds2 visa\n");
        sb.append("@doc ").append(DOCUMENT_NUMBER).append('\n');
        sb.append("@dob ").append(DATE_OF_BIRTH).append('\n');
        sb.append("@doe ").append(DATE_OF_EXPIRY).append('\n');
        sb.append("@ca ").append(Hex.format(caScalar)).append('\n');
        sb.append("@record 0103 ").append(Hex.format(sampleVisaRecord("JPN", "20260401")))
                .append('\n');
        sb.append("@record 0103 ").append(Hex.format(sampleVisaRecord("AUS", "20260505")))
                .append('\n');
        sb.append("@record 011A ").append(certHex).append('\n');

        sb.append("\n# LDS2 Additional Biometrics: EF.Biometrics1 0201 (transparent),\n");
        sb.append("# EF.Certificates 011A.\n");
        sb.append("@instance ").append(LdsFileUtil.AID_BIOMETRICS).append('\n');
        sb.append("@lds2 biometrics\n");
        sb.append("@doc ").append(DOCUMENT_NUMBER).append('\n');
        sb.append("@dob ").append(DATE_OF_BIRTH).append('\n');
        sb.append("@doe ").append(DATE_OF_EXPIRY).append('\n');
        sb.append("@ca ").append(Hex.format(caScalar)).append('\n');
        sb.append("@transparent 0201 ").append(Hex.format(sampleBiometric())).append('\n');
        sb.append("@record 011A ").append(certHex).append('\n');
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
    private static KeyPair generateP256Key() throws Exception {
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
    private static byte[] cardAccessInfos(String aaAlgorithm) {
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
    private static byte[] taInfo() {
        return DerWriter.sequence(DerWriter.oid(SecurityInfo.ID_TA), DerWriter.integer(1));
    }

    /** ActiveAuthenticationInfo SEQUENCE { id-AA, version 1, signatureAlgorithm } (§9.2.4). */
    private static byte[] aaInfo(String signatureAlgorithmOid) {
        return DerWriter.sequence(DerWriter.oid(SecurityInfo.ID_AA), DerWriter.integer(1),
                DerWriter.oid(signatureAlgorithmOid));
    }

    /**
     * The demo ECDSA CVCA trust point used by {@link TaChain#demo}: the CVCA
     * public key W(65) || CAR || Effective Date || relative authorization.
     */
    private static LdsScript.TrustPoint demoTrustPoint() {
        TaChain.Chain chain = TaChain.demo(new java.security.SecureRandom());
        byte[] w = chain.cvca.ecPublicKey();
        byte[] car = chain.cvca.certificateHolderReference().encode();
        return new LdsScript.TrustPoint(w, new String(car,
                java.nio.charset.StandardCharsets.US_ASCII), TA_CURRENT_DATE,
                new byte[] { 0x03, 0x0F, 0x0F, 0x0F }, false);
    }

    /** The demo RSA-PSS CVCA trust point used by {@link TaChain#demoRsa}. */
    private static LdsScript.TrustPoint demoRsaTrustPoint() {
        return new LdsScript.TrustPoint(TaChain.demoRsaModulus(), TaChain.demoRsaExponent(),
                TaChain.DEMO_RSA_CAR, TA_CURRENT_DATE, new byte[] { 0x03, 0x0F, 0x0F, 0x0F },
                false);
    }

    /** Writes the EC (FF07/FF09) and RSA (FF0B/FF0C) trust points and the ICC date. */
    private static void writeTrustPoints(ByteArrayOutputStream out, LdsScript.Entry entry) {
        for (LdsScript.TrustPoint tp : entry.trustPoints) {
            if (tp.rsa) {
                writeDgi(out, tp.secondary ? 0xFF0C : DGI_TA_TRUST_POINT_RSA, rsaTrustPointValue(tp));
            } else {
                writeDgi(out, tp.secondary ? 0xFF09 : DGI_TA_TRUST_POINT, trustPointValue(tp));
            }
        }
        writeDgi(out, DGI_TA_CURRENT_DATE, taCurrentDate(entry.taDate));
    }

    /**
     * Encodes an EC trust point: {@code W(65) || refLen(1) || CAR || effective(6)
     * || auth(4)} (ICAO Doc 9303-11 §7.1.4.3.1).
     */
    private static byte[] trustPointValue(LdsScript.TrustPoint tp) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tp.publicKey, 0, tp.publicKey.length);
        out.write(tp.car.length());
        out.write(tp.car.getBytes(java.nio.charset.StandardCharsets.US_ASCII), 0, tp.car.length());
        out.write(dateBytes(tp.effective), 0, 6);
        out.write(tp.authorization, 0, 4);
        return out.toByteArray();
    }

    /**
     * Encodes an RSA trust point: {@code modLen(2) || modulus || expLen(2) ||
     * exponent || refLen(1) || CAR || effective(6) || auth(4)} (DGI FF0B).
     */
    private static byte[] rsaTrustPointValue(LdsScript.TrustPoint tp) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((tp.modulus.length >> 8) & 0xFF);
        out.write(tp.modulus.length & 0xFF);
        out.write(tp.modulus, 0, tp.modulus.length);
        out.write((tp.exponent.length >> 8) & 0xFF);
        out.write(tp.exponent.length & 0xFF);
        out.write(tp.exponent, 0, tp.exponent.length);
        out.write(tp.car.length());
        out.write(tp.car.getBytes(java.nio.charset.StandardCharsets.US_ASCII), 0, tp.car.length());
        out.write(dateBytes(tp.effective), 0, 6);
        out.write(tp.authorization, 0, 4);
        return out.toByteArray();
    }

    /** The Terminal Authentication current date (DGI FF08), 6 octets unpacked BCD. */
    private static byte[] taCurrentDate(String date) {
        return dateBytes(date == null ? TA_CURRENT_DATE : date);
    }

    /** Encodes a 6-digit YYMMDD date as 6 octets of unpacked BCD. */
    private static byte[] dateBytes(String date) {
        byte[] out = new byte[6];
        for (int i = 0; i < 6; i++) {
            out[i] = (byte) (date.charAt(i) - '0');
        }
        return out;
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
        return Hex.parse("7F611002010102020304050608010A0B0C0D0E0F10");
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

    /** DG3 = {@code 63 { 7F61 { 7F60 { 5F2E <fingerprint> } } }} (fingerprints). */
    private static byte[] dg3() {
        byte[] bir = tlv(0x7F60, tlv(0x5F2E,
                Hex.parse("0102030405060708090A0B0C0D0E0F1011121314")));
        return tlv(0x63, tlv(0x7F61, bir));
    }

    /** DG4 = {@code 76 { 7F61 { 7F60 { 5F2E <iris> } } }} (irises). */
    private static byte[] dg4() {
        byte[] bir = tlv(0x7F60, tlv(0x5F2E,
                Hex.parse("2122232425262728292A2B2C2D2E2F30")));
        return tlv(0x76, tlv(0x7F61, bir));
    }

    /** DG5 = {@code 65 { 5F2E <portrait> }} (displayed portrait). */
    private static byte[] dg5() {
        return tlv(0x65, tlv(0x5F2E, Hex.parse("FFD8FFE000104A4649460001")));
    }

    /** DG7 = {@code 67 { 7F61 { 5F2E <signature image> } }} (signature). */
    private static byte[] dg7() {
        return tlv(0x67, tlv(0x7F61, tlv(0x5F2E, Hex.parse("FFD8FFE000104A4649460002"))));
    }

    /** DG8 = {@code 68 { 5F2B..5F2E }} (data features). */
    private static byte[] dg8() {
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        TlvWriter.writeTlv(inner, 0x5F2B, Hex.parse("01010101"));
        TlvWriter.writeTlv(inner, 0x5F2C, Hex.parse("02020202"));
        TlvWriter.writeTlv(inner, 0x5F2D, Hex.parse("03030303"));
        TlvWriter.writeTlv(inner, 0x5F2E, Hex.parse("04040404"));
        return tlv(0x68, inner.toByteArray());
    }

    /** DG9 = {@code 69 { 5F2B <structure feature points> }}. */
    private static byte[] dg9() {
        return tlv(0x69, tlv(0x5F2B, Hex.parse("000102030405060708090A0B")));
    }

    /** DG10 = {@code 6A { 5F2B <substance feature points> }}. */
    private static byte[] dg10() {
        return tlv(0x6A, tlv(0x5F2B, Hex.parse("101112131415161718191A1B")));
    }

    /**
     * DG11 = {@code 6B { 5C <tag list> 5F0E <full name> 5F11 <place of birth>
     * 5F42 <address> 5F12 <telephone> }} (ICAO Doc 9303-10 §4.7.11).
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
     * serial> }} (ICAO Doc 9303-10 §4.7.12).
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

    /** DG13 = {@code 6D { 5F2B <optional details> }} (ICAO Doc 9303-10 §4.7.13). */
    private static byte[] dg13() {
        return tlv(0x6D, tlv(0x5F2B, Hex.parse("2021222324252627")));
    }

    /** DG16 = {@code 70 { 61 { 5F0E <name> } }} (persons to notify, §4.7.16). */
    private static byte[] dg16() {
        return tlv(0x70, tlv(0x61, tlv(0x5F0E,
                "UTOPIA<CONTACT".getBytes(java.nio.charset.StandardCharsets.US_ASCII))));
    }

    /**
     * DG14 = {@code 6E { SecurityInfos }} (ICAO Doc 9303-10 §4.7.14): the same
     * DER {@code SET OF SecurityInfo} that EF.CardSecurity signs.
     */
    private static byte[] dg14(byte[] securityInfos) {
        return tlv(0x6E, securityInfos);
    }

    /**
     * DG15 = {@code 6F { SubjectPublicKeyInfo } } for an RSA AA key
     * (ICAO Doc 9303-11 §6.1.5).
     */
    private static byte[] dg15Rsa(BigInteger modulus) {
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
    private static byte[] dg15Ec(byte[] subjectPublicKeyInfo) {
        return tlv(0x6F, subjectPublicKeyInfo);
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

    private static byte aaAlgorithmByte(String algorithm) {
        if ("ecdsa".equalsIgnoreCase(algorithm)) {
            return AA_ALGORITHM_ECDSA;
        }
        return "sha256".equalsIgnoreCase(algorithm) ? AA_ALGORITHM_SHA256 : AA_ALGORITHM_SHA1;
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return java.security.MessageDigest.getInstance("SHA-256").digest(data);
    }

    /**
     * The 20-byte PACE key seed SHA-1(MRZ_information) (DGI FF04).
     */
    private static byte[] paceSeed(String documentNumber, String dateOfBirth,
                                   String dateOfExpiry) throws Exception {
        return java.security.MessageDigest.getInstance("SHA-1").digest(
                MrzKeySeed.mrzInformation(documentNumber, dateOfBirth, dateOfExpiry));
    }

    /** The PACE password encoding {@code f(CAN)} (DGI FF06, password reference 0x02). */
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
        String aa = DEFAULT_AA;
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
            } else if (arg.startsWith("-aa=")) {
                aa = arg.substring("-aa=".length());
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
            System.out.print(script(aa, dscPath, dscKeyPath, portrait));
            return;
        }
        LdsScript parsed;
        if (scriptPath != null) {
            parsed = LdsScript.parse(new File(scriptPath));
        } else {
            parsed = LdsScript.parse(script(aa, dscPath, dscKeyPath, portrait));
        }
        for (LdsScript.Entry entry : parsed.entries) {
            System.out.println(entry.aid + " " + Hex.format(dgiSequence(entry, dsc, dscKey)));
        }
    }
}
