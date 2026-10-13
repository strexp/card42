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
import card42.host.emrtd.lds.security.SecurityInfo;
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

    /* The demo fixtures and their constants live in SampleData; re-exported
     * here because the CLI/tests reference them as EmrtdPersoExporter.X. */
    public static final String LINE1 = SampleData.LINE1;
    public static final String LINE2 = SampleData.LINE2;
    public static final String DOCUMENT_NUMBER = SampleData.DOCUMENT_NUMBER;
    public static final String DATE_OF_BIRTH = SampleData.DATE_OF_BIRTH;
    public static final String DATE_OF_EXPIRY = SampleData.DATE_OF_EXPIRY;
    public static final String CARD_ACCESS_NUMBER = SampleData.CARD_ACCESS_NUMBER;

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
        writeDgi(out, 0xFF04, SampleData.paceSeed(entry.documentNumber, entry.dateOfBirth,
                entry.dateOfExpiry));
        if (entry.can != null) {
            writeDgi(out, DGI_PACE_CAN_SEED, SampleData.canSeed(entry.can));
        }
        for (Map.Entry<Integer, byte[]> dg : entry.dataGroups.entrySet()) {
            writeDgi(out, LdsFileUtil.dgFid(dg.getKey()), dg.getValue());
        }
        // EF.CardAccess in the master file (Doc 9303-10 §3.11.3): PACE, Chip
        // Authentication and, for the ECDSA AA variant, ActiveAuthenticationInfo.
        writeDgi(out, LdsFileUtil.FID_CARD_ACCESS,
                entry.cardAccess != null ? entry.cardAccess : SampleData.cardAccessInfos(entry.aaAlgorithm));
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
                hashes.put(dg.getKey(), SampleData.sha256(dg.getValue()));
            }
            writeDgi(out, LdsFileUtil.FID_SOD, SodBuilder.build(hashes, dscKey, dscCertificate));
        }
        // Active Authentication key material + algorithm (mutually exclusive).
        writeDgi(out, DGI_AA_ALGORITHM, new byte[] { SampleData.aaAlgorithmByte(entry.aaAlgorithm) });
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
                    SampleData.paceSeed(entry.documentNumber, entry.dateOfBirth, entry.dateOfExpiry));
        }
        if (entry.can != null) {
            writeDgi(out, 0xFF06, SampleData.canSeed(entry.can));
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

        Map<Integer, byte[]> dgs = SampleData.dataGroups(portrait);
        // AA material: RSA (SHA-1/256) or ECDSA.
        byte[] aaKey = null;
        byte[] aaEcKey = null;
        if ("ecdsa".equalsIgnoreCase(aa)) {
            KeyPair ecAa = SampleData.generateP256Key();
            aaEcKey = SampleData.unsigned(((ECPrivateKey) ecAa.getPrivate()).getS());
            dgs.put(15, SampleData.dg15Ec(ecAa.getPublic().getEncoded()));
        } else {
            KeyPair rsaAa = SampleData.generateAaKey();
            BigInteger modulus = ((java.security.interfaces.RSAPublicKey) rsaAa.getPublic())
                    .getModulus();
            BigInteger privateExponent = ((RSAPrivateKey) rsaAa.getPrivate()).getPrivateExponent();
            aaKey = SampleData.aaPrivateKey(modulus, privateExponent);
            dgs.put(15, SampleData.dg15Rsa(modulus));
        }

        // One Chip Authentication key pair and its SecurityInfos are shared by
        // EF.DG14, EF.CardSecurity and the LDS2 Travel application.
        KeyPair caKeyPair = SampleData.generateP256Key();
        byte[] caScalar = SampleData.unsigned(((ECPrivateKey) caKeyPair.getPrivate()).getS());
        byte[] cardAccess = SampleData.cardAccessInfos(aa);
        byte[] securityInfos = CardSecurityBuilder.securityInfos(
                caKeyPair.getPublic().getEncoded(), 1, cardAccess);
        dgs.put(14, SampleData.dg14(securityInfos));
        byte[] cardSecurity = CardSecurityBuilder.build(securityInfos, dscKey, dscCertificate);

        Map<Integer, byte[]> hashes = new LinkedHashMap<Integer, byte[]>();
        for (Map.Entry<Integer, byte[]> dg : dgs.entrySet()) {
            hashes.put(dg.getKey(), SampleData.sha256(dg.getValue()));
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
        sb.append("@doc ").append(SampleData.DOCUMENT_NUMBER).append('\n');
        sb.append("@dob ").append(SampleData.DATE_OF_BIRTH).append('\n');
        sb.append("@doe ").append(SampleData.DATE_OF_EXPIRY).append('\n');
        sb.append("@can ").append(SampleData.CARD_ACCESS_NUMBER).append('\n');
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
        LdsScript.TrustPoint ecTp = SampleData.demoTrustPoint();
        sb.append("@ta-date ").append(SampleData.TA_CURRENT_DATE).append('\n');
        sb.append("@cvca ").append(Hex.format(ecTp.publicKey)).append(' ')
                .append(ecTp.car).append(' ').append(ecTp.effective).append(' ')
                .append(Hex.format(ecTp.authorization)).append('\n');
        LdsScript.TrustPoint rsaTp = SampleData.demoRsaTrustPoint();
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
        sb.append("@doc ").append(SampleData.DOCUMENT_NUMBER).append('\n');
        sb.append("@dob ").append(SampleData.DATE_OF_BIRTH).append('\n');
        sb.append("@doe ").append(SampleData.DATE_OF_EXPIRY).append('\n');
        sb.append("@cardaccess ").append(Hex.format(cardAccess)).append('\n');
        sb.append("@cardsecurity ").append(Hex.format(cardSecurity)).append('\n');
        sb.append("@ca ").append(Hex.format(caScalar)).append('\n');
        sb.append("@record 0101 ").append(Hex.format(SampleData.sampleTravelRecord("USA", "20260101")))
                .append('\n');
        sb.append("@record 0101 ").append(Hex.format(SampleData.sampleTravelRecord("NLD", "20260215")))
                .append('\n');
        sb.append("@record 0101 ").append(Hex.format(SampleData.sampleTravelRecord("JPN", "20260320")))
                .append('\n');
        sb.append("@record 0102 ").append(Hex.format(SampleData.sampleTravelRecord("DEU", "20260601")))
                .append('\n');
        sb.append("@record 011A ").append(certHex).append('\n');

        sb.append("\n# LDS2 Visa Records: EF.VisaRecords 0103, EF.Certificates 011A.\n");
        sb.append("@instance ").append(LdsFileUtil.AID_VISA).append('\n');
        sb.append("@lds2 visa\n");
        sb.append("@doc ").append(SampleData.DOCUMENT_NUMBER).append('\n');
        sb.append("@dob ").append(SampleData.DATE_OF_BIRTH).append('\n');
        sb.append("@doe ").append(SampleData.DATE_OF_EXPIRY).append('\n');
        sb.append("@ca ").append(Hex.format(caScalar)).append('\n');
        sb.append("@record 0103 ").append(Hex.format(SampleData.sampleVisaRecord("JPN", "20260401")))
                .append('\n');
        sb.append("@record 0103 ").append(Hex.format(SampleData.sampleVisaRecord("AUS", "20260505")))
                .append('\n');
        sb.append("@record 011A ").append(certHex).append('\n');

        sb.append("\n# LDS2 Additional Biometrics: EF.Biometrics1 0201 (transparent),\n");
        sb.append("# EF.Certificates 011A.\n");
        sb.append("@instance ").append(LdsFileUtil.AID_BIOMETRICS).append('\n');
        sb.append("@lds2 biometrics\n");
        sb.append("@doc ").append(SampleData.DOCUMENT_NUMBER).append('\n');
        sb.append("@dob ").append(SampleData.DATE_OF_BIRTH).append('\n');
        sb.append("@doe ").append(SampleData.DATE_OF_EXPIRY).append('\n');
        sb.append("@ca ").append(Hex.format(caScalar)).append('\n');
        sb.append("@transparent 0201 ").append(Hex.format(SampleData.sampleBiometric())).append('\n');
        sb.append("@record 011A ").append(certHex).append('\n');
    }

    // --- LDS1 data groups ----------------------------------------------------








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
        return dateBytes(date == null ? SampleData.TA_CURRENT_DATE : date);
    }

    /** Encodes a 6-digit YYMMDD date as 6 octets of unpacked BCD. */
    private static byte[] dateBytes(String date) {
        byte[] out = new byte[6];
        for (int i = 0; i < 6; i++) {
            out[i] = (byte) (date.charAt(i) - '0');
        }
        return out;
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
