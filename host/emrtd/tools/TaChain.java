package card42.host.emrtd.tools;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import card42.host.common.crypto.P256;
import card42.host.emrtd.ta.*;

/**
 * Issues a Terminal Authentication CV certificate chain (CVCA trust anchor →
 * DV → IS terminal) for the demos and tests.  A real deployment replaces this
 * with an offline CA; the on-wire encoding is the same.
 *
 * <p>{@link #demo} uses fixed demo scalars so the personalization writer (which
 * puts the CVCA public key into the card's FF07 trust point) and an inspection
 * system (which holds the matching certificate chain) agree; the signatures are
 * still randomized.
 */
public final class TaChain {

    private static final String DATE_FROM = "250101";
    private static final String DATE_TO = "300101";

    /*
     * Fixed demo keys (NOT for production): the CVCA/DV/IS private scalars that
     * the demo personalization and the integration suites share.  They are
     * deliberately printed here so a reader can reproduce the whole chain.
     */
    private static final BigInteger DEMO_CVCA = new BigInteger(
            "33D2A1C7A9F1B4E6082C5A9E3F1D7B8C4A6E2F0B9D3C5A7182E4B6D8F0A2C4E6", 16);
    private static final BigInteger DEMO_DV = new BigInteger(
            "7B1E3A5C9D2F40681A3C5E7092B4D6F8A0C2E41638570A9C1D3E5F720486A0C2", 16);
    private static final BigInteger DEMO_IS = new BigInteger(
            "A0C2E41638570A9C1D3E5F7204864806A2C4E6183A5C790D1F3B5A7294860C4E", 16);

    /*
     * Fixed RSA-1024 demo key (NOT for production) shared by the RSA-PSS demo
     * trust point (personalization DGI FF0B) and the integration suites, so the
     * card's RSA CVCA and the terminal's chain agree.  The same key backs the
     * CVCA, DV and IS certificates of the RSA demo chain.
     */
    private static final BigInteger DEMO_RSA_MODULUS = new BigInteger(
            "CFC364E7BF8C86743800B986396B3DF393C65D5277D5D1AC0636BA652FD347A3"
            + "9975638E831C524987CAFD717B69715349E4381FD4DD4C87C5E4094A1978E7CA"
            + "318D33F1AF99FBBC4D52E04755012138BB92562200CB6B174D6F955772BDE6EE"
            + "5FDEB2BD89B0685F9BB6F3BAEAEF0189C67349307F2E8524DE0DA2EA99893DEB", 16);
    private static final BigInteger DEMO_RSA_PRIVATE = new BigInteger(
            "1321C821FB26A29F032535F0614B39DA3B4A71FF8D1F787E61D81A5405126CAF"
            + "690B414EB74E1D59BE12784241FE14BC79BA755CA10A7BE8A8D575F187E4F55B"
            + "2383C6C49608FBE6948E05C997E5685AAC3E702AD9A482BFC798C9E8A1549C65"
            + "F82F136189BA4D33D8F9B5E56CC81E72B65F7D469BBA07C51DF04F21C7543409", 16);
    /** The RSA demo CVCA Certificate Authority Reference (distinct from the EC one). */
    public static final String DEMO_RSA_CAR = "UTCVCA0000000002";

    /** An issued chain: the self-signed CVCA trust anchor, the DV and the terminal (IS) certificate. */
    public static final class Chain {
        public final CvCertificate cvca;
        public final CvCertificate dv;
        public final CvCertificate terminal;
        public final BigInteger terminalPrivateScalar;
        public final byte[] terminalPublicKeyW;
        /** The RSA-PSS terminal private key, or null for the ECDSA chain. */
        public final java.security.PrivateKey terminalRsaKey;

        Chain(CvCertificate cvca, CvCertificate dv, CvCertificate terminal,
              BigInteger terminalPrivateScalar, byte[] terminalPublicKeyW) {
            this(cvca, dv, terminal, terminalPrivateScalar, terminalPublicKeyW, null);
        }

        Chain(CvCertificate cvca, CvCertificate dv, CvCertificate terminal,
              BigInteger terminalPrivateScalar, byte[] terminalPublicKeyW,
              java.security.PrivateKey terminalRsaKey) {
            this.cvca = cvca;
            this.dv = dv;
            this.terminal = terminal;
            this.terminalPrivateScalar = terminalPrivateScalar;
            this.terminalPublicKeyW = terminalPublicKeyW;
            this.terminalRsaKey = terminalRsaKey;
        }

        /** The certificates to send to the card (issuer-first, no self-signed anchor). */
        public List<byte[]> toSend() {
            List<byte[]> out = new ArrayList<byte[]>();
            out.add(dv.encoded());
            out.add(terminal.encoded());
            return out;
        }

        /** The full chain including the CVCA trust anchor (for authorization computation). */
        public List<CvCertificate> fullChain() {
            List<CvCertificate> out = new ArrayList<CvCertificate>();
            out.add(cvca);
            out.add(dv);
            out.add(terminal);
            return out;
        }
    }

    private TaChain() {
    }

    /** Issues a random chain (unit tests). */
    public static Chain create(SecureRandom random) {
        return create(P256.randomScalar(random), P256.randomScalar(random),
                P256.randomScalar(random), random);
    }

    /** Issues the deterministic demo chain shared by the personalization and the suites. */
    public static Chain demo(SecureRandom random) {
        return create(DEMO_CVCA, DEMO_DV, DEMO_IS, random);
    }

    /** Demo chain with a restricted Travel Records authorization byte (Table 96). */
    public static Chain demo(SecureRandom random, byte travelAuth) {
        return create(DEMO_CVCA, DEMO_DV, DEMO_IS, random, travelAuth);
    }

    /** The RSA demo CVCA public modulus (DGI FF0B trust point). */
    public static byte[] demoRsaModulus() {
        return unsigned(DEMO_RSA_MODULUS);
    }

    /** The RSA demo public exponent (65537). */
    public static byte[] demoRsaExponent() {
        return new byte[] { 0x01, 0x00, 0x01 };
    }

    /**
     * Issues the deterministic demo RSA-PSS chain (CVCA/DV/IS) used by the RSA
     * Terminal Authentication profile; the same key backs every certificate.
     */
    public static Chain demoRsa() {
        java.security.PrivateKey key = rsaPrivate();
        byte[] mod = demoRsaModulus();
        byte[] exp = demoRsaExponent();

        Map<String, byte[]> auth = new LinkedHashMap<String, byte[]>();
        auth.put(CvCertificate.OID_LDS2_TRAVEL, new byte[] { (byte) 0x0F });
        auth.put(CvCertificate.OID_LDS2_VISA, new byte[] { (byte) 0x0F });
        auth.put(CvCertificate.OID_LDS2_BIOMETRICS, new byte[] { (byte) 0x0F });

        CvcPrincipal cvcaRef = CvcPrincipal.of(DEMO_RSA_CAR);
        CvcPrincipal dvRef = CvcPrincipal.of("UTDV000000000002");
        CvcPrincipal isRef = CvcPrincipal.of("UTIS000000000003");

        CvCertificate cvca = CvCertificateBuilder.buildRsa(0, cvcaRef, cvcaRef, Chat.Role.CVCA,
                new byte[] { (byte) 0x03 }, mod, exp, DATE_FROM, DATE_TO, auth, key);
        CvCertificate dv = CvCertificateBuilder.buildRsa(0, cvcaRef, dvRef, Chat.Role.DV_DOMESTIC,
                new byte[] { (byte) 0x03 }, mod, exp, DATE_FROM, DATE_TO, auth, key);
        CvCertificate terminal = CvCertificateBuilder.buildRsa(0, dvRef, isRef, Chat.Role.IS,
                new byte[] { (byte) 0x03 }, mod, exp, DATE_FROM, DATE_TO, auth, key);

        return new Chain(cvca, dv, terminal, null, null, key);
    }

    private static java.security.PrivateKey rsaPrivate() {
        try {
            return java.security.KeyFactory.getInstance("RSA").generatePrivate(
                    new java.security.spec.RSAPrivateKeySpec(DEMO_RSA_MODULUS, DEMO_RSA_PRIVATE));
        } catch (Exception e) {
            throw new IllegalStateException("cannot build the demo RSA key", e);
        }
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            return java.util.Arrays.copyOfRange(raw, 1, raw.length);
        }
        return raw;
    }

    /** Issues a chain from explicit CVCA/DV/IS private scalars. */
    public static Chain create(BigInteger cvcaScalar, BigInteger dvScalar,
                               BigInteger isScalar, SecureRandom random) {
        return create(cvcaScalar, dvScalar, isScalar, random, (byte) 0x0F);
    }

    /**
     * Issues a chain whose Travel Records application authorization byte is
     * {@code travelAuth} (Doc 9303-10 §5.4.2 Table 96).  The trust point keeps
     * all bits; the card computes the effective authorization as the bitwise
     * AND of the trust point and every certificate extension, so this models a
     * terminal certificate restricted to read-only (0x01), certificate-read
     * only (0x04) or any other subset.
     */
    public static Chain create(BigInteger cvcaScalar, BigInteger dvScalar,
                               BigInteger isScalar, SecureRandom random, byte travelAuth) {
        Map<String, byte[]> cvcaAuth = lds2Auth(travelAuth);
        Map<String, byte[]> dvAuth = lds2Auth(travelAuth);
        Map<String, byte[]> isAuth = lds2Auth(travelAuth);

        CvcPrincipal cvcaRef = CvcPrincipal.of("UTCVCA0000000001");
        CvcPrincipal dvRef = CvcPrincipal.of("UTDV000000000002");
        CvcPrincipal isRef = CvcPrincipal.of("UTIS000000000003");

        byte[] cvcaW = P256.encode(P256.scalarMult(cvcaScalar, P256.generator()));
        CvCertificate cvca = CvCertificateBuilder.build(0, cvcaRef, cvcaRef, Chat.Role.CVCA,
                new byte[] { (byte) 0x03 }, cvcaW, DATE_FROM, DATE_TO, cvcaAuth, cvcaScalar, random);

        byte[] dvW = P256.encode(P256.scalarMult(dvScalar, P256.generator()));
        CvCertificate dv = CvCertificateBuilder.build(0, cvcaRef, dvRef, Chat.Role.DV_DOMESTIC,
                new byte[] { (byte) 0x03 }, dvW, DATE_FROM, DATE_TO, dvAuth, cvcaScalar, random);

        byte[] terminalW = P256.encode(P256.scalarMult(isScalar, P256.generator()));
        CvCertificate terminal = CvCertificateBuilder.build(0, dvRef, isRef, Chat.Role.IS,
                new byte[] { (byte) 0x03 }, terminalW, DATE_FROM, DATE_TO, isAuth, dvScalar, random);

        return new Chain(cvca, dv, terminal, isScalar, terminalW);
    }

    /** Table 96 authorization: Travel restricted, Visa/Biometrics full. */
    private static Map<String, byte[]> lds2Auth(byte travelAuth) {
        Map<String, byte[]> auth = new LinkedHashMap<String, byte[]>();
        auth.put(CvCertificate.OID_LDS2_TRAVEL, new byte[] { travelAuth });
        auth.put(CvCertificate.OID_LDS2_VISA, new byte[] { (byte) 0x0F });
        auth.put(CvCertificate.OID_LDS2_BIOMETRICS, new byte[] { (byte) 0x0F });
        return auth;
    }
}
