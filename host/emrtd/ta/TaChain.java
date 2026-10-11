package card42.host.emrtd.ta;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import card42.host.common.crypto.P256;

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

    /** An issued chain: the self-signed CVCA trust anchor, the DV and the terminal (IS) certificate. */
    public static final class Chain {
        public final CvCertificate cvca;
        public final CvCertificate dv;
        public final CvCertificate terminal;
        public final BigInteger terminalPrivateScalar;
        public final byte[] terminalPublicKeyW;

        Chain(CvCertificate cvca, CvCertificate dv, CvCertificate terminal,
              BigInteger terminalPrivateScalar, byte[] terminalPublicKeyW) {
            this.cvca = cvca;
            this.dv = dv;
            this.terminal = terminal;
            this.terminalPrivateScalar = terminalPrivateScalar;
            this.terminalPublicKeyW = terminalPublicKeyW;
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

    /** Issues a chain from explicit CVCA/DV/IS private scalars. */
    public static Chain create(BigInteger cvcaScalar, BigInteger dvScalar,
                               BigInteger isScalar, SecureRandom random) {
        Map<String, byte[]> cvcaAuth = new LinkedHashMap<String, byte[]>();
        cvcaAuth.put(CvCertificate.OID_LDS2_TRAVEL, new byte[] { (byte) 0x0F });
        cvcaAuth.put(CvCertificate.OID_LDS2_VISA, new byte[] { (byte) 0x0F });
        cvcaAuth.put(CvCertificate.OID_LDS2_BIOMETRICS, new byte[] { (byte) 0x0F });

        Map<String, byte[]> dvAuth = new LinkedHashMap<String, byte[]>();
        dvAuth.put(CvCertificate.OID_LDS2_TRAVEL, new byte[] { (byte) 0x0F });
        dvAuth.put(CvCertificate.OID_LDS2_VISA, new byte[] { (byte) 0x0F });
        dvAuth.put(CvCertificate.OID_LDS2_BIOMETRICS, new byte[] { (byte) 0x0F });

        Map<String, byte[]> isAuth = new LinkedHashMap<String, byte[]>();
        isAuth.put(CvCertificate.OID_LDS2_TRAVEL, new byte[] { (byte) 0x0F });
        isAuth.put(CvCertificate.OID_LDS2_VISA, new byte[] { (byte) 0x0F });
        isAuth.put(CvCertificate.OID_LDS2_BIOMETRICS, new byte[] { (byte) 0x0F });

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
}
