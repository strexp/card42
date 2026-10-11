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
 */
public final class TaChain {

    private static final String DATE_FROM = "250101";
    private static final String DATE_TO = "300101";

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

    /** Issues a chain.  The IS (terminal) key pair is returned for {@code EXTERNAL AUTHENTICATE}. */
    public static Chain create(SecureRandom random) {
        Map<String, byte[]> cvcaAuth = new LinkedHashMap<String, byte[]>();
        cvcaAuth.put(CvCertificate.OID_LDS2_TRAVEL, new byte[] { (byte) 0x0F });
        cvcaAuth.put(CvCertificate.OID_LDS2_VISA, new byte[] { (byte) 0x0F });
        cvcaAuth.put(CvCertificate.OID_LDS2_BIOMETRICS, new byte[] { (byte) 0x0F });

        Map<String, byte[]> dvAuth = new LinkedHashMap<String, byte[]>();
        dvAuth.put(CvCertificate.OID_LDS2_TRAVEL, new byte[] { (byte) 0x03 });
        dvAuth.put(CvCertificate.OID_LDS2_VISA, new byte[] { (byte) 0x03 });
        dvAuth.put(CvCertificate.OID_LDS2_BIOMETRICS, new byte[] { (byte) 0x03 });

        Map<String, byte[]> isAuth = new LinkedHashMap<String, byte[]>();
        isAuth.put(CvCertificate.OID_LDS2_TRAVEL, new byte[] { (byte) 0x03 });
        isAuth.put(CvCertificate.OID_LDS2_VISA, new byte[] { (byte) 0x03 });
        isAuth.put(CvCertificate.OID_LDS2_BIOMETRICS, new byte[] { (byte) 0x03 });

        CvcPrincipal cvcaRef = CvcPrincipal.of("UTCVCA0000000001");
        CvcPrincipal dvRef = CvcPrincipal.of("UTDV000000000002");
        CvcPrincipal isRef = CvcPrincipal.of("UTIS000000000003");

        BigInteger cvcaScalar = P256.randomScalar(random);
        byte[] cvcaW = P256.encode(P256.scalarMult(cvcaScalar, P256.generator()));
        CvCertificate cvca = CvCertificateBuilder.build(0, cvcaRef, cvcaRef, Chat.Role.CVCA,
                new byte[] { (byte) 0x03 }, cvcaW, DATE_FROM, DATE_TO, cvcaAuth, cvcaScalar, random);

        BigInteger dvScalar = P256.randomScalar(random);
        byte[] dvW = P256.encode(P256.scalarMult(dvScalar, P256.generator()));
        CvCertificate dv = CvCertificateBuilder.build(0, cvcaRef, dvRef, Chat.Role.DV_DOMESTIC,
                new byte[] { (byte) 0x03 }, dvW, DATE_FROM, DATE_TO, dvAuth, cvcaScalar, random);

        BigInteger terminalScalar = P256.randomScalar(random);
        byte[] terminalW = P256.encode(P256.scalarMult(terminalScalar, P256.generator()));
        CvCertificate terminal = CvCertificateBuilder.build(0, dvRef, isRef, Chat.Role.IS,
                new byte[] { (byte) 0x03 }, terminalW, DATE_FROM, DATE_TO, isAuth, dvScalar, random);

        return new Chain(cvca, dv, terminal, terminalScalar, terminalW);
    }
}
