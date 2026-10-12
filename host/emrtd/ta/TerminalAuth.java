package card42.host.emrtd.ta;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.crypto.Ecdsa;
import card42.host.common.crypto.P256;
import card42.host.common.crypto.RsaPss;
import card42.host.common.util.Bytes;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Terminal-side Terminal Authentication, ECDSA-SHA-256 profile
 * (ICAO Doc 9303-11 §7.1, BSI TR-03110-3 A.7): sends the CV certificate chain
 * with {@code MSE:Set DST} + {@code PSO:Verify Certificate}, selects the
 * terminal key with {@code MSE:Set AT}, gets the chip challenge and answers it
 * with {@code EXTERNAL AUTHENTICATE}.
 *
 * <p>The signed message is {@code ID_IC || rIC || Comp(PKDH,IFD)}; for the ECDSA
 * profile {@code Comp} is the x-coordinate (32 bytes).  {@code ID_IC} is the
 * PICC's PACE key hash ({@link #chipIdentifier}) and {@code Comp(PKDH,IFD)} is
 * the terminal's Chip Authentication key hash ({@link #chipAuthenticationKeyHash}).
 */
public final class TerminalAuth {

    /** Terminal Authentication result. */
    public static final class Result {
        public final CvCertificate terminalCertificate;
        public final byte[] chipChallenge;
        public final byte[] identifier;
        public final byte[] chipAuthenticationKeyHash;

        Result(CvCertificate terminalCertificate, byte[] chipChallenge, byte[] identifier,
               byte[] chipAuthenticationKeyHash) {
            this.terminalCertificate = terminalCertificate;
            this.chipChallenge = chipChallenge;
            this.identifier = identifier;
            this.chipAuthenticationKeyHash = chipAuthenticationKeyHash;
        }
    }

    private TerminalAuth() {
    }

    /** {@code ID_IC = Comp(PKDH,IC)} = the x-coordinate of the PICC PACE key. */
    public static byte[] chipIdentifier(byte[] piccPublicKeyW) {
        return P256.x(P256.decode(piccPublicKeyW));
    }

    /** {@code Comp(PKDH,IFD)} = the x-coordinate of the terminal's CA key. */
    public static byte[] chipAuthenticationKeyHash(byte[] terminalPublicKeyW) {
        return P256.x(P256.decode(terminalPublicKeyW));
    }

    /** The message that the terminal signs: {@code ID_IC || rIC || Comp(PKDH,IFD)}. */
    public static byte[] signatureInput(byte[] identifier, byte[] chipChallenge,
                                        byte[] chipAuthenticationKeyHash) {
        return Bytes.concat(identifier, chipChallenge, chipAuthenticationKeyHash);
    }

    /**
     * Runs Terminal Authentication.  {@code certificateChain} is issuer-first
     * and must not contain a self-signed CVCA trust anchor (ICAO Doc 9303-11
     * §7.1.5); the chain is sent as-is.
     */
    public static Result authenticate(EmrtdTerminal terminal, List<CvCertificate> certificateChain,
                                      BigInteger terminalPrivateScalar, byte[] identifier,
                                      byte[] chipAuthenticationKeyHash, SecureRandom random)
            throws Exception {
        return authenticate(terminal, certificateChain, terminalPrivateScalar, null,
                identifier, chipAuthenticationKeyHash, random);
    }

    /**
     * Runs Terminal Authentication; the terminal signature algorithm follows
     * the terminal certificate's public-key OID (ECDSA-SHA-256 plain or
     * RSA-PSS-SHA-256).  Exactly the matching private key must be supplied.
     */
    public static Result authenticate(EmrtdTerminal terminal, List<CvCertificate> certificateChain,
                                      BigInteger terminalPrivateScalar,
                                      java.security.PrivateKey terminalRsaKey,
                                      byte[] identifier, byte[] chipAuthenticationKeyHash,
                                      SecureRandom random) throws Exception {
        if (certificateChain == null || certificateChain.isEmpty()) {
            throw new IllegalArgumentException("terminal authentication needs a certificate chain");
        }
        CvCertificate terminalCertificate = null;
        for (CvCertificate certificate : certificateChain) {
            ResponseAPDU dst = terminal.mseSetDst(
                    certificate.certificationAuthorityReference().encode());
            requireOk(dst, "MSE:Set DST "
                    + certificate.certificationAuthorityReference());
            ResponseAPDU verify = terminal.psoVerifyCertificate(
                    certificate.body(), CvCertificateCodec.signatureTlv(certificate.signature()));
            requireOk(verify, "PSO:Verify Certificate "
                    + certificate.certificateHolderReference());
            terminalCertificate = certificate;
        }

        ResponseAPDU at = terminal.mseSetAt(
                terminalCertificate.certificateHolderReference().encode());
        requireOk(at, "MSE:Set AT " + terminalCertificate.certificateHolderReference());

        byte[] chipChallenge = terminal.getChallenge();
        byte[] input = signatureInput(identifier, chipChallenge, chipAuthenticationKeyHash);
        byte[] signature;
        if (terminalCertificate.isRsa()) {
            if (terminalRsaKey == null) {
                throw new IllegalArgumentException(
                        "RSA terminal certificate needs an RSA private key");
            }
            signature = RsaPss.sign(input, terminalRsaKey);
        } else {
            signature = Ecdsa.sign(input, terminalPrivateScalar, random);
        }
        ResponseAPDU auth = terminal.externalAuthenticate(signature);
        requireOk(auth, "EXTERNAL AUTHENTICATE");

        return new Result(terminalCertificate, chipChallenge, identifier, chipAuthenticationKeyHash);
    }

    private static void requireOk(ResponseAPDU response, String what) {
        if (response.getSW() != 0x9000) {
            throw new IllegalStateException(what + " failed: "
                    + String.format("%04X", response.getSW()));
        }
    }
}
