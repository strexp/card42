package card42.host.emrtd.ta;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

import card42.host.common.crypto.Ecdsa;
import card42.host.common.crypto.RsaPss;

/**
 * Builds CV certificates for the Terminal Authentication ECDSA profile
 * (BSI TR-03110-3 C.1, ICAO Doc 9303-11 §7.1.4.2).  The signature is created
 * with the self-contained {@link Ecdsa} and is the TR-03111 plain
 * {@code r||s} form, over the encoded body TLV (tag and length included).
 */
public final class CvCertificateBuilder {

    private CvCertificateBuilder() {
    }

    /**
     * Builds and signs a CV certificate, returning the parsed result so the
     * caller can read back the body/signature.
     */
    public static CvCertificate build(int profileId, CvcPrincipal car, CvcPrincipal chr,
                                      Chat.Role role, byte[] relativeAuthorization,
                                      byte[] publicPointW, String effective, String expiration,
                                      Map<String, byte[]> extensions,
                                      BigInteger signerPrivateScalar, SecureRandom random) {
        byte[] body = CvCertificateCodec.encodeBody(profileId, car,
                CvCertificate.OID_TA_ECDSA_SHA_256, publicPointW, chr, role,
                relativeAuthorization, effective, expiration, extensions);
        byte[] signature = Ecdsa.sign(body, signerPrivateScalar, random);
        return CvCertificateCodec.parse(CvCertificateCodec.encode(body, signature));
    }

    /**
     * Builds and signs a CV certificate whose subject public key is RSA (the
     * RSA-PSS-SHA-256 profile); the signature is created with the signer's
     * RSA private key (BSI TR-03110-3 C.1.2.2).
     */
    public static CvCertificate buildRsa(int profileId, CvcPrincipal car, CvcPrincipal chr,
                                         Chat.Role role, byte[] relativeAuthorization,
                                         byte[] modulus, byte[] exponent, String effective,
                                         String expiration, Map<String, byte[]> extensions,
                                         java.security.PrivateKey signerKey) {
        byte[] body = CvCertificateCodec.encodeBodyRsa(profileId, car,
                CvCertificate.OID_TA_RSA_PSS_SHA_256, modulus, exponent, chr, role,
                relativeAuthorization, effective, expiration, extensions);
        byte[] signature = RsaPss.sign(body, signerKey);
        return CvCertificateCodec.parse(CvCertificateCodec.encode(body, signature));
    }
}
