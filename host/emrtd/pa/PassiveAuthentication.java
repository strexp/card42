package card42.host.emrtd.pa;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.List;

import card42.host.common.codec.Der;
import card42.host.common.codec.DerWriter;
import card42.host.emrtd.lds.AlgorithmIds;
import card42.host.emrtd.lds.CmsSignedData;
import card42.host.emrtd.lds.LdsSecurityObject;
import card42.host.emrtd.lds.Sod;

/**
 * Passive Authentication (ICAO Doc 9303-11 §5.1, H3.6): verify the DSC against
 * the CSCA store, verify the SOD signature, then compare each read data group
 * against its hash in the LDS Security Object.
 *
 * <p>The DSC is selected by matching the SignerInfo {@code sid} against the
 * certificates carried in the SignedData (RFC 5652 §5.4), and the mandatory
 * {@code contentType} signed attribute is checked against the encapsulated
 * content type (§5.3).
 */
public final class PassiveAuthentication {

    private static final String OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
    private static final String OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    private static final String OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";

    private PassiveAuthentication() {
    }

    /** Verifies the DSC chain and the SOD signature; returns the security object. */
    public static LdsSecurityObject verify(Sod sod, CscaKeyStore trust) throws Exception {
        X509Certificate dsc = selectSigner(sod.cms, trust);
        verifySignature(sod.cms, dsc);
        return sod.securityObject;
    }

    /** True when the data group bytes match the hash in the security object. */
    public static boolean verifyDataGroup(LdsSecurityObject securityObject, int dataGroup,
                                          byte[] bytes) throws Exception {
        byte[] expected = securityObject.dataGroupHashes.get(dataGroup);
        return expected != null
                && Arrays.equals(expected, digest(securityObject.digestAlgorithm, bytes));
    }

    /**
     * Selects the certificate named by the SignerInfo sid and verifies it
     * against the trusted CSCA store (RFC 5652 §5.4, ICAO Doc 9303-12 H3.5).
     */
    private static X509Certificate selectSigner(CmsSignedData cms, CscaKeyStore trust)
            throws Exception {
        if (cms.certificates.isEmpty()) {
            throw new IllegalStateException("SOD carries no certificate");
        }
        if (cms.signerIdentifier == null) {
            throw new IllegalStateException("SOD SignerInfo has no signer identifier");
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        for (byte[] der : cms.certificates) {
            X509Certificate cert = (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(der));
            if (matchesSignerIdentifier(cms.signerIdentifier, cert)) {
                return DscVerifier.verify(der, trust);
            }
        }
        throw new IllegalStateException("no certificate matches the SignerInfo sid");
    }

    /** Matches a SignerIdentifier (IssuerAndSerialNumber or [0] SKI) to a certificate. */
    private static boolean matchesSignerIdentifier(byte[] sid, X509Certificate cert)
            throws Exception {
        Der.Tlv choice = Der.read(sid, 0);
        if (choice.tag == 0x30) {
            // IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }.
            List<Der.Tlv> parts = Der.children(sid, choice);
            if (parts.size() < 2) {
                return false;
            }
            byte[] issuer = Der.encoded(sid, parts.get(0));
            BigInteger serial = new BigInteger(1, Der.value(sid, parts.get(1)));
            return serial.equals(cert.getSerialNumber())
                    && Arrays.equals(issuer, cert.getIssuerX500Principal().getEncoded());
        }
        if (choice.tag == 0x80) {
            // [0] IMPLICIT SubjectKeyIdentifier ::= OCTET STRING.
            byte[] keyId = Der.value(sid, choice);
            byte[] extension = cert.getExtensionValue(OID_SUBJECT_KEY_IDENTIFIER);
            if (extension == null) {
                return false;
            }
            // getExtensionValue returns OCTET STRING { OCTET STRING keyIdentifier }.
            Der.Tlv outer = Der.read(extension, 0);
            byte[] inner = Der.value(extension, outer);
            Der.Tlv ski = Der.read(inner, 0);
            return Arrays.equals(keyId, Der.value(inner, ski));
        }
        return false;
    }

    private static void verifySignature(CmsSignedData cms, X509Certificate dsc) throws Exception {
        byte[] data;
        if (cms.signedAttrs != null) {
            // RFC 5652 §5.3: contentType and messageDigest are mandatory.
            String contentType = contentTypeAttribute(cms.signedAttrs);
            if (contentType == null || !contentType.equals(cms.eContentType)) {
                throw new IllegalStateException("SOD contentType attribute mismatch");
            }
            byte[] expected = messageDigestAttribute(cms.signedAttrs);
            byte[] actual = digest(cms.digestAlgorithm, cms.eContent);
            if (!Arrays.equals(expected, actual)) {
                throw new IllegalStateException("SOD messageDigest attribute mismatch");
            }
            // The signature is over signedAttrs re-encoded as a SET OF.
            data = DerWriter.set(cms.signedAttrs);
        } else {
            data = cms.eContent;
        }
        Signature verifier = signatureVerifier(cms);
        verifier.initVerify(dsc.getPublicKey());
        verifier.update(data);
        if (!verifier.verify(cms.signature)) {
            throw new IllegalStateException("SOD signature is invalid");
        }
    }

    /**
     * Builds the JDK verifier for the SignerInfo signature algorithm.
     * RSASSA-PSS (RFC 4055) needs the parameters carried in the signature
     * AlgorithmIdentifier; PKCS#1 v1.5 and ECDSA are self-describing.
     */
    private static Signature signatureVerifier(CmsSignedData cms) throws Exception {
        if (!AlgorithmIds.RSASSA_PSS.equals(cms.signatureAlgorithm)) {
            return Signature.getInstance(cms.signatureAlgorithm);
        }
        Signature verifier = Signature.getInstance(AlgorithmIds.RSASSA_PSS);
        verifier.setParameter(pssParameterSpec(cms.signatureAlgorithmParameters));
        return verifier;
    }

    /**
     * Parses an RSASSA-PSS-params SEQUENCE (RFC 4055) into a
     * {@code PSSParameterSpec}.  Absent fields take the RFC 4055 defaults
     * (SHA-1, MGF1-SHA1, 20-byte salt, trailer 1).
     */
    private static PSSParameterSpec pssParameterSpec(byte[] params) {
        String hash = "SHA-1";
        String mgfHash = "SHA-1";
        int saltLength = 20;
        int trailerField = 1;
        if (params != null && params.length > 0) {
            Der.Tlv sequence = Der.read(params, 0);
            for (Der.Tlv field : Der.children(params, sequence)) {
                switch (field.tag & 0xFF) {
                case 0xA0:
                    hash = AlgorithmIds.digest(algorithmOid(params, field));
                    break;
                case 0xA1:
                    Der.Tlv maskGen = Der.children(params, field).get(0);
                    List<Der.Tlv> mgf = Der.children(params, maskGen);
                    if (mgf.size() > 1) {
                        mgfHash = AlgorithmIds.digest(algorithmOid(params, mgf.get(1)));
                    }
                    break;
                case 0xA2:
                    saltLength = Der.intValue(params, Der.children(params, field).get(0));
                    break;
                case 0xA3:
                    trailerField = Der.intValue(params, Der.children(params, field).get(0));
                    break;
                default:
                    break;
                }
            }
        }
        return new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(mgfHash),
                saltLength, trailerField);
    }

    /**
     * The hash OID of an AlgorithmIdentifier, whether passed directly (a
     * SEQUENCE) or wrapped in an explicit tag such as {@code [0] { SEQ { OID } }}.
     */
    private static String algorithmOid(byte[] buf, Der.Tlv tlv) {
        Der.Tlv algorithm = tlv.tag == 0x30 ? tlv : Der.children(buf, tlv).get(0);
        return Der.oid(buf, Der.children(buf, algorithm).get(0));
    }

    /** The dotted-decimal contentType signed attribute, or null when absent. */
    private static String contentTypeAttribute(byte[] signedAttrsContent) {
        byte[] set = DerWriter.set(signedAttrsContent);
        Der.Tlv root = Der.read(set, 0);
        for (Der.Tlv attribute : Der.children(set, root)) {
            List<Der.Tlv> parts = Der.children(set, attribute);
            if (OID_CONTENT_TYPE.equals(Der.oid(set, parts.get(0)))) {
                Der.Tlv values = parts.get(1);
                return Der.oid(set, Der.children(set, values).get(0));
            }
        }
        return null;
    }

    private static byte[] messageDigestAttribute(byte[] signedAttrsContent) {
        byte[] set = DerWriter.set(signedAttrsContent);
        Der.Tlv root = Der.read(set, 0);
        for (Der.Tlv attribute : Der.children(set, root)) {
            List<Der.Tlv> parts = Der.children(set, attribute);
            if (OID_MESSAGE_DIGEST.equals(Der.oid(set, parts.get(0)))) {
                Der.Tlv values = parts.get(1);
                Der.Tlv octets = Der.children(set, values).get(0);
                return Der.value(set, octets);
            }
        }
        throw new IllegalStateException("SOD signedAttrs has no messageDigest");
    }

    private static byte[] digest(String algorithm, byte[] data) throws Exception {
        return MessageDigest.getInstance(algorithm).digest(data);
    }
}
