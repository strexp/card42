package card42.host.emrtd.pa;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import card42.host.common.codec.Der;
import card42.host.common.codec.DerWriter;
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
        Signature verifier = Signature.getInstance(cms.signatureAlgorithm);
        verifier.initVerify(dsc.getPublicKey());
        verifier.update(data);
        if (!verifier.verify(cms.signature)) {
            throw new IllegalStateException("SOD signature is invalid");
        }
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
