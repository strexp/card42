package card42.host.emrtd.perso;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import card42.host.common.codec.DerWriter;

/**
 * Builds an EF.SOD: a CMS SignedData over an LDS Security Object, signed by a
 * Document Signer key (ICAO Doc 9303-10 §4.6.2, H5.3).  The digest is SHA-256 and
 * the signature is RSA PKCS#1 v1.5.
 */
public final class SodBuilder {

    private static final String OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
    private static final String OID_LDS_SECURITY_OBJECT = "2.23.136.1.1.1";
    private static final String OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
    private static final String OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    private static final String OID_SHA256 = "2.16.840.1.101.3.4.2.1";
    private static final String OID_SHA256_RSA = "1.2.840.113549.1.1.11";

    private SodBuilder() {
    }

    /** The SOD for the given data-group hashes, signed by the DSC key. */
    public static byte[] build(Map<Integer, byte[]> dataGroupHashes, PrivateKey dscKey,
                               X509Certificate dscCertificate) throws Exception {
        // EF.SOD wraps the CMS ContentInfo in the outer tag 77 (Doc 9303-10
        // §5.3 Table 36); EF.CardSecurity does not (see buildCms).
        return DerWriter.tlv(0x77,
                buildCms(OID_LDS_SECURITY_OBJECT, ldsSecurityObject(dataGroupHashes),
                        dscKey, dscCertificate));
    }

    /**
     * Builds the CMS ContentInfo of a SignedData over an arbitrary eContent,
     * signed by the Document Signer.  EF.SOD wraps the result in the outer tag
     * {@code 77}; EF.CardSecurity is stored raw (Doc 9303-10 §3.11.4, which
     * requires a plain RFC 3369 SignedData).
     */
    public static byte[] buildCms(String eContentTypeOid, byte[] eContent, PrivateKey dscKey,
                                  X509Certificate dscCertificate) throws Exception {
        byte[] eContentDigest = MessageDigest.getInstance("SHA-256").digest(eContent);

        byte[] signedAttrsContent = DerWriter.concat(
                DerWriter.sequence(DerWriter.oid(OID_CONTENT_TYPE),
                        DerWriter.set(DerWriter.oid(eContentTypeOid))),
                DerWriter.sequence(DerWriter.oid(OID_MESSAGE_DIGEST),
                        DerWriter.set(DerWriter.octetString(eContentDigest))));
        byte[] signedAttrsSet = DerWriter.set(signedAttrsContent);

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(dscKey);
        signer.update(signedAttrsSet);
        byte[] signature = signer.sign();

        byte[] digestAlgorithm = algorithmIdentifier(OID_SHA256);
        byte[] signatureAlgorithm = algorithmIdentifier(OID_SHA256_RSA);
        byte[] sid = DerWriter.sequence(
                dscCertificate.getIssuerX500Principal().getEncoded(),
                DerWriter.integer(dscCertificate.getSerialNumber()));

        byte[] signerInfo = DerWriter.sequence(
                DerWriter.integer(1),
                sid,
                digestAlgorithm,
                DerWriter.context(0, signedAttrsContent),
                signatureAlgorithm,
                DerWriter.octetString(signature));

        byte[] signedData = DerWriter.sequence(
                DerWriter.integer(1),
                DerWriter.set(digestAlgorithm),
                DerWriter.sequence(DerWriter.oid(eContentTypeOid),
                        DerWriter.context(0, DerWriter.octetString(eContent))),
                DerWriter.context(0, dscCertificate.getEncoded()),
                DerWriter.set(signerInfo));

        return DerWriter.sequence(DerWriter.oid(OID_SIGNED_DATA),
                DerWriter.context(0, signedData));
    }

    private static byte[] ldsSecurityObject(Map<Integer, byte[]> hashes) {
        List<Integer> numbers = new ArrayList<Integer>(hashes.keySet());
        Collections.sort(numbers);
        byte[][] entries = new byte[numbers.size()][];
        for (int i = 0; i < numbers.size(); i++) {
            int number = numbers.get(i);
            entries[i] = DerWriter.sequence(DerWriter.integer(number),
                    DerWriter.octetString(hashes.get(number)));
        }
        return DerWriter.sequence(
                DerWriter.integer(0),
                algorithmIdentifier(OID_SHA256),
                DerWriter.sequence(entries));
    }

    private static byte[] algorithmIdentifier(String oid) {
        return DerWriter.sequence(DerWriter.oid(oid), DerWriter.nullValue());
    }
}
