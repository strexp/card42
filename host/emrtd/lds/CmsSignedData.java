package card42.host.emrtd.lds;

import java.util.ArrayList;
import java.util.List;

import card42.host.common.codec.Der;

/**
 * The CMS SignedData of EF.SOD (RFC 5652, ICAO Doc 9303-10 §4.6.2), reduced to
 * what Passive Authentication needs: the encapsulated LDS Security Object, the
 * signer's certificate, the signed attributes and the signature (H3.1).
 */
public final class CmsSignedData {

    public final byte[] eContent;
    /** The eContentType OID of the encapsulated content (RFC 5652 §5.1). */
    public final String eContentType;
    /** The first certificate in the certificates field, or null. */
    public final byte[] signerCertificate;
    /** Every certificate in the certificates [0] field, in order. */
    public final List<byte[]> certificates;
    /** The DER-encoded SignerInfo sid (IssuerAndSerialNumber or [0] SKI). */
    public final byte[] signerIdentifier;
    /** Content of signedAttrs ([0] IMPLICIT), or null when absent. */
    public final byte[] signedAttrs;
    public final String digestAlgorithm;
    public final String signatureAlgorithm;
    public final byte[] signature;

    private CmsSignedData(byte[] eContent, String eContentType, byte[] signerCertificate,
                          List<byte[]> certificates, byte[] signerIdentifier, byte[] signedAttrs,
                          String digestAlgorithm, String signatureAlgorithm, byte[] signature) {
        this.eContent = eContent;
        this.eContentType = eContentType;
        this.signerCertificate = signerCertificate;
        this.certificates = certificates;
        this.signerIdentifier = signerIdentifier;
        this.signedAttrs = signedAttrs;
        this.digestAlgorithm = digestAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
    }

    public static CmsSignedData parse(byte[] sod) {
        Der.Tlv contentInfo = Der.read(sod, 0);
        List<Der.Tlv> ci = Der.children(sod, contentInfo);
        // ci[0] = contentType OID, ci[1] = [0] EXPLICIT SignedData.
        Der.Tlv signedData = Der.children(sod, ci.get(1)).get(0);
        List<Der.Tlv> sd = Der.children(sod, signedData);

        // encapContentInfo = SEQ { OID, [0] { OCTET STRING eContent } }.
        Der.Tlv encap = sd.get(2);
        List<Der.Tlv> encapFields = Der.children(sod, encap);
        String eContentType = Der.oid(sod, encapFields.get(0));
        Der.Tlv octets = Der.children(sod, encapFields.get(1)).get(0);
        byte[] eContent = Der.value(sod, octets);

        // certificates [0] IMPLICIT SET OF Certificate (RFC 5652 §5.1).
        List<byte[]> certificates = new ArrayList<byte[]>();
        for (Der.Tlv field : sd) {
            if (field.tag == 0xA0) {
                for (Der.Tlv cert : Der.children(sod, field)) {
                    certificates.add(Der.encoded(sod, cert));
                }
                break;
            }
        }
        byte[] signerCert = certificates.isEmpty() ? null : certificates.get(0);

        // signerInfos SET OF SignerInfo (first).  si[1] is the SignerIdentifier.
        Der.Tlv signerInfos = sd.get(sd.size() - 1);
        Der.Tlv signerInfo = Der.children(sod, signerInfos).get(0);
        List<Der.Tlv> si = Der.children(sod, signerInfo);
        byte[] signerIdentifier = Der.encoded(sod, si.get(1));

        String digestAlg = AlgorithmIds.digest(
                Der.oid(sod, Der.children(sod, si.get(2)).get(0)));
        byte[] signedAttrs = null;
        int p = 3;
        if (si.get(p).tag == 0xA0) {
            signedAttrs = Der.value(sod, si.get(p));
            p++;
        }
        String sigAlg = AlgorithmIds.signature(
                Der.oid(sod, Der.children(sod, si.get(p)).get(0)));
        p++;
        byte[] signature = Der.value(sod, si.get(p));

        return new CmsSignedData(eContent, eContentType, signerCert, certificates,
                signerIdentifier, signedAttrs, digestAlg, sigAlg, signature);
    }
}
