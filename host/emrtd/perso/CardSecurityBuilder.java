package card42.host.emrtd.perso;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import card42.host.common.codec.Der;
import card42.host.common.codec.DerWriter;
import card42.host.emrtd.lds.SecurityInfo;

/**
 * Builds EF.CardSecurity: a CMS SignedData whose eContent is a DER SET OF
 * SecurityInfo that publishes the chip's static Chip Authentication public key
 * and repeats the SecurityInfos from EF.CardAccess (ICAO Doc 9303-10 §3.11.4,
 * BSI TR-03110-3 §A.1.2.5).  The content type is {@code id-SecurityObject}
 * ({@code 0.4.0.127.0.7.3.2.1}) and the SignedData is signed by the Document
 * Signer, whose certificate is embedded.
 *
 * <p>EF.CardSecurity is the plain RFC 3369 SignedData ContentInfo; unlike
 * EF.SOD it is not wrapped in the outer tag {@code 77} (inspection systems
 * parse it raw).
 *
 * <p>The chip's public key is the RFC 5280 SubjectPublicKeyInfo produced by the
 * JCE for the matching P-256 private scalar personalized with DGI {@code FF03}.
 * The same SecurityInfos set is exposed by {@link #securityInfos} and reused
 * verbatim as EF.DG14 (ICAO Doc 9303-10 §4.7.14).
 */
public final class CardSecurityBuilder {

    /** id-SecurityObject (BSI TR-03110-3 §A.1.2.5). */
    private static final String OID_SECURITY_OBJECT = "0.4.0.127.0.7.3.2.1";

    private CardSecurityBuilder() {
    }

    /**
     * EF.CardSecurity for one Chip Authentication public key plus the
     * EF.CardAccess SecurityInfos.
     *
     * @param subjectPublicKeyInfo the DER SubjectPublicKeyInfo of the chip key
     * @param keyId the Chip Authentication key id (matches EF.CardAccess)
     * @param cardAccess the EF.CardAccess DER SET OF SecurityInfo, or null
     * @param dscKey the Document Signer private key
     * @param dscCertificate the Document Signer certificate
     */
    public static byte[] build(byte[] subjectPublicKeyInfo, int keyId, byte[] cardAccess,
                               PrivateKey dscKey, X509Certificate dscCertificate) throws Exception {
        return build(securityInfos(subjectPublicKeyInfo, keyId, cardAccess), dscKey,
                dscCertificate);
    }

    /**
     * The EF.CardSecurity eContent (and EF.DG14, Doc 9303-10 §4.7.14): a DER
     * {@code SET OF SecurityInfo} that repeats the EF.CardAccess SecurityInfos
     * and adds the chip's static Chip Authentication public key.
     *
     * @param subjectPublicKeyInfo the DER SubjectPublicKeyInfo of the chip key
     * @param keyId the Chip Authentication key id (matches EF.CardAccess)
     * @param cardAccess the EF.CardAccess DER SET OF SecurityInfo, or null
     */
    public static byte[] securityInfos(byte[] subjectPublicKeyInfo, int keyId, byte[] cardAccess) {
        byte[] caPublicKeyInfo = DerWriter.sequence(
                DerWriter.oid(SecurityInfo.ID_PK_ECDH),
                subjectPublicKeyInfo,
                DerWriter.integer(keyId));
        if (cardAccess != null && cardAccess.length > 0) {
            // Repeat the CardAccess SecurityInfos (ICAO 9303-10 §3.11.4) and add
            // the CA public key info.
            Der.Tlv set = Der.read(cardAccess, 0);
            return DerWriter.tlv(0x31,
                    DerWriter.concat(Der.value(cardAccess, set), caPublicKeyInfo));
        }
        return DerWriter.set(caPublicKeyInfo);
    }

    /**
     * EF.CardSecurity CMS SignedData over a pre-built SecurityInfos set.  Lets a
     * caller reuse the same set as EF.DG14 instead of rebuilding it.
     */
    public static byte[] build(byte[] securityInfos, PrivateKey dscKey,
                               X509Certificate dscCertificate) throws Exception {
        return SodBuilder.buildCms(OID_SECURITY_OBJECT, securityInfos, dscKey, dscCertificate);
    }
}
