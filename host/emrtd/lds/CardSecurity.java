package card42.host.emrtd.lds;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * EF.CardSecurity: a CMS SignedData whose eContent is a DER SET OF SecurityInfo
 * (ICAO Doc 9303-10 §3.11.4, Doc 9303-11 §3).  It publishes the chip's static
 * Chip Authentication public key and is signed by the Document Signer (H7.2).
 */
public final class CardSecurity {

    public final CmsSignedData cms;
    public final List<SecurityInfo> securityInfos;

    private CardSecurity(CmsSignedData cms, List<SecurityInfo> securityInfos) {
        this.cms = cms;
        this.securityInfos = securityInfos;
    }

    public static CardSecurity parse(byte[] cardSecurity) {
        byte[] cmsBytes = cardSecurity;
        if (cardSecurity.length > 0 && (cardSecurity[0] & 0xFF) == 0x77) {
            cmsBytes = card42.host.common.codec.Der.value(cardSecurity,
                    card42.host.common.codec.Der.read(cardSecurity, 0));
        }
        CmsSignedData cms = CmsSignedData.parse(cmsBytes);
        return new CardSecurity(cms, SecurityInfo.parseList(cms.eContent));
    }

    /** All Chip Authentication public-key entries, in document order. */
    public List<ChipAuthenticationPublicKeyInfo> publicKeyInfos() {
        return filter(ChipAuthenticationPublicKeyInfo.class);
    }

    /** All Chip Authentication protocol entries, in document order. */
    public List<ChipAuthenticationInfo> chipAuthenticationInfos() {
        return filter(ChipAuthenticationInfo.class);
    }

    private <T> List<T> filter(Class<T> type) {
        java.util.List<T> out = new java.util.ArrayList<T>();
        for (SecurityInfo info : securityInfos) {
            if (type.isInstance(info)) {
                out.add(type.cast(info));
            }
        }
        return out;
    }

    /** The DSC carried in the CMS certificates, or null. */
    public X509Certificate signerCertificate() throws Exception {
        if (cms.signerCertificate == null) {
            return null;
        }
        return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(cms.signerCertificate));
    }
}
