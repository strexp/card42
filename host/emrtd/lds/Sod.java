package card42.host.emrtd.lds;

import card42.host.common.codec.Der;

/**
 * EF.SOD: the CMS SignedData plus its encapsulated LDS Security Object
 * (ICAO Doc 9303-10 §4.6.2 Table 36, H3.3).  The CMS ContentInfo is carried
 * inside the EF.SOD outer tag {@code 77}.
 */
public final class Sod {

    public final CmsSignedData cms;
    public final LdsSecurityObject securityObject;

    private Sod(CmsSignedData cms, LdsSecurityObject securityObject) {
        this.cms = cms;
        this.securityObject = securityObject;
    }

    public static Sod parse(byte[] sod) {
        byte[] cmsBytes = sod;
        if (sod.length > 0 && (sod[0] & 0xFF) == 0x77) {
            cmsBytes = Der.value(sod, Der.read(sod, 0));
        }
        CmsSignedData cms = CmsSignedData.parse(cmsBytes);
        return new Sod(cms, LdsSecurityObject.parse(cms.eContent));
    }
}
