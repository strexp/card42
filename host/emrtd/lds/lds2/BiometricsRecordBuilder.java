package card42.host.emrtd.lds.lds2;

import java.security.PrivateKey;

/**
 * Builds an Additional Biometrics EF (ICAO Doc 9303-10 §5.3, Table 93):
 * {@code 7F2E { 5F2E <biometric data>, 5F37 <signature>, 5F38 <cert ref> }}.
 * The signature covers the complete {@code 5F2E} DO, including tag and length.
 */
public final class BiometricsRecordBuilder extends Lds2RecordBuilder {

    private byte[] biometrics;
    private int certificateReference = 1;

    public BiometricsRecordBuilder biometrics(byte[] value) {
        biometrics = value;
        return this;
    }

    public BiometricsRecordBuilder certificateReference(int value) {
        certificateReference = value;
        return this;
    }

    public byte[] build(PrivateKey lds2bKey) throws Exception {
        if (biometrics == null || biometrics.length == 0) {
            throw new IllegalStateException("biometrics data is required");
        }
        byte[] signedInfo = tlv(0x5F2E, biometrics);
        byte[] signature = sign(lds2bKey, signedInfo);
        return tlv(0x7F2E, concat(signedInfo, tlv(0x5F37, signature),
                certificateReferenceDo(certificateReference)));
    }
}
