package card42.host.emrtd.lds;

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.Signature;

import card42.host.common.codec.TlvWriter;
import card42.host.common.util.Bytes;

/**
 * Common BER-TLV and signature helpers for the LDS2 record writers
 * (ICAO Doc 9303-10 Table 86/90/83).
 *
 * <p>The LDS2-TS signature covers the complete signed-information DO
 * ({@code 73} for Travel, {@code 71} for Visa), including its tag and length,
 * and is carried in {@code 5F37}.  The signer is the caller's X.509 LDS2-TS
 * key; {@code RSA} uses SHA-256 with PKCS#1 v1.5 and {@code EC} SHA-256 with
 * ECDSA (DER), matching the certificate profile the project uses for X.509
 * (Doc 9303-12).  This is the write-side counterpart of
 * {@link TravelRecord}/{@link VisaRecord}.
 */
abstract class Lds2RecordBuilder {

    protected static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, value);
        return out.toByteArray();
    }

    protected static byte[] ascii(String value) {
        return value.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    protected static byte[] concat(byte[]... parts) {
        return Bytes.concat(parts);
    }

    /** Signs the complete signed-information DO with the caller's LDS2-TS key. */
    protected static byte[] sign(PrivateKey key, byte[] signedInfoTlv) throws Exception {
        String algorithm = key.getAlgorithm();
        String jca;
        if ("EC".equalsIgnoreCase(algorithm)) {
            jca = "SHA256withECDSA";
        } else if ("RSA".equalsIgnoreCase(algorithm)) {
            jca = "SHA256withRSA";
        } else {
            throw new IllegalArgumentException(
                    "LDS2-TS key must be RSA or EC (was " + algorithm + ")");
        }
        Signature signer = Signature.getInstance(jca);
        signer.initSign(key);
        signer.update(signedInfoTlv);
        return signer.sign();
    }

    /** The one-byte certificate reference DO'5F38' (Doc 9303-10 Table 86/90). */
    protected static byte[] certificateReferenceDo(int reference) {
        if (reference < 1 || reference > 254) {
            throw new IllegalArgumentException("certificate reference must be 1..254");
        }
        return tlv(0x5F38, new byte[] { (byte) reference });
    }

    protected static void require(String name, String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalStateException("LDS2 record field " + name + " is required");
        }
    }
}
