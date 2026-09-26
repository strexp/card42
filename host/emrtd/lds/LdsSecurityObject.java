package card42.host.emrtd.lds;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import card42.host.common.codec.Der;

/**
 * The LDS Security Object carried inside EF.SOD (ICAO Doc 9303-10 §4.6.2):
 * {@code SEQUENCE { version, hashAlgorithm, dataGroupHashValues } }, where each
 * {@code DataGroupHash} is {@code { dataGroupNumber, dataGroupHashValue }}
 * (H3.2).
 */
public final class LdsSecurityObject {

    public final int version;
    public final String digestAlgorithm;
    public final Map<Integer, byte[]> dataGroupHashes;
    /** LDS version from ldsVersionInfo, or null (Doc 9303-10 §4.6.2.1). */
    public final String ldsVersion;
    /** Unicode version from ldsVersionInfo, or null. */
    public final String unicodeVersion;

    private LdsSecurityObject(int version, String digestAlgorithm,
                              Map<Integer, byte[]> dataGroupHashes,
                              String ldsVersion, String unicodeVersion) {
        this.version = version;
        this.digestAlgorithm = digestAlgorithm;
        this.dataGroupHashes = dataGroupHashes;
        this.ldsVersion = ldsVersion;
        this.unicodeVersion = unicodeVersion;
    }

    public static LdsSecurityObject parse(byte[] der) {
        Der.Tlv sequence = Der.read(der, 0);
        List<Der.Tlv> fields = Der.children(der, sequence);
        int version = Der.intValue(der, fields.get(0));
        // LDSSecurityObjectVersion is v0(0) or v1(1) (Doc 9303-10 §4.6.2.3).
        if (version != 0 && version != 1) {
            throw new IllegalArgumentException(
                    "unsupported LDS Security Object version " + version);
        }
        String digest = AlgorithmIds.digest(Der.oid(der, Der.children(der, fields.get(1)).get(0)));
        Map<Integer, byte[]> hashes = new LinkedHashMap<Integer, byte[]>();
        for (Der.Tlv entry : Der.children(der, fields.get(2))) {
            List<Der.Tlv> pair = Der.children(der, entry);
            hashes.put(Der.intValue(der, pair.get(0)), Der.value(der, pair.get(1)));
        }

        // ldsVersionInfo MUST be present for V1 and MUST NOT be present for V0.
        String ldsVersion = null;
        String unicodeVersion = null;
        boolean hasVersionInfo = fields.size() > 3;
        if (version == 1 && !hasVersionInfo) {
            throw new IllegalArgumentException("LDS Security Object V1 requires ldsVersionInfo");
        }
        if (version == 0 && hasVersionInfo) {
            throw new IllegalArgumentException("ldsVersionInfo requires LDS Security Object V1");
        }
        if (hasVersionInfo) {
            List<Der.Tlv> info = Der.children(der, fields.get(3));
            ldsVersion = ascii(der, info.get(0));
            unicodeVersion = ascii(der, info.get(1));
        }
        return new LdsSecurityObject(version, digest, hashes, ldsVersion, unicodeVersion);
    }

    private static String ascii(byte[] der, Der.Tlv t) {
        return new String(Der.value(der, t), java.nio.charset.StandardCharsets.US_ASCII);
    }
}
