package card42.host.emv.oda;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A ring of EMV Certification Authority public keys selected by the CA Public
 * Key Index ('8F') (EMV v4.4 Book 2 §5.1).
 *
 * <p>The library holds no CA keys: the caller (a terminal CLI, or a test
 * fixture) supplies the keys it trusts.  {@link CaKeyProfile} loads a ring from
 * a deployment text file.
 */
public interface CaKeyStore {

    /** The CA key with the given index value, or null when it is not trusted. */
    CaKey byIndex(byte[] caPublicKeyIndex);

    /** A store that trusts no CA key, so ODA cannot be performed. */
    static CaKeyStore empty() {
        return index -> null;
    }

    /** A store with a single key at the given one-byte CA Public Key Index. */
    static CaKeyStore of(int index, CaKey key) {
        Map<Integer, CaKey> keys = new LinkedHashMap<>();
        keys.put(index, key);
        return of(keys);
    }

    /**
     * A store backed by a map from the CA Public Key Index value to its key.
     * The index is interpreted as a big-endian unsigned integer, matching the
     * '8F' value carried in the SDA certificate chain.
     */
    static CaKeyStore of(Map<Integer, CaKey> byIndex) {
        return index -> {
            if (index == null) {
                return null;
            }
            int value = 0;
            for (byte b : index) {
                value = (value << 8) | (b & 0xFF);
            }
            return byIndex.get(value);
        };
    }
}
