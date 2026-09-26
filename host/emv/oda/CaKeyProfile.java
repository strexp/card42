package card42.host.emv.oda;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import card42.host.common.util.KeyValueFile;

/**
 * Loads a {@link CaKeyStore} ring from a text file (EMV v4.4 Book 2 §5.1).
 *
 * <p>The generator holds no key material: a deployment supplies the CA public
 * keys it trusts.  The file is a flat {@code key = hex} list, one entry per
 * line, with {@code #} comments and blank lines ignored:
 *
 * <pre>
 *   ca.01.modulus  = &lt;hex&gt;   CA public modulus (index 01)
 *   ca.01.exponent = 010001
 *   ca.02.modulus  = &lt;hex&gt;   CA public modulus (index 02)
 *   ca.02.exponent = 010001
 * </pre>
 *
 * <p>The middle token is the CA Public Key Index ('8F') in hex, so
 * {@code ca.01} is the key the card advertises with {@code 8F = 01}.  The demo
 * ring used by {@code terminal pay} lives in {@code perso/emv/sample.ca.keys}; a
 * real deployment keeps its own file outside the repository.
 */
public final class CaKeyProfile {

    private CaKeyProfile() {
    }

    /** Loads a {@link CaKeyStore} from the given file path. */
    public static CaKeyStore load(String path) throws IOException {
        Map<String, String> props = KeyValueFile.read(path);
        Map<Integer, CaKey> keys = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : props.entrySet()) {
            String key = entry.getKey();
            if (!key.startsWith("ca.") || !key.endsWith(".modulus")) {
                continue;
            }
            String indexHex = key.substring(3, key.length() - ".modulus".length());
            String exponent = props.get("ca." + indexHex + ".exponent");
            if (exponent == null) {
                throw new IOException("CA key profile " + path
                        + ": missing ca." + indexHex + ".exponent");
            }
            int index;
            try {
                index = Integer.parseInt(indexHex, 16);
            } catch (NumberFormatException e) {
                throw new IOException("CA key profile " + path
                        + ": not a hex CA Public Key Index: ca." + indexHex);
            }
            if (index < 0 || index > 0xFF) {
                throw new IOException("CA key profile " + path
                        + ": CA Public Key Index out of range: ca." + indexHex);
            }
            keys.put(index, CaKey.ofHex(entry.getValue(), exponent));
        }
        if (keys.isEmpty()) {
            throw new IOException("CA key profile " + path
                    + ": no ca.<index>.modulus entries");
        }
        return CaKeyStore.of(keys);
    }
}
