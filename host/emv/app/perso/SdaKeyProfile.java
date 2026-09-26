package card42.host.emv.app.perso;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;

import card42.host.emv.oda.SdaKeys;
import card42.host.common.util.KeyValueFile;

/**
 * Loads an {@link SdaKeys} profile from a text file (EMV v4.4 Book 2 §5).
 *
 * <p>The generator holds no key material: a deployment supplies its own CA and
 * Issuer key pairs.  The file is a flat {@code key = hex} list, one entry per
 * line, with {@code #} comments and blank lines ignored:
 *
 * <pre>
 *   ca.modulus          = &lt;hex&gt;   CA public modulus
 *   ca.privateExponent  = &lt;hex&gt;   CA private exponent
 *   issuer.modulus      = &lt;hex&gt;   Issuer public modulus
 *   issuer.privateExponent = &lt;hex&gt; Issuer private exponent
 *   ca.publicKeyIndex   = &lt;hex&gt;   CA Public Key Index advertised in tag 8F
 *   exponent            = &lt;hex&gt;   Issuer/ICC public key exponent (e.g. 010001)
 * </pre>
 *
 * <p>The demo profile shared by {@code perso/emv/sample.perso} and
 * {@code perso/emv/sample-test.perso} lives in {@code perso/emv/sample.perso.sda.keys}; a real
 * deployment keeps its own profile outside the repository.
 */
public final class SdaKeyProfile {

    private SdaKeyProfile() {
    }

    /** Loads an {@link SdaKeys} profile from the given file path. */
    public static SdaKeys load(String path) throws IOException {
        Map<String, String> props = KeyValueFile.read(path);
        return new SdaKeys(
                bigInteger(props, "ca.modulus"),
                bigInteger(props, "ca.privateExponent"),
                bigInteger(props, "issuer.modulus"),
                bigInteger(props, "issuer.privateExponent"),
                bytes(props, "ca.publicKeyIndex"),
                bytes(props, "exponent"));
    }

    private static BigInteger bigInteger(Map<String, String> props, String key)
            throws IOException {
        return new BigInteger(hex(props, key), 16);
    }

    private static byte[] bytes(Map<String, String> props, String key) throws IOException {
        String hex = hex(props, key);
        if ((hex.length() & 1) != 0) {
            throw new IOException("SDA key profile: odd-length hex for " + key);
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static String hex(Map<String, String> props, String key) throws IOException {
        String value = props.get(key);
        if (value == null || value.isEmpty()) {
            throw new IOException("SDA key profile: missing " + key);
        }
        for (int i = 0; i < value.length(); i++) {
            if (Character.digit(value.charAt(i), 16) < 0) {
                throw new IOException("SDA key profile: non-hex value for " + key);
            }
        }
        return value;
    }
}
