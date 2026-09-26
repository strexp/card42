package card42.host.emv.app.issuer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import card42.host.emv.kernel.core.Authorization;
import card42.host.emv.kernel.core.Issuer;
import card42.host.common.util.Hex;
import card42.host.common.util.KeyValueFile;

/**
 * Static replay issuer for {@code terminal pay}: a flat file with {@code arc},
 * {@code auth} and {@code script.N} (docs/specs/common/toolchain.md §7.1).  The same
 * response is returned for every transaction.
 */
public final class AuthFileIssuer implements Issuer {

    private final byte[] arc;
    private final byte[] auth;
    private final byte[][] scripts;

    public AuthFileIssuer(String path) {
        try {
            Map<String, String> props = KeyValueFile.read(path);
            this.arc = Hex.parse(props.getOrDefault("arc", "3030"));
            this.auth = props.containsKey("auth") ? Hex.parse(props.get("auth")) : null;
            List<byte[]> list = new ArrayList<>();
            for (int i = 1; props.containsKey("script." + i); i++) {
                list.add(Hex.parse(props.get("script." + i)));
            }
            this.scripts = list.toArray(new byte[0][]);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Authorization authorize(byte[] arqc, int atc, card42.host.emv.kernel.core.TransactionResult result) {
        return new Authorization(arc, auth, scripts.length == 0 ? null : scripts);
    }
}
