package card42.host.emv.app.issuer;

import card42.host.emv.kernel.core.Authorization;
import card42.host.emv.kernel.core.Issuer;

/**
 * Closed loop issuer for {@code terminal pay}: the ARPC Method 2 and CSU are
 * computed in-process from the ICC master key (docs/specs/common/toolchain.md §7.1,
 * decision D).
 */
public final class ClosedLoopIssuer implements Issuer {

    private final byte[] iccKey;
    private final byte[] csu;
    private final byte[] arc;
    private final byte[][] scripts;

    public ClosedLoopIssuer(byte[] iccKey, byte[] csu, byte[] arc, byte[][] scripts) {
        this.iccKey = iccKey;
        this.csu = csu;
        this.arc = arc;
        this.scripts = scripts;
    }

    @Override
    public Authorization authorize(byte[] arqc, int atc, card42.host.emv.kernel.core.TransactionResult result) {
        try {
            byte[] auth = IssuerCrypto.inlineAuthData(iccKey, atc, arqc, csu);
            return new Authorization(arc, auth, scripts.length == 0 ? null : scripts);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
