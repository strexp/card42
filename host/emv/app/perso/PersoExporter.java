package card42.host.emv.app.perso;

import java.util.ArrayList;
import java.util.List;

import card42.host.common.util.Hex;

/**
 * Exports the DGI sequence of every instance in a personalization script as
 * GPPro-ready hex (docs/specs/common/toolchain.md §5, docs/specs/emv/personalization.md §1).
 */
public final class PersoExporter {

    private PersoExporter() {
    }

    /**
     * One {@code "<AID> <hex>"} line per instance, in script order.  The DGI
     * sequence is the same {@link PersoScript#sequence(PersoScript.Entry)} the
     * simulator client sends (EMV CPS v2.0 Annex A).
     */
    public static List<String> lines(PersoScript script) {
        List<String> out = new ArrayList<>();
        for (PersoScript.Entry entry : script.entries) {
            byte[] sequence = PersoScript.sequence(entry);
            out.add(entry.aid + " " + Hex.format(sequence));
        }
        return out;
    }
}
