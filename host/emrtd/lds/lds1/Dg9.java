package card42.host.emrtd.lds.lds1;

import java.util.Collections;
import java.util.List;

import card42.host.emrtd.lds.common.LdsBytes;
import card42.host.emrtd.lds.common.LdsDataGroup;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.ParseStatus;

/**
 * Data group 9: structure feature(s) (ICAO Doc 9303-10 §4.7.9).
 *
 * <p>Like DG8, the structure is "To Be Defined" by the standard; only the
 * count and the proprietary templates are exposed.
 */
public final class Dg9 implements LdsDataGroup {

    public final byte[] raw;
    public final List<byte[]> templates;
    public final int declaredCount;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    private Dg9(byte[] raw, TemplateGroup.Result result) {
        this.raw = LdsBytes.copy(raw);
        this.templates = result.templates;
        this.declaredCount = result.declaredCount;
        this.status = result.status;
        this.issues = result.issues;
    }

    public static Dg9 parse(byte[] dg9) {
        return new Dg9(dg9, TemplateGroup.parse(dg9, 9, 0x69));
    }

    @Override
    public int dg() {
        return 9;
    }

    @Override
    public byte[] raw() {
        return raw.clone();
    }

    @Override
    public ParseStatus status() {
        return status;
    }

    @Override
    public List<LdsIssue> issues() {
        return Collections.unmodifiableList(issues);
    }
}
