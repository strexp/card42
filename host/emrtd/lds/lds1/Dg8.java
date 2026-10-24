package card42.host.emrtd.lds.lds1;

import java.util.Collections;
import java.util.List;

import card42.host.emrtd.lds.common.LdsBytes;
import card42.host.emrtd.lds.common.LdsDataGroup;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.ParseStatus;

/**
 * Data group 8: data feature(s) (ICAO Doc 9303-10 §4.7.8).
 *
 * <p>The structure is marked "To Be Defined" and available for proprietary
 * use, so only the instance count and the complete templates are exposed.
 */
public final class Dg8 implements LdsDataGroup {

    public final byte[] raw;
    /** The proprietary templates as complete BER-TLV objects. */
    public final List<byte[]> templates;
    public final int declaredCount;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    private Dg8(byte[] raw, TemplateGroup.Result result) {
        this.raw = LdsBytes.copy(raw);
        this.templates = result.templates;
        this.declaredCount = result.declaredCount;
        this.status = result.status;
        this.issues = result.issues;
    }

    public static Dg8 parse(byte[] dg8) {
        return new Dg8(dg8, TemplateGroup.parse(dg8, 8, 0x68));
    }

    @Override
    public int dg() {
        return 8;
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
