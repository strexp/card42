package card42.host.emrtd.lds.common;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The result of parsing one data group into a field model: the model (when
 * available), its status, the observations and the raw EF bytes.
 *
 * <p>This is the uniform entry point for callers that only have a
 * data-group number and the EF bytes, e.g. a generic document inspector.
 *
 * @param <T> the model type (usually a {@link LdsDataGroup})
 */
public final class LdsParseResult<T> {

    /** The parsed model, or null when the structure was unreadable. */
    public final T value;
    public final ParseStatus status;
    public final List<LdsIssue> issues;
    /** The complete raw EF, including its outer tag. */
    public final byte[] raw;

    public LdsParseResult(T value, ParseStatus status, List<LdsIssue> issues, byte[] raw) {
        this.value = value;
        this.status = status == null ? ParseStatus.INVALID : status;
        this.issues = Collections.unmodifiableList(
                issues == null ? new ArrayList<LdsIssue>() : new ArrayList<LdsIssue>(issues));
        this.raw = raw == null ? new byte[0] : raw.clone();
    }

    /** True when the model can be used (status OK or PARTIAL). */
    public boolean isUsable() {
        return status.isUsable() && value != null;
    }

    /** The complete raw EF as a fresh copy. */
    public byte[] raw() {
        return raw.clone();
    }
}
