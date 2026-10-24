package card42.host.emrtd.lds.lds1;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import card42.host.emrtd.lds.common.LdsBytes;
import card42.host.emrtd.lds.common.LdsDataGroup;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.LdsTlv;
import card42.host.emrtd.lds.common.ParseStatus;
import card42.host.common.codec.TlvCursor;

/**
 * Data group 13: optional details (ICAO Doc 9303-10 §4.7.13).
 *
 * <p>The content is at the discretion of the issuing State or organization
 * and the standard defines no fields, so the parser only validates the
 * {@code 6D} wrapper and keeps the complete inner value raw.
 */
public final class Dg13 implements LdsDataGroup {

    public final byte[] raw;
    /** The value of the {@code 6D} wrapper (issuer-defined bytes). */
    public final byte[] value;
    public final ParseStatus status;
    public final List<LdsIssue> issues;

    private Dg13(byte[] raw, byte[] value, ParseStatus status, List<LdsIssue> issues) {
        this.raw = LdsBytes.copy(raw);
        this.value = LdsBytes.copy(value);
        this.status = status;
        this.issues = Collections.unmodifiableList(new ArrayList<LdsIssue>(issues));
    }

    /** Parses a DG13 EF. */
    public static Dg13 parse(byte[] dg13) {
        List<LdsIssue> issues = new ArrayList<LdsIssue>();
        if (dg13 == null || dg13.length == 0) {
            issues.add(LdsIssue.error(LdsIssue.Code.EMPTY_VALUE, 13, 0, "empty EF"));
            return new Dg13(dg13, new byte[0], ParseStatus.INVALID, issues);
        }
        TlvCursor cursor = new TlvCursor(dg13);
        TlvCursor.Status status = cursor.next();
        if (status == TlvCursor.Status.OK && cursor.tag() == 0x6D) {
            if (cursor.end() != dg13.length) {
                issues.add(LdsIssue.warn(LdsIssue.Code.TRAILING_DATA, 13, cursor.end(),
                        "bytes after the complete outer object were ignored"));
            }
            return new Dg13(dg13, cursor.value(), ParseStatus.OK, issues);
        }
        if (status != TlvCursor.Status.OK) {
            issues.add(LdsIssue.error(LdsIssue.Code.TRUNCATED_TLV, 13, cursor.start(),
                    "truncated outer object (" + status + ")"));
            return new Dg13(dg13, new byte[0], ParseStatus.INVALID, issues);
        }
        issues.add(LdsIssue.warn(LdsIssue.Code.OUTER_TAG_MISMATCH, 13, 0,
                "outer tag is not 6D; the complete EF is kept as the value"));
        return new Dg13(dg13, dg13, ParseStatus.PARTIAL, issues);
    }

    @Override
    public int dg() {
        return 13;
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
        return issues;
    }
}
