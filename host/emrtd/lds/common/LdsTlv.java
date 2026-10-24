package card42.host.emrtd.lds.common;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import card42.host.common.codec.TlvCursor;

/**
 * Offset-aware BER-TLV traversal for the LDS parsers.
 *
 * <p>{@link card42.host.common.codec.Tags} returns values only; the issue
 * model needs the byte offset of a malformed or unexpected object inside the
 * raw EF, so this helper wraps {@link TlvCursor} and keeps each node's
 * position.  Unlike {@code Tags.find}, it can be restricted to the
 * <em>immediate</em> children of a template, which prevents a nested tag from
 * being mistaken for a top-level field.
 */
public final class LdsTlv {

    /** One parsed BER-TLV object with its offsets in the backing buffer. */
    public static final class Node {
        private final byte[] buf;
        public final int tag;
        /** Offset of the first tag byte. */
        public final int start;
        /** Offset of the first value byte. */
        public final int valueOffset;
        public final int length;
        public final boolean constructed;

        Node(byte[] buf, TlvCursor cursor) {
            this.buf = buf;
            this.tag = cursor.tag();
            this.start = cursor.start();
            this.valueOffset = cursor.valueOffset();
            this.length = cursor.valueLength();
            this.constructed = cursor.constructed();
        }

        /** A copy of the value bytes. */
        public byte[] value() {
            return java.util.Arrays.copyOfRange(buf, valueOffset, valueOffset + length);
        }

        /** A copy of the complete tag || length || value encoding. */
        public byte[] encoded() {
            return java.util.Arrays.copyOfRange(buf, start, valueOffset + length);
        }

        public int end() {
            return valueOffset + length;
        }
    }

    private LdsTlv() {
    }

    /**
     * Parses the immediate children of {@code buf[off..off+len)}.  A truncated
     * object is reported on {@code issues} and stops the walk; the nodes that
     * were complete before it are still returned.
     */
    public static List<Node> children(byte[] buf, int off, int len, int dg,
                                      List<LdsIssue> issues) {
        List<Node> out = new ArrayList<Node>();
        if (buf == null) {
            return Collections.unmodifiableList(out);
        }
        TlvCursor cursor = new TlvCursor(buf, off, len);
        while (true) {
            TlvCursor.Status status = cursor.next();
            if (status == TlvCursor.Status.END) {
                break;
            }
            if (status != TlvCursor.Status.OK) {
                issues.add(LdsIssue.error(LdsIssue.Code.TRUNCATED_TLV, dg,
                        cursor.start(), "truncated TLV (" + status + ")"));
                break;
            }
            out.add(new Node(buf, cursor));
        }
        return Collections.unmodifiableList(out);
    }

    /** Parses the immediate children of a whole buffer. */
    public static List<Node> children(byte[] buf, int dg, List<LdsIssue> issues) {
        return children(buf, 0, buf == null ? 0 : buf.length, dg, issues);
    }

    /**
     * Returns the children of the data-group outer tag.  A buffer without the
     * expected outer tag is still parsed as a bare inner template so a card
     * that omits the wrapper is not rejected outright; the condition is
     * reported as {@link LdsIssue.Code#OUTER_TAG_MISMATCH}.
     */
    public static List<Node> body(byte[] raw, int outerTag, int dg, List<LdsIssue> issues) {
        if (raw == null || raw.length == 0) {
            issues.add(LdsIssue.error(LdsIssue.Code.EMPTY_VALUE, dg, 0, "empty EF"));
            return Collections.emptyList();
        }
        TlvCursor cursor = new TlvCursor(raw);
        TlvCursor.Status status = cursor.next();
        if (status == TlvCursor.Status.OK && cursor.tag() == outerTag) {
            if (cursor.end() != raw.length) {
                issues.add(LdsIssue.warn(LdsIssue.Code.TRAILING_DATA, dg, cursor.end(),
                        "bytes after the complete outer object were ignored"));
            }
            return children(raw, cursor.valueOffset(), cursor.valueLength(), dg, issues);
        }
        if (status != TlvCursor.Status.OK) {
            issues.add(LdsIssue.error(LdsIssue.Code.TRUNCATED_TLV, dg, cursor.start(),
                    "truncated outer object (" + status + ")"));
            return Collections.emptyList();
        }
        issues.add(LdsIssue.warn(LdsIssue.Code.OUTER_TAG_MISMATCH, dg, 0,
                String.format("outer tag is %02X, expected %02X", cursor.tag(), outerTag)));
        return children(raw, 0, raw.length, dg, issues);
    }

    /** The first node with {@code tag}, or null. */
    public static Node first(List<Node> nodes, int tag) {
        for (Node node : nodes) {
            if (node.tag == tag) {
                return node;
            }
        }
        return null;
    }

    /** All nodes with {@code tag}, in document order. */
    public static List<Node> all(List<Node> nodes, int tag) {
        List<Node> out = new ArrayList<Node>();
        for (Node node : nodes) {
            if (node.tag == tag) {
                out.add(node);
            }
        }
        return Collections.unmodifiableList(out);
    }

    /** The children of a node's value, with offsets in the same backing buffer. */
    public static List<Node> childrenOf(Node node, int dg, List<LdsIssue> issues) {
        if (node == null) {
            return Collections.emptyList();
        }
        return children(node.buf, node.valueOffset, node.length, dg, issues);
    }

    /**
     * Decodes the tag list of a {@code 5C} data object (one or two bytes per
     * tag, Doc 9303-10 §4.6.1).  A truncated two-byte tag is ignored.
     */
    public static List<Integer> tagList(byte[] value) {
        List<Integer> out = new ArrayList<Integer>();
        if (value == null) {
            return Collections.unmodifiableList(out);
        }
        int p = 0;
        while (p < value.length) {
            int b = value[p] & 0xFF;
            if ((b & 0x1F) == 0x1F) {
                if (p + 1 >= value.length) {
                    break;
                }
                out.add((b << 8) | (value[p + 1] & 0xFF));
                p += 2;
            } else {
                out.add(b);
                p++;
            }
        }
        return Collections.unmodifiableList(out);
    }
}
