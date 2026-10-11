package card42.common;

import javacard.framework.JCSystem;

/* Read-only on-card memory diagnostic, used to measure the J3R180 transient /
 * persistent margin (TODO.emv.md §A3).
 *
 * <p>It is compiled out of the command path by default ({@link #ENABLED} is
 * {@code false}), so a production CAP carries no diagnostic entry point.  To
 * measure, set {@code ENABLED = true}, rebuild the CAPs, and read the report
 * with the EMV {@code GET DATA 9F7F} command (`Main card get-data -tag=9F7F`)
 * from a selected payment instance.  The eMRTD context is measured by comparing
 * the value before and after `make card-emrtd-install` (see TODO.emv.md §A3).
 *
 * <p>No allocation and no state: the report is the value the platform returns
 * for {@link JCSystem#getAvailableMemory(byte)}, or {@code 0xFFFF} when the
 * platform cannot answer.  The report is 6 bytes:
 * <pre>
 *   bytes 0-1  MEMORY_TYPE_TRANSIENT_DESELECT free
 *   bytes 2-3  MEMORY_TYPE_TRANSIENT_RESET    free
 *   bytes 4-5  MEMORY_TYPE_PERSISTENT         free
 * </pre>
 *
 * @author card42
 */

public final class MemDiag {

    /** Compile-time switch: flip to {@code true} for a measurement build. */
    public static final boolean ENABLED = false;

    /** Length of the report written by {@link #write(byte[], short)}. */
    public static final short REPORT_LENGTH = (short) 6;

    private MemDiag() {
    }

    /**
     * Writes the 6-byte report at {@code out[off..off+6)} and returns its
     * length.  A memory type the platform cannot report is written as
     * {@code 0xFFFF}.
     */
    public static short write(byte[] out, short off) {
        short p = off;
        p = put(out, p, available(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
        p = put(out, p, available(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
        p = put(out, p, available(JCSystem.MEMORY_TYPE_PERSISTENT));
        return (short) (p - off);
    }

    /** {@code JCSystem.getAvailableMemory(type)}, or 0xFFFF when unavailable. */
    private static short available(byte memoryType) {
        try {
            return (short) JCSystem.getAvailableMemory(memoryType);
        } catch (Exception e) {
            return (short) 0xFFFF;
        }
    }

    private static short put(byte[] out, short off, short value) {
        out[off] = (byte) (value >> 8);
        out[(short) (off + 1)] = (byte) value;
        return (short) (off + 2);
    }
}
