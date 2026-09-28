package javacard.framework;

import java.util.IdentityHashMap;
import java.util.Map;

/**
 * EEPROM-write counter for the pure-JVM unit tests (docs/specs/common/risks.md
 * §2, "unnecessary EEPROM writes").
 *
 * <p>The plain-JVM stubs cannot see a real programming cycle, so the counter
 * models one from the two things the stubs <em>can</em> observe:
 *
 * <ul>
 *   <li><b>Util writes</b> — every bulk write that goes through
 *       {@link Util#arrayCopy}/{@link Util#arrayCopyNonAtomic}/
 *       {@link Util#arrayFillNonAtomic}/{@link Util#setShort} into an array
 *       that was <em>not</em> handed out by {@code JCSystem.makeTransient*}.
 *       A real card issues one programming operation per byte here, including
 *       writes that store the value a cell already holds, so this counter is
 *       the modelled cost of the bulk-copy path and it deliberately counts
 *       same-value writes too — the "no change guard" class of problem
 *       (a same-value write may still cost a programming cycle).</li>
 *   <li><b>State change</b> — see {@code card42.test.NvmProbe}, which
 *       snapshots the persistent object graph before/after a scenario and
 *       counts bytes whose value actually changed.  That covers the direct
 *       {@code array[i] = x} and {@code field = v} writes that never pass
 *       through {@code Util} (and that the Util counter cannot see).</li>
 * </ul>
 *
 * <p>Neither counter is exact: same-value <em>field</em> writes are invisible
 * to both, and the two counters overlap on copies that do change the
 * destination.  They are therefore reported side by side and never summed.  The
 * point is a stable, reviewable trend number per scenario, not an absolute
 * endurance figure.
 *
 * <p>Instances of this class are never created; it lives in the stub package
 * only so {@link Util} can call {@link #note} without an import.  It is
 * test-only code and is never converted into a CAP.
 */
public final class NvmWrite {

    /**
     * Arrays handed out by {@code JCSystem.makeTransient*}: RAM-backed, so
     * writing them is not an EEPROM write.  Identity semantics on purpose — a
     * re-used array object must keep its classification for the whole run.
     */
    private static final Map<Object, Object> TRANSIENT = new IdentityHashMap<Object, Object>();

    private static long utilBytes;
    private static long utilOps;
    private static long transientBytes;

    /**
     * Number and total capacity of the transient arrays handed out since the
     * JVM started, and the value at the last {@link #markAllocationBaseline()}.
     * A command that allocates a transient array after the applet is installed
     * raises the count, which the baseline tests assert against
     * (docs/specs/common/risks.md §2: "no transient array at run time").
     */
    private static long transientAllocations;
    private static long transientCapacity;
    private static long allocationBaseline = -1;

    private NvmWrite() {
    }

    /** Called by {@code JCSystem.makeTransient*} for every RAM array it hands out. */
    static void register(Object array, int size) {
        if (array != null) {
            TRANSIENT.put(array, Boolean.TRUE);
            transientAllocations++;
            if (size > 0) {
                transientCapacity += size;
            }
        }
    }

    /** True when the object is RAM-backed (allocated by {@code JCSystem.makeTransient*}). */
    public static boolean isTransient(Object array) {
        return array != null && TRANSIENT.containsKey(array);
    }

    /** Number of transient arrays allocated so far. */
    public static long transientAllocations() {
        return transientAllocations;
    }

    /** Total bytes of transient arrays allocated so far (memory-capacity, not traffic). */
    public static long transientCapacity() {
        return transientCapacity;
    }

    /**
     * Records the current allocation count as the baseline: a later
     * {@link #allocationsSinceBaseline()} must be 0 once the applet is
     * installed (all shared buffers are allocated during construction).
     */
    public static void markAllocationBaseline() {
        allocationBaseline = transientAllocations;
    }

    /** Transient arrays allocated since {@link #markAllocationBaseline()}. */
    public static long allocationsSinceBaseline() {
        return allocationBaseline < 0 ? 0 : transientAllocations - allocationBaseline;
    }

    /** Records a bulk write of {@code bytes} into {@code dest}. */
    static void note(byte[] dest, int bytes) {
        if (dest == null || bytes <= 0) {
            return;
        }
        if (TRANSIENT.containsKey(dest)) {
            transientBytes += bytes;
        } else {
            utilBytes += bytes;
            utilOps++;
        }
    }

    /** Clears the counters; the transient-array registry is kept for the whole run. */
    public static void reset() {
        utilBytes = 0;
        utilOps = 0;
        transientBytes = 0;
    }

    /** Bytes written into persistent arrays through {@code Util}. */
    public static long utilBytes() {
        return utilBytes;
    }

    /** Number of {@code Util} calls that wrote into persistent arrays. */
    public static long utilOps() {
        return utilOps;
    }

    /** Bytes written into transient (RAM) arrays through {@code Util}; reported for context. */
    public static long transientBytes() {
        return transientBytes;
    }
}
