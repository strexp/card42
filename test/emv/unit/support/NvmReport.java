package card42.test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javacard.framework.NvmWrite;

/**
 * Scenario accumulator and printer for the EEPROM write baselines
 * (docs/specs/common/risks.md §2).
 *
 * <p>A baseline runs as a sequence of {@link #step labelled steps} (one APDU or
 * one EMV phase each).  Every step snapshots the persistent object graph with
 * {@link NvmProbe}, diffs it against the previous snapshot, and resets the
 * {@link NvmWrite} Util counter before the step runs.  Differencing per step
 * instead of once for the whole scenario is deliberate: a session that fills
 * {@code ksEnc} and then zeroizes it on deselect would net to zero over the
 * whole window, while the two writes are exactly what has to be counted.
 *
 * <p>The two counters are reported side by side and never summed — see the
 * notes on {@link NvmWrite} and {@link NvmProbe} for what each one can and
 * cannot see.
 */
final class NvmReport {

    /** One labelled unit of work inside a scenario. */
    interface Step {
        void run() throws Exception;
    }

    private final String name;
    private final Object[] roots;
    private final Class<?>[] seeds;
    private NvmProbe.State current;

    private long stateBytes;
    private long stateOps;
    private long utilBytes;
    private long utilOps;
    private long ramBytes;
    private int steps;

    private final StringBuilder perStep = new StringBuilder();
    private final Map<String, Long> top = new LinkedHashMap<String, Long>();

    NvmReport(String name, Object[] roots, Class<?>[] seeds) {
        this.name = name;
        this.roots = roots;
        this.seeds = seeds;
        this.current = NvmProbe.take(roots, seeds);
    }

    void step(String label, Step action) throws Exception {
        NvmWrite.reset();
        // No step may allocate a transient array: all package-shared buffers are
        // allocated during applet construction (docs/specs/common/risks.md).
        NvmWrite.markAllocationBaseline();
        action.run();
        long newAllocations = NvmWrite.allocationsSinceBaseline();
        Asserts.check(newAllocations == 0,
                "no transient array created during " + label);
        NvmProbe.State next = NvmProbe.take(roots, seeds);
        NvmProbe.Result r = NvmProbe.diff(current, next);
        current = next;

        long ub = NvmWrite.utilBytes();
        long uo = NvmWrite.utilOps();
        long rb = NvmWrite.transientBytes();
        stateBytes += r.bytes;
        stateOps += r.ops;
        utilBytes += ub;
        utilOps += uo;
        ramBytes += rb;
        steps++;

        perStep.append(String.format("    %-32s state %6d B / %5d ops   util %6d B / %3d calls   RAM %6d B%n",
                label, r.bytes, r.ops, ub, uo, rb));
        for (Map.Entry<String, Long> e : r.top) {
            Long old = top.get(e.getKey());
            top.put(e.getKey(),
                    Long.valueOf(old == null ? e.getValue().longValue()
                            : old.longValue() + e.getValue().longValue()));
        }
    }

    String name() {
        return name;
    }

    long stateBytes() {
        return stateBytes;
    }

    long utilBytes() {
        return utilBytes;
    }

    int steps() {
        return steps;
    }

    void print() {
        System.out.println();
        System.out.println("  " + name);
        System.out.println(String.format("    %d steps   persistent state diff %,d B / %,d ops"
                + "   Util bulk writes %,d B / %,d calls   RAM (transient) %,d B",
                steps, stateBytes, stateOps, utilBytes, utilOps, ramBytes));
        System.out.print(perStep.toString());
        List<Map.Entry<String, Long>> sorted =
                new ArrayList<Map.Entry<String, Long>>(top.entrySet());
        Collections.sort(sorted, new Comparator<Map.Entry<String, Long>>() {
            public int compare(Map.Entry<String, Long> a, Map.Entry<String, Long> b) {
                if (b.getValue().longValue() != a.getValue().longValue()) {
                    return b.getValue() < a.getValue() ? -1 : 1;
                }
                return a.getKey().compareTo(b.getKey());
            }
        });
        System.out.println("    top persistent writers:");
        int shown = 0;
        for (Map.Entry<String, Long> e : sorted) {
            if (shown++ >= 8) {
                break;
            }
            System.out.println(String.format("      %-46s %,d B", e.getKey(), e.getValue()));
        }
    }

    /** One-line headline, used by the summary table. */
    void printSummary() {
        System.out.println(String.format("  %-30s state %8d B / %7d ops   util %7d B / %4d calls   RAM %8d B",
                name, stateBytes, stateOps, utilBytes, utilOps, ramBytes));
    }
}
