package card42.test;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javacard.framework.NvmWrite;

/**
 * Persistent-state differ for the EEPROM write baselines
 * (docs/specs/common/risks.md §2).
 *
 * <p>{@link NvmWrite} sees the bulk writes that go through
 * {@code javacard.framework.Util}; the card code also assigns array elements
 * and instance fields directly ({@code response[p++] = ...},
 * {@code challengeValid = false}), which no stub can intercept on a plain JVM.
 * This probe closes that gap by snapshotting the persistent object graph of a
 * scenario root before and after the scenario and counting the bytes whose
 * value actually changed:
 *
 * <ul>
 *   <li>a {@code byte[]} field contributes one byte per element that differs
 *       (and its whole length when the field is newly assigned);</li>
 *   <li>a primitive field contributes its width when the value changes;</li>
 *   <li>an object reference contributes 2 bytes when it is re-pointed, and a
 *       newly allocated persistent object contributes the state it was born
 *       with.</li>
 * </ul>
 *
 * <p>Arrays handed out by {@code JCSystem.makeTransient*} are skipped
 * altogether (they live in RAM), which is what makes a transient conversion
 * show up as a drop in the report.
 *
 * <p><b>Scope.</b> Only classes in {@code card42.*} are walked, excluding the
 * host and test trees; platform objects ({@code javacard.*}) are recorded as a
 * reference but never entered.  A command class that is all {@code static}
 * scratch and never instantiated must be passed as a {@code seed} so its static
 * buffers are counted too.
 *
 * <p><b>Known gap.</b> a write that stores the value a field already holds is
 * invisible here; that class of write is only visible to {@link NvmWrite}'s
 * Util counter.  The two are therefore reported side by side and never summed.
 */
final class NvmProbe {

    /** One recorded piece of persistent state. */
    private static final class Cell {
        /** Class/field label used to aggregate the report. */
        final String label;
        /** Boxed primitive, array copy, object reference, or null. */
        final Object value;

        Cell(String label, Object value) {
            this.label = label;
            this.value = value;
        }
    }

    /** The persistent state reachable from one scenario's roots. */
    static final class State {
        /** Keyed by owner identity + declaring class + field name. */
        private final Map<String, Cell> cells = new LinkedHashMap<String, Cell>();

        private State() {
        }
    }

    /** The write cost of one scenario. */
    static final class Result {
        final long bytes;
        final long ops;
        /** Label to bytes, largest first: the "who wrote" part of the report. */
        final List<Map.Entry<String, Long>> top;

        Result(long bytes, long ops, List<Map.Entry<String, Long>> top) {
            this.bytes = bytes;
            this.ops = ops;
            this.top = top;
        }
    }

    private NvmProbe() {
    }

    // --- snapshot ------------------------------------------------------------

    static State take(Object[] roots, Class<?>... seeds) {
        State state = new State();
        Deque<Object> queue = new ArrayDeque<Object>();
        IdentityHashMap<Object, Object> visited = new IdentityHashMap<Object, Object>();
        // Class is not Comparable, so this cannot be a TreeSet.
        Set<Class<?>> staticsDone = new HashSet<Class<?>>();
        for (int i = 0; i < seeds.length; i++) {
            if (seeds[i] != null && isCardType(seeds[i])) {
                collectStatics(seeds[i], state, queue, visited, staticsDone);
            }
        }
        for (int i = 0; roots != null && i < roots.length; i++) {
            if (roots[i] != null) {
                queue.add(roots[i]);
            }
        }
        while (!queue.isEmpty()) {
            Object o = queue.remove();
            if (o == null || visited.put(o, o) != null) {
                continue;
            }
            Class<?> type = o.getClass();
            if (!isCardType(type)) {
                continue;
            }
            collectStatics(type, state, queue, visited, staticsDone);
            for (Class<?> k = type; k != null && k != Object.class; k = k.getSuperclass()) {
                if (!isCardType(k)) {
                    break;
                }
                Field[] fields = k.getDeclaredFields();
                for (int i = 0; i < fields.length; i++) {
                    Field f = fields[i];
                    if (Modifier.isStatic(f.getModifiers()) || f.isSynthetic()) {
                        continue;
                    }
                    record(f, o, read(f, o), k.getSimpleName() + "." + f.getName(),
                            state, queue, visited);
                }
            }
        }
        return state;
    }

    private static void collectStatics(Class<?> type, State state, Deque<Object> queue,
            IdentityHashMap<Object, Object> visited, Set<Class<?>> staticsDone) {
        if (!staticsDone.add(type)) {
            return;
        }
        Field[] fields = type.getDeclaredFields();
        for (int i = 0; i < fields.length; i++) {
            Field f = fields[i];
            int mod = f.getModifiers();
            if (!Modifier.isStatic(mod) || f.isSynthetic()) {
                continue;
            }
            // static final primitives and Strings are ROM constants; a
            // static final *array* still lives in the persistent heap.
            if (Modifier.isFinal(mod)
                    && (f.getType().isPrimitive() || f.getType() == String.class
                        || f.getType() == Class.class)) {
                continue;
            }
            record(f, null, read(f, null),
                    type.getSimpleName() + "." + f.getName() + " (static)",
                    state, queue, visited);
        }
    }

    private static Object read(Field f, Object owner) {
        try {
            f.setAccessible(true);
            return f.get(owner);
        } catch (RuntimeException e) {
            return null;
        } catch (IllegalAccessException e) {
            return null;
        }
    }

    private static void record(Field f, Object owner, Object value, String label,
            State state, Deque<Object> queue, IdentityHashMap<Object, Object> visited) {
        if (value instanceof String || value instanceof Class<?>) {
            return;
        }
        String key = key(f, owner);
        if (value == null) {
            state.cells.put(key, new Cell(label, null));
            return;
        }
        if (value.getClass().isArray()) {
            if (NvmWrite.isTransient(value)) {
                return; // RAM
            }
            state.cells.put(key, new Cell(label, copyArray(value)));
            if (!value.getClass().getComponentType().isPrimitive()) {
                int n = Array.getLength(value);
                for (int i = 0; i < n; i++) {
                    Object element = Array.get(value, i);
                    if (element != null && isCardType(element.getClass())) {
                        queue.add(element);
                    }
                }
            }
            return;
        }
        state.cells.put(key, new Cell(label, value));
        if (isCardType(value.getClass())) {
            queue.add(value);
        }
    }

    /**
     * Identity of the owner plus the declaring class, so a shadowed field and
     * two instances of the same class do not collide.  Static fields are keyed
     * by their declaring class only: there is no owner instance.
     */
    private static String key(Field f, Object owner) {
        String ownerToken = owner == null
                ? "S"
                : "O" + Integer.toHexString(System.identityHashCode(owner));
        return ownerToken + "|" + f.getDeclaringClass().getName() + "." + f.getName();
    }

    private static Object copyArray(Object array) {
        Class<?> component = array.getClass().getComponentType();
        // Clone the primitive arrays as themselves so the diff keeps the
        // component type (element sizes and element-wise comparison depend on
        // it); only reference arrays are boxed into Object[].
        if (component == byte.class) {
            return ((byte[]) array).clone();
        }
        if (component == boolean.class) {
            return ((boolean[]) array).clone();
        }
        if (component == short.class) {
            return ((short[]) array).clone();
        }
        if (component == char.class) {
            return ((char[]) array).clone();
        }
        if (component == int.class) {
            return ((int[]) array).clone();
        }
        if (component == float.class) {
            return ((float[]) array).clone();
        }
        if (component == long.class) {
            return ((long[]) array).clone();
        }
        if (component == double.class) {
            return ((double[]) array).clone();
        }
        int n = Array.getLength(array);
        Object[] copy = new Object[n];
        System.arraycopy(array, 0, copy, 0, n);
        return copy;
    }

    // --- diff ----------------------------------------------------------------

    static Result diff(State before, State after) {
        long bytes = 0;
        long ops = 0;
        Map<String, Long> byLabel = new LinkedHashMap<String, Long>();

        for (Map.Entry<String, Cell> e : after.cells.entrySet()) {
            Cell now = e.getValue();
            long n;
            if (!before.cells.containsKey(e.getKey())) {
                n = sizeBorn(now);
                if (n > 0) {
                    ops += bornOps(now);
                }
            } else {
                n = changed(before.cells.get(e.getKey()), now);
            }
            if (n > 0) {
                bytes += n;
                ops += n;
                add(byLabel, now.label, n);
            }
        }

        List<Map.Entry<String, Long>> top =
                new ArrayList<Map.Entry<String, Long>>(byLabel.entrySet());
        Collections.sort(top, new Comparator<Map.Entry<String, Long>>() {
            public int compare(Map.Entry<String, Long> a, Map.Entry<String, Long> b) {
                if (b.getValue().longValue() != a.getValue().longValue()) {
                    return b.getValue() < a.getValue() ? -1 : 1;
                }
                return a.getKey().compareTo(b.getKey());
            }
        });
        return new Result(bytes, ops, top);
    }

    private static void add(Map<String, Long> byLabel, String label, long n) {
        Long old = byLabel.get(label);
        byLabel.put(label, Long.valueOf(old == null ? n : old.longValue() + n));
    }

    private static long changed(Cell was, Cell now) {
        boolean wasNull = was.value == null;
        boolean nowNull = now.value == null;
        if (wasNull && nowNull) {
            return 0;
        }
        if (nowNull) {
            // The field still exists; only the reference was cleared.
            return 2;
        }
        if (wasNull) {
            return sizeBorn(now);
        }
        if (was.value.getClass().isArray() && now.value.getClass().isArray()) {
            return changedArray(was.value, now.value);
        }
        if (was.value.getClass().isArray() || now.value.getClass().isArray()) {
            return sizeBorn(now);
        }
        if (isScalar(was.value) && isScalar(now.value)) {
            return was.value.equals(now.value) ? 0 : scalarSize(now.value);
        }
        return was.value == now.value ? 0 : 2;
    }

    private static long changedArray(Object a, Object b) {
        if (a.getClass() != b.getClass()) {
            return sizeBorn(new Cell("", b));
        }
        Class<?> component = a.getClass().getComponentType();
        int n = Array.getLength(a);
        int m = Array.getLength(b);
        long bytes = 0;
        int common = Math.min(n, m);
        for (int i = 0; i < common; i++) {
            Object x = Array.get(a, i);
            Object y = Array.get(b, i);
            boolean differs = component.isPrimitive() ? !eq(x, y) : x != y;
            if (differs) {
                bytes += elementSize(component);
            }
        }
        if (n != m) {
            bytes += (long) Math.abs(m - n) * elementSize(component);
        }
        return bytes;
    }

    private static boolean eq(Object a, Object b) {
        return a == null ? b == null : a.equals(b);
    }

    private static long sizeBorn(Cell cell) {
        Object v = cell.value;
        if (v == null) {
            return 0;
        }
        if (v.getClass().isArray()) {
            return (long) Array.getLength(v) * elementSize(v.getClass().getComponentType());
        }
        if (isScalar(v)) {
            return scalarSize(v);
        }
        return 2;
    }

    private static long bornOps(Cell cell) {
        Object v = cell.value;
        if (v == null) {
            return 0;
        }
        if (v.getClass().isArray()) {
            return Array.getLength(v);
        }
        return 1;
    }

    private static boolean isScalar(Object v) {
        return v instanceof Byte || v instanceof Short || v instanceof Integer
                || v instanceof Long || v instanceof Boolean || v instanceof Character
                || v instanceof Float || v instanceof Double;
    }

    private static long scalarSize(Object v) {
        if (v instanceof Byte || v instanceof Boolean) {
            return 1;
        }
        if (v instanceof Short || v instanceof Character) {
            return 2;
        }
        if (v instanceof Integer || v instanceof Float) {
            return 4;
        }
        return 8;
    }

    private static long elementSize(Class<?> component) {
        if (component == long.class || component == double.class) {
            return 8;
        }
        if (component == int.class || component == float.class) {
            return 4;
        }
        if (component == short.class || component == char.class) {
            return 2;
        }
        return component.isPrimitive() ? 1 : 2; // booleans, bytes and references
    }

    /** card42 card-side types only: never the host tree, the tests or the platform. */
    private static boolean isCardType(Class<?> type) {
        if (type.isArray()) {
            return isCardType(type.getComponentType());
        }
        Package p = type.getPackage();
        String name = p == null ? "" : p.getName();
        if (name.equals("card42")) {
            return true;
        }
        if (!name.startsWith("card42.")) {
            return false;
        }
        return !name.startsWith("card42.host.") && !name.startsWith("card42.test.");
    }
}
