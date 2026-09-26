package card42.test;

import java.util.Arrays;

import card42.emv.RecordStore;

/**
 * Pure-JVM tests for the card-side variable-length record store, including the
 * compact-after-replace regression of docs/specs/common/architecture.md §2.
 *
 * <p>Internal data-structure coverage (no EMV clause); not counted as
 * spec-derived coverage.
 */
final class RecordStoreTest {

    private RecordStoreTest() {
    }

    static void run() {
        System.out.println("RecordStore");

        RecordStore store = new RecordStore();
        byte[] out = new byte[512];

        // --- store / read ---------------------------------------------------
        byte[] a = fill(100, 0x11);
        store.put((short) 0x0101, a, (short) 0, (short) a.length);
        Asserts.eq(100, store.lengthOf((short) 0x0101), "lengthOf after put");
        short n = store.copyIfPresent((short) 0x0101, out, (short) 0);
        Asserts.eq(100, n, "copyIfPresent length");
        Asserts.bytes(a, Arrays.copyOf(out, n), "copyIfPresent content");
        Asserts.eq(-1, store.copyIfPresent((short) 0x0199, out, (short) 0),
                "copyIfPresent absent -> -1");
        Asserts.eq(-1, store.lengthOf((short) 0x0199), "lengthOf absent -> -1");

        // --- smaller replacement is in place --------------------------------
        byte[] a2 = fill(50, 0x22);
        store.put((short) 0x0101, a2, (short) 0, (short) a2.length);
        Asserts.eq(50, store.lengthOf((short) 0x0101), "replace smaller length");
        n = store.copyIfPresent((short) 0x0101, out, (short) 0);
        Asserts.bytes(a2, Arrays.copyOf(out, n), "replace smaller content");

        // --- compact regression (docs/specs/common/architecture.md §2) -------------
        // Build a store whose slot order differs from the physical pool order:
        // record 1 is replaced by a larger value, so its low slot points at the
        // pool tail while record 2 (higher slot) sits at the pool head.  A
        // further put then triggers compact(); the old slot-order compaction
        // copied record 1 over record 2's source and corrupted it.
        RecordStore s = new RecordStore();
        byte[] r1 = fill(100, 0x01);
        byte[] r2 = fill(300, 0x02);
        byte[] r3 = fill(200, 0x03);
        byte[] r4 = fill(100, 0x04);
        byte[] r1b = fill(400, 0x0B);
        s.put((short) 1, r1, (short) 0, (short) r1.length);   // slot 0 @ 0
        s.put((short) 2, r2, (short) 0, (short) r2.length);   // slot 1 @ 100
        s.put((short) 1, r1b, (short) 0, (short) r1b.length); // slot 0 @ 400
        s.put((short) 3, r3, (short) 0, (short) r3.length);   // slot 2 @ 800
        s.put((short) 4, r4, (short) 0, (short) r4.length);   // triggers compact

        n = s.copyIfPresent((short) 1, out, (short) 0);
        Asserts.bytes(r1b, Arrays.copyOf(out, n), "compact keeps record 1");
        n = s.copyIfPresent((short) 2, out, (short) 0);
        Asserts.bytes(r2, Arrays.copyOf(out, n), "compact keeps record 2");
        n = s.copyIfPresent((short) 3, out, (short) 0);
        Asserts.bytes(r3, Arrays.copyOf(out, n), "compact keeps record 3");
        n = s.copyIfPresent((short) 4, out, (short) 0);
        Asserts.bytes(r4, Arrays.copyOf(out, n), "compact keeps record 4");

        // --- overwriting the whole key set still works ----------------------
        s.put((short) 2, r4, (short) 0, (short) r4.length);
        n = s.copyIfPresent((short) 2, out, (short) 0);
        Asserts.bytes(r4, Arrays.copyOf(out, n), "replace record 2 smaller");
    }

    private static byte[] fill(int length, int value) {
        byte[] b = new byte[length];
        Arrays.fill(b, (byte) value);
        return b;
    }
}
