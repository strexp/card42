package card42.test;

import java.util.Arrays;

import javacard.framework.ISO7816;

import card42.emv.DirectoryRecords;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for the keyed directory record store:
 * EMV v4.4 Book 1 §12.2.3 allows the directory file at any SFI 1-10 and more
 * than one record, so {@code DirectoryApplet} stores them keyed by
 * DGI (SFI&lt;&lt;8)|record.
 *
 * <p>Internal keyed-store coverage; Book 1 §12.2.3 only requires SFI 1-10.
 */
final class DirectoryRecordsTest {

    private DirectoryRecordsTest() {
    }

    static void run() {
        System.out.println("DirectoryRecords");

        DirectoryRecords records = new DirectoryRecords();
        byte[] record1 = Hex.parse("7003610101");
        records.put((short) 0x0101, record1, (short) 0, (short) record1.length);
        Asserts.eq(record1.length, records.lengthOf((short) 0x0101),
                "record stored under (SFI 1, record 1)");
        Asserts.eq(-1, records.lengthOf((short) 0x0201),
                "absent key reports length -1");
        Asserts.eq(-1, records.offsetOf((short) 0x0201),
                "absent key reports offset -1");
        short offset = records.offsetOf((short) 0x0101);
        Asserts.bytes(record1,
                Arrays.copyOfRange(records.pool(), offset, offset + record1.length),
                "record content served from the pool");

        // A second record at another SFI (multi-SFI directory) coexists.
        byte[] record3 = Hex.parse("7003610102");
        records.put((short) 0x0301, record3, (short) 0, (short) record3.length);
        Asserts.eq(record3.length, records.lengthOf((short) 0x0301),
                "record stored under (SFI 3, record 1)");
        Asserts.eq(record1.length, records.lengthOf((short) 0x0101),
                "first record still present after a second SFI");

        // A replacement that fits reuses the slot and updates the content.
        byte[] shorter = Hex.parse("70016100");
        records.put((short) 0x0101, shorter, (short) 0, (short) shorter.length);
        Asserts.eq(shorter.length, records.lengthOf((short) 0x0101),
                "replacement updates the length");
        short newOffset = records.offsetOf((short) 0x0101);
        Asserts.bytes(shorter,
                Arrays.copyOfRange(records.pool(), newOffset, newOffset + shorter.length),
                "replacement content updated");

        // A zero key is not a valid DGI and is rejected.
        Asserts.sw(ISO7816.SW_WRONG_DATA,
                () -> records.put((short) 0, record1, (short) 0, (short) record1.length),
                "key 0 -> 6A80");

        // The record table holds at most four records.
        DirectoryRecords full = new DirectoryRecords();
        for (short sfi = 1; sfi <= 4; sfi++) {
            full.put((short) ((sfi << 8) | 1), record1, (short) 0, (short) record1.length);
        }
        Asserts.sw(ISO7816.SW_WRONG_DATA,
                () -> full.put((short) 0x0501, record1, (short) 0, (short) record1.length),
                "fifth record -> 6A80 (table full)");

        // A record larger than the pool is refused.
        DirectoryRecords small = new DirectoryRecords();
        Asserts.sw(ISO7816.SW_WRONG_DATA,
                () -> small.put((short) 0x0101, new byte[300], (short) 0, (short) 300),
                "oversized record -> 6A80 (pool full)");

        // reset() empties the store (personalization reset).
        records.reset();
        Asserts.eq(-1, records.lengthOf((short) 0x0101), "reset clears the records");
    }
}
