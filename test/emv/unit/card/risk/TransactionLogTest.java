package card42.test;

import java.util.Arrays;

import card42.emv.EMVProtocolState;
import card42.emv.EMVStaticData;
import card42.emv.TransactionLog;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for the card transaction log (EMV v4.4 Book 3
 * Annex D4): the default format / record length, the plain value-concatenation
 * record, and the index-free cyclic behaviour (record #1 is the newest, the
 * oldest is overwritten, a record number beyond the stored entries is missing).
 */
final class TransactionLogTest {

    private TransactionLogTest() {
    }

    static void run() {
        System.out.println("TransactionLog");

        EMVProtocolState state = new EMVProtocolState();
        EMVStaticData data = new EMVStaticData();
        TransactionLog log = new TransactionLog();

        Asserts.eq(15, log.getSfi(), "log SFI is in 11..30");
        Asserts.eq(8, log.getCapacity(), "log capacity");
        Asserts.eq(19, log.getRecordLength(), "default log record length");
        Asserts.eq(0, log.count(), "fresh log is empty");
        Asserts.eq(-1, log.readRecord((short) 1, new byte[32], (short) 0),
                "empty log has no record 1");

        // A terminal data buffer matching the default CDOL1 (43 bytes).  The
        // offsets are 9F02=0, 95=14, 5F2A=19, 9A=21 (see Defaults.CDOL1).
        byte[] terminal = new byte[43];
        terminal[5] = (byte) 0x50; // amount 000000000050
        terminal[18] = (byte) 0x80; // TVR 0000000080
        terminal[19] = 0x03;
        terminal[20] = 0x56; // currency 0356
        terminal[21] = 0x25;
        terminal[22] = 0x09;
        terminal[23] = 0x15; // date 250915

        state.advanceATC(); // ATC 1
        log.write((byte) 0x40, state, data, terminal, (short) terminal.length);
        Asserts.eq(1, log.count(), "one record stored");

        byte[] rec = new byte[32];
        short len = log.readRecord((short) 1, rec, (short) 0);
        Asserts.eq(19, len, "record length");
        byte[] expected = new byte[19];
        expected[0] = 0x25;
        expected[1] = 0x09;
        expected[2] = 0x15; // date
        expected[3] = 0x03;
        expected[4] = 0x56; // currency
        expected[10] = (byte) 0x50; // amount low byte
        expected[11] = 0x00;
        expected[12] = 0x01; // ATC 1
        expected[13] = 0x40; // CID TC
        expected[18] = (byte) 0x80; // TVR low byte
        Asserts.bytes(expected, Arrays.copyOf(rec, len), "record 1 is a plain concatenation");

        // The newest record is #1: a second write takes that position.
        state.advanceATC(); // ATC 2
        log.write((byte) 0x00, state, data, terminal, (short) terminal.length);
        Asserts.eq(2, log.count(), "two records");
        log.readRecord((short) 1, rec, (short) 0);
        Asserts.eq(0x02, rec[12], "record 1 ATC is the newest");
        Asserts.eq(0x00, rec[13], "record 1 CID is the newest");
        log.readRecord((short) 2, rec, (short) 0);
        Asserts.eq(0x01, rec[12], "record 2 ATC is the previous one");

        // The ring overwrites the oldest entry and never grows past capacity.
        for (short atc = 3; atc <= 10; atc++) {
            state.advanceATC();
            log.write((byte) 0x40, state, data, terminal, (short) terminal.length);
        }
        Asserts.eq(8, log.count(), "ring is capped at capacity");
        log.readRecord((short) 1, rec, (short) 0);
        Asserts.eq(0x0A, rec[12], "record 1 is the last written");
        log.readRecord((short) 8, rec, (short) 0);
        Asserts.eq(0x03, rec[12], "record 8 is the oldest live entry");
        Asserts.eq(-1, log.readRecord((short) 9, rec, (short) 0),
                "record beyond capacity is missing");

        // A personalised format changes the record length.
        TransactionLog custom = new TransactionLog();
        custom.setFormat(Hex.parse("9F3602"), (short) 0, (short) 3);
        Asserts.eq(2, custom.getRecordLength(), "custom format record length");
        custom.write((byte) 0x40, state, data, terminal, (short) terminal.length);
        short customLen = custom.readRecord((short) 1, rec, (short) 0);
        Asserts.eq(2, customLen, "custom record length on read");
        Asserts.eq(0x00, rec[0], "custom record holds the ATC high byte");
        Asserts.eq(0x0A, rec[1], "custom record holds the ATC low byte");

        // --- Malformed / oversized formats (docs/specs/common/toolchain.md §6) -----
        TransactionLog bad = new TransactionLog();
        Asserts.sw((short) 0x6A80,
                () -> bad.setFormat(new byte[33], (short) 0, (short) 33),
                "format longer than 32 bytes -> 6A80");
        Asserts.sw((short) 0x6A80,
                () -> bad.setFormat(Hex.parse("9F02"), (short) 0, (short) 2),
                "truncated format -> 6A80");
        Asserts.sw((short) 0x6A80,
                () -> bad.setFormat(Hex.parse("9F0200"), (short) 0, (short) 3),
                "zero-length format -> 6A80");
        Asserts.sw((short) 0x6A80,
                () -> bad.setFormat(Hex.parse("9F0221"), (short) 0, (short) 3),
                "format record longer than 32 -> 6A80");
        // The default format is retained after a rejected setFormat.
        Asserts.eq(19, bad.getRecordLength(), "default format survives a rejected update");

        // --- Sequence renumbering at the 16-bit wrap (EMV v4.4 Book 3 Annex D4) -------
        // After MAX_SEQUENCE writes the ring renumbers its live slots
        // consecutively, so all CAPACITY records remain readable in order
        // instead of collapsing onto sequence 1.
        TransactionLog ring = new TransactionLog();
        EMVProtocolState ringState = new EMVProtocolState();
        for (int i = 0; i < 0x7FFE + 4; i++) {
            ringState.advanceATC();
            ring.write((byte) 0x40, ringState, data, terminal, (short) terminal.length);
        }
        Asserts.eq(8, ring.count(), "renumbered ring keeps capacity records");
        int[] atcs = new int[8];
        for (short r = 1; r <= 8; r++) {
            short l = ring.readRecord(r, rec, (short) 0);
            Asserts.eq(19, l, "renumbered record " + r + " is readable");
            atcs[r - 1] = ((rec[11] & 0xFF) << 8) | (rec[12] & 0xFF);
        }
        for (short r = 1; r < 8; r++) {
            Asserts.check(atcs[r - 1] > atcs[r],
                    "renumbered record " + r + " is newer than record " + (r + 1));
        }
        Asserts.eq(-1, ring.readRecord((short) 9, rec, (short) 0),
                "renumbered ring has no record 9");

        // A slot whose stored bytes no longer match the checksum is treated as
        // empty, so the caller reports 6A83 (EMV v4.4 Book 3 Annex D4).  The
        // corruption is injected directly because no APDU path can write a
        // record without recomputing the checksum.
        TransactionLog corrupt = new TransactionLog();
        corrupt.write((byte) 0x40, state, data, terminal, (short) terminal.length);
        try {
            java.lang.reflect.Field slots = TransactionLog.class.getDeclaredField("records");
            slots.setAccessible(true);
            byte[] stored = (byte[]) slots.get(corrupt);
            stored[0] ^= 0x01;
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
        Asserts.eq(-1, corrupt.readRecord((short) 1, rec, (short) 0),
                "checksum mismatch -> record missing (6A83)");
    }
}
