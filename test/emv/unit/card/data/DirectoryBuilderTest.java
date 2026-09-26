package card42.test;

import java.util.List;

import card42.emv.DirectoryBuilder;
import card42.common.Tlv;
import card42.host.common.util.Hex;
import card42.host.common.codec.Tags;

/**
 * Pure-JVM tests for the default PSE / PPSE Directory Entry builder
 * (EMV Contactless Book B v2.12 Table 3-2/3-3/3-4).  It covers the Kernel
 * Identifier encoding, the Application Priority Indicator masking and several
 * Directory Entries in one PPSE A5 template, all without the simulator.
 */
final class DirectoryBuilderTest {

    private DirectoryBuilderTest() {
    }

    static void run() {
        System.out.println("DirectoryBuilder");

        byte[] entries = new byte[256];
        short p = 0;
        // Candidate 1: contactless AID, label, priority 2, kernel 00 (by ADF name).
        p = DirectoryBuilder.appendDirectoryEntry(entries, p,
                Hex.parse("43415244420102"), (short) 7,
                "CTLS".getBytes(java.nio.charset.StandardCharsets.US_ASCII), (short) 4,
                (byte) 0x02, true, new byte[] { 0x00 }, (short) 1);
        // Candidate 2: another AID, priority 1, a 3-byte domestic kernel ID.
        p = DirectoryBuilder.appendDirectoryEntry(entries, p,
                Hex.parse("43415244420104"), (short) 7,
                "TEST".getBytes(java.nio.charset.StandardCharsets.US_ASCII), (short) 4,
                (byte) 0x01, true, Hex.parse("80 84 01"), (short) 3);
        // Candidate 3: no label, priority 0x12 (b8-b5 RFU must be cleared,
        // EMV Contactless Book B v2.12 Table 3-3), no kernel.
        p = DirectoryBuilder.appendDirectoryEntry(entries, p,
                Hex.parse("43415244420106"), (short) 7,
                null, (short) 0, (byte) 0x12, true, null, (short) 0);

        byte[] a5Raw = new byte[256];
        short a5Length = DirectoryBuilder.buildPpseA5(entries, p, a5Raw);
        byte[] a5 = java.util.Arrays.copyOf(a5Raw, a5Length);

        // The A5 template is well formed and its encoded length is returned.
        Asserts.eq(Tlv.totalLength(a5, (short) 0), a5Length, "A5 encoded length");
        Asserts.eq(0xA5, a5[0] & 0xFF, "A5 tag");
        byte[] bf0c = Tags.find(a5, 0xBF0C);
        Asserts.check(bf0c != null, "A5 carries BF0C");
        // BF0C is nested inside A5.
        Asserts.check(Tags.find(a5, 0xBF0C) != null, "BF0C is nested inside A5");

        List<byte[]> found = Tags.findAll(a5, 0x61);
        Asserts.eq(3, found.size(), "three Directory Entries");

        // Entry 1: 4F, 50, 87=02, 9F2A=00.
        Asserts.bytes(Hex.parse("43415244420102"), Tags.find(found.get(0), 0x4F),
                "entry 1 ADF name");
        Asserts.bytes("CTLS".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                Tags.find(found.get(0), 0x50), "entry 1 label");
        Asserts.bytes(new byte[] { 0x02 }, Tags.find(found.get(0), 0x87),
                "entry 1 priority");
        Asserts.bytes(new byte[] { 0x00 }, Tags.find(found.get(0), 0x9F2A),
                "entry 1 kernel identifier");
        // 9F2A is nested inside the 61 entry.
        Asserts.check(Tags.find(found.get(0), 0x9F2A) != null,
                "entry 1 9F2A is nested inside 61");

        // Entry 2: 3-byte kernel identifier.
        Asserts.bytes(Hex.parse("80 84 01"), Tags.find(found.get(1), 0x9F2A),
                "entry 2 kernel identifier");
        Asserts.bytes(new byte[] { 0x01 }, Tags.find(found.get(1), 0x87),
                "entry 2 priority");

        // Entry 3: no label, priority masked to b4-b1, no kernel identifier.
        Asserts.check(Tags.find(found.get(2), 0x50) == null,
                "entry 3 has no label");
        Asserts.bytes(new byte[] { 0x02 }, Tags.find(found.get(2), 0x87),
                "entry 3 priority is masked to b4-b1");
        Asserts.check(Tags.find(found.get(2), 0x9F2A) == null,
                "entry 3 has no kernel identifier");

        // A PSE-style entry (no kernel) is also well formed, and its priority
        // preserves b8 (cardholder confirmation) while clearing the RFU b7-b5
        // (EMV v4.4 Book 1 Table 13).
        byte[] pseEntry = new byte[32];
        short pseLength = DirectoryBuilder.appendDirectoryEntry(pseEntry, (short) 0,
                Hex.parse("43415244420101"), (short) 7,
                "CONTACT".getBytes(java.nio.charset.StandardCharsets.US_ASCII), (short) 7,
                (byte) 0x81, false, null, (short) 0);
        Asserts.eq(Tlv.totalLength(pseEntry, (short) 0), pseLength,
                "PSE entry encoded length");
        Asserts.bytes(Hex.parse("43415244420101"), Tags.find(pseEntry, 0x4F),
                "PSE entry ADF name");
        Asserts.bytes(new byte[] { (byte) 0x81 }, Tags.find(pseEntry, 0x87),
                "PSE priority keeps b8 (cardholder confirmation)");
        Asserts.check(Tags.find(pseEntry, 0x9F2A) == null,
                "PSE entry has no kernel identifier");
    }
}
