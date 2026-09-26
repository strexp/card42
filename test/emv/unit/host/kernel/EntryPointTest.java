package card42.test;

import java.io.ByteArrayOutputStream;

import card42.host.common.codec.TlvWriter;
import card42.host.emv.kernel.entry.Combination;
import card42.host.emv.kernel.entry.CombinationTable;
import card42.host.emv.kernel.entry.EntryPoint;
import card42.host.common.util.Hex;

/**
 * Unit tests for the Entry Point Combination Selection details that the
 * end-to-end suites do not reach (EMV Contactless Book B v2.12
 * §3.3.2 / Table 3-6 / Table A-1): the brand default Requested Kernel
 * IDs, ADF Name partial matching, the Application Priority Indicator edge
 * values, the nested-Directory-Entry rule and the malformed Kernel Identifier
 * lengths.
 */
final class EntryPointTest {

    /**
     * A Kernel Identifier that decodes to a Requested Kernel ID of 0 for a
     * brand AID: a single-byte '00' would select the Table 3-6 brand default,
     * so the multi-byte form whose first byte is '00' is used instead
     * (Book B §3.3.2.5 bullet C).
     */
    private static final byte[] KERNEL_ZERO = { 0x00, 0x01 };

    private EntryPointTest() {
    }

    static void run() {
        System.out.println("EntryPoint");

        // --- brand default Requested Kernel IDs (Book B Table 3-6) ----------
        Asserts.eq(3, EntryPoint.defaultKernelId("A0000000031010"), "Visa default kernel 3");
        Asserts.eq(2, EntryPoint.defaultKernelId("A0000000041010"),
                "Mastercard default kernel 2");
        Asserts.eq(4, EntryPoint.defaultKernelId("A00000002501"), "Amex default kernel 4");
        Asserts.eq(5, EntryPoint.defaultKernelId("A0000000651010"), "JCB default kernel 5");
        Asserts.eq(6, EntryPoint.defaultKernelId("A0000001523010"),
                "Discover default kernel 6");
        Asserts.eq(7, EntryPoint.defaultKernelId("A0000003330101"),
                "UnionPay default kernel 7");
        Asserts.eq(0, EntryPoint.defaultKernelId("43415244420102"), "other AID default kernel 0");

        // --- ADF Name full and partial (prefix) matching (bullet B) ---------
        // The flat supported-AID list is a reader Combination Table whose
        // Combinations all carry the reader's implemented kernel
        // (EntryPoint.READER_KERNEL_ID = 0), so the Directory Entries request
        // kernel 0 with the multi-byte '00 01' Kernel Identifier.
        String[] visa = { "A0000000031010" };
        Asserts.eq("A0000000031010", EntryPoint.selectCandidate(
                        ppseFci(entry("A0000000031010", 0x01, KERNEL_ZERO, null)), visa),
                "full ADF Name match");
        Asserts.eq("A000000003101001", EntryPoint.selectCandidate(
                        ppseFci(entry("A000000003101001", 0x01, KERNEL_ZERO, null)), visa),
                "ADF Name prefix match");

        // --- Application Priority Indicator edge values ---------------------
        // 87 absent, 0x00 and 0x0F all mean the lowest priority (15), so the
        // entry with 0x02 is selected first (Book B Table 3-3).
        String[] two = { "A0000000031010", "A0000000031011" };
        Asserts.eq("A0000000031011", EntryPoint.selectCandidate(ppseFci(
                        entry("A0000000031010", -1, KERNEL_ZERO, null),
                        entry("A0000000031011", 0x02, KERNEL_ZERO, null)), two),
                "missing 87 is the lowest priority");
        Asserts.eq("A0000000031011", EntryPoint.selectCandidate(ppseFci(
                        entry("A0000000031010", 0x00, KERNEL_ZERO, null),
                        entry("A0000000031011", 0x02, KERNEL_ZERO, null)), two),
                "87=00 is the lowest priority");
        Asserts.eq("A0000000031011", EntryPoint.selectCandidate(ppseFci(
                        entry("A0000000031010", 0x0F, KERNEL_ZERO, null),
                        entry("A0000000031011", 0x02, KERNEL_ZERO, null)), two),
                "87=0F is the lowest priority");
        // The high nibble of 87 is RFU and must be ignored (Book B Table 3-3):
        // 0xF1 is priority 1, so it beats the 0x02 entry.
        Asserts.eq("A0000000031010", EntryPoint.selectCandidate(ppseFci(
                        entry("A0000000031010", 0xF1, KERNEL_ZERO, null),
                        entry("A0000000031011", 0x02, KERNEL_ZERO, null)), two),
                "87 high nibble is ignored");

        // --- a nested 61 is not a Directory Entry (Table 3-2 note) ----------
        byte[] nested = ppseFciNested(entry("A0000000031010", 0x01, KERNEL_ZERO, null));
        Asserts.check(EntryPoint.selectCandidate(nested, visa) == null,
                "a 61 nested in a proprietary template is ignored");

        // --- malformed Kernel Identifier lengths (Table A-1) ----------------
        // A 2-byte value with b8b7 = 10b is an Extended Kernel ID that needs at
        // least 3 bytes, so it is skipped (Book B Table 3-5).
        Asserts.check(EntryPoint.selectCandidate(ppseFci(
                        entry("A0000000031010", 0x01, new byte[] { (byte) 0x80, 0x00 }, null)),
                        visa) == null,
                "2-byte 9F2A with b8b7=10b is skipped");
        Asserts.check(EntryPoint.selectCandidate(ppseFci(
                        entry("A0000000031010", 0x01, new byte[9], null)), visa) == null,
                "9F2A longer than 8 bytes is skipped");
        // The reader implements only kernel 0, so a Visa card that requests
        // its brand default kernel 3 is not a candidate
        // (Book B §3.3.2.5 bullet D).
        Asserts.check(EntryPoint.selectCandidate(ppseFci(
                        entry("A0000000031010", 0x01, new byte[] { 0x03 }, null)), visa) == null,
                "Visa requested kernel 3 is not supported by the kernel-0 reader");
        Asserts.check(EntryPoint.selectCandidate(ppseFci(
                        entry("A0000000031010", 0x01, null, null)), visa) == null,
                "Visa default requested kernel 3 is not supported by the kernel-0 reader");
        // b8b7 = 10b: bytes 1-3 are the Extended Kernel ID; the default is not
        // used, so a non-matching 3-byte value is skipped (Book B Table 3-5).
        Asserts.check(EntryPoint.selectCandidate(ppseFci(
                        entry("A0000000031010", 0x01,
                                new byte[] { (byte) 0x80, 0x00, 0x02 }, null)), visa) == null,
                "extended Kernel ID not matching the Combination is skipped");

        // --- malformed ADF Name lengths (5-16 bytes, bullet A) --------------
        Asserts.check(EntryPoint.selectCandidate(ppseFci(
                        entry("A00000", 0x01, null, null)), visa) == null,
                "ADF Name shorter than 5 bytes is skipped");
        Asserts.check(EntryPoint.selectCandidate(ppseFci(
                        entry("A0000000031010112233445566778899AA", 0x01, null, null)),
                        visa) == null,
                "ADF Name longer than 16 bytes is skipped");

        // --- '9F29' Extended Selection does not change the selection --------
        Asserts.eq("A0000000031010", EntryPoint.selectCandidate(ppseFci(
                        entry("A0000000031010", 0x01, KERNEL_ZERO, Hex.parse("AABB"))), visa),
                "9F29 is carried but not appended to the ADF Name");

        // --- Candidate List entry carries the full bullet E Combination ------
        // ADF Name, AID, Kernel ID, priority presence and Extended Selection
        // (EMV Contactless Book B v2.12 §3.3.2.5 bullet E).
        java.util.List<EntryPoint.Candidate> list = EntryPoint.selectCandidates(
                ppseFci(entry("A000000003101001", 0x01, KERNEL_ZERO, Hex.parse("AABB"))), visa);
        Asserts.eq(1, list.size(), "one Combination");
        EntryPoint.Candidate c = list.get(0);
        Asserts.eq("A000000003101001", c.adfHex, "Candidate carries the ADF Name");
        Asserts.eq("A0000000031010", c.aid, "Candidate carries the matched AID");
        Asserts.eq(EntryPoint.READER_KERNEL_ID, c.kernelId,
                "Candidate carries the reader's implemented Kernel ID");
        Asserts.check(c.priorityPresent, "Candidate records the priority indicator");
        Asserts.bytes(Hex.parse("AABB"), c.extendedSelection,
                "Candidate carries the Extended Selection");

        list = EntryPoint.selectCandidates(ppseFci(
                entry("A0000000031010", -1, KERNEL_ZERO, null)), visa);
        Asserts.check(!list.get(0).priorityPresent,
                "Candidate records an absent priority indicator");
        Asserts.check(list.get(0).extendedSelection == null,
                "Candidate has no Extended Selection when absent");

        // --- Combination Table selection by transaction type (H2) -----------
        // A reader Combination Table that supports the AID for a purchase only
        // yields a Candidate List for a purchase; for cash it is empty
        // (Contactless Application Not Allowed, Book A Table 5-3).
        CombinationTable table = new CombinationTable();
        table.add(CombinationTable.PURCHASE, new Combination("A0000000031010", 3));
        byte[] oneEntry = ppseFci(entry("A0000000031010", 0x01, null, null));
        Asserts.eq(1, EntryPoint.selectCandidates(oneEntry, table,
                        CombinationTable.PURCHASE).size(),
                "purchase combination selects the entry");
        Asserts.check(EntryPoint.selectCandidates(oneEntry, table,
                        CombinationTable.CASH).isEmpty(),
                "no cash combination -> empty Candidate List");
        Asserts.eq(3, EntryPoint.selectCandidates(oneEntry, table,
                        CombinationTable.PURCHASE).get(0).kernelId,
                "table candidate carries the Combination kernel");
        // The Requested Kernel ID must match the Combination's Kernel ID.
        CombinationTable kernel4 = new CombinationTable();
        kernel4.add(CombinationTable.PURCHASE, new Combination("A0000000031010", 4));
        Asserts.check(EntryPoint.selectCandidates(
                        ppseFci(entry("A0000000031010", 0x01, new byte[] { 0x03 }, null)),
                        kernel4, CombinationTable.PURCHASE).isEmpty(),
                "requested kernel 3 does not match combination kernel 4");

        // --- one Directory Entry matches several reader Combinations --------
        // EMV Contactless Book B v2.12 §3.3.2.5: every supported reader
        // Combination processes each Directory Entry, so a zero Requested Kernel
        // ID (kernel by ADF Name, bullet D) yields one Candidate per matching
        // AID/Kernel ID pair instead of only the first match.
        CombinationTable multi = new CombinationTable();
        multi.add(CombinationTable.PURCHASE, new Combination("A0000000031010", 0));
        multi.add(CombinationTable.PURCHASE, new Combination("A0000000031010", 3));
        java.util.List<EntryPoint.Candidate> multiList = EntryPoint.selectCandidates(
                ppseFci(entry("A0000000031010", 0x01, KERNEL_ZERO, null)), multi,
                CombinationTable.PURCHASE);
        Asserts.eq(2, multiList.size(),
                "one Directory Entry yields a Candidate per matching Combination");
        Asserts.eq(0, multiList.get(0).kernelId, "first Combination kernel 0");
        Asserts.eq(3, multiList.get(1).kernelId, "second Combination kernel 3");
    }

    // --- fixtures ------------------------------------------------------------

    /** A PPSE FCI with the given Directory Entry values as direct BF0C children. */
    private static byte[] ppseFci(byte[]... entries) {
        ByteArrayOutputStream bf0c = new ByteArrayOutputStream();
        for (byte[] entry : entries) {
            TlvWriter.writeTlv(bf0c, 0x61, entry);
        }
        return wrap(bf0c.toByteArray());
    }

    /** A PPSE FCI whose only 61 is nested inside a proprietary A5 template. */
    private static byte[] ppseFciNested(byte[] entry) {
        ByteArrayOutputStream proprietary = new ByteArrayOutputStream();
        TlvWriter.writeTlv(proprietary, 0x61, entry);
        ByteArrayOutputStream bf0c = new ByteArrayOutputStream();
        TlvWriter.writeTlv(bf0c, 0xA5, proprietary.toByteArray());
        return wrap(bf0c.toByteArray());
    }

    private static byte[] wrap(byte[] bf0cValue) {
        ByteArrayOutputStream bf0c = new ByteArrayOutputStream();
        TlvWriter.writeTlv(bf0c, 0xBF0C, bf0cValue);
        ByteArrayOutputStream a5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(a5, 0xA5, bf0c.toByteArray());
        return a5.toByteArray();
    }

    /**
     * One 61 Directory Entry.  A priority of -1 omits the 87 tag; a null
     * kernelId omits 9F2A; a non-null extended selection is added as 9F29.
     */
    private static byte[] entry(String aidHex, int priority, byte[] kernelId,
            byte[] extendedSelection) {
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(entry, 0x4F, Hex.parse(aidHex));
        if (priority >= 0) {
            TlvWriter.writeTlv(entry, 0x87, new byte[] { (byte) priority });
        }
        if (kernelId != null) {
            TlvWriter.writeTlv(entry, 0x9F2A, kernelId);
        }
        if (extendedSelection != null) {
            TlvWriter.writeTlv(entry, 0x9F29, extendedSelection);
        }
        return entry.toByteArray();
    }
}
