package card42.test;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import card42.host.common.codec.TlvWriter;
import card42.host.emv.kernel.entry.ApplicationSelection;
import card42.host.common.util.Hex;

/**
 * Unit tests for {@link ApplicationSelection} (EMV v4.4 Book 1 §12.3): PSE FCI
 * validation and ADF Name / priority selection.
 */
final class ApplicationSelectionTest {

    private static final String AID_A = "43415244420101";
    private static final String AID_B = "43415244420102";

    private ApplicationSelectionTest() {
    }

    static void run() {
        System.out.println("ApplicationSelectionTest");

        byte[] pse = pseFci();
        Asserts.check(ApplicationSelection.isPseFci(pse), "valid PSE FCI accepted");
        Asserts.check(!ApplicationSelection.isPseFci(ppseFci()),
                "a PPSE FCI is not a PSE FCI");

        // One directory record with one entry: the ADF Name is selected.
        List<byte[]> records = new ArrayList<byte[]>();
        records.add(dirRecord(AID_A, 0x01));
        Asserts.eq(AID_A, ApplicationSelection.selectFromPse(
                pse, records, new String[] { AID_A }), "single entry selected");

        // The lower priority value wins.
        records = new ArrayList<byte[]>();
        records.add(dirRecord(AID_A, 0x03, AID_B, 0x01));
        Asserts.eq(AID_B, ApplicationSelection.selectFromPse(
                pse, records, new String[] { AID_A, AID_B }),
                "highest priority entry selected");

        // Entries spread over several records are all considered.
        records = new ArrayList<byte[]>();
        records.add(dirRecord(AID_A, 0x05));
        records.add(dirRecord(AID_B, 0x02));
        Asserts.eq(AID_B, ApplicationSelection.selectFromPse(
                pse, records, new String[] { AID_A, AID_B }),
                "entry in a later record selected by priority");

        // An unsupported ADF Name is ignored.
        records = new ArrayList<byte[]>();
        records.add(dirRecord(AID_B, 0x01));
        Asserts.check(ApplicationSelection.selectFromPse(
                pse, records, new String[] { AID_A }) == null,
                "unsupported ADF Name yields no candidate");

        // A partial (prefix) ADF Name matches the supported AID.
        records = new ArrayList<byte[]>();
        records.add(dirRecord(AID_A + "0102", 0x01));
        Asserts.eq(AID_A + "0102", ApplicationSelection.selectFromPse(
                pse, records, new String[] { AID_A }), "prefix ADF Name matched");

        // A missing priority defaults to the lowest priority (15).
        records = new ArrayList<byte[]>();
        records.add(dirRecordNoPriority(AID_A));
        records.add(dirRecord(AID_B, 0x0F));
        Asserts.eq(AID_A, ApplicationSelection.selectFromPse(
                pse, records, new String[] { AID_A, AID_B }),
                "missing priority loses to an explicit priority");

        // Records without entries and entries without an ADF Name are skipped,
        // not treated as the end of the directory: a later record is still
        // considered (EMV v4.4 Book 1 §12.3.2 step 2).
        records = new ArrayList<byte[]>();
        records.add(Hex.parse("70 03 5F 28 02")); // 70 without 61
        records.add(Hex.parse("84 0E 31504159")); // record without 70
        records.add(entryWithoutAdf()); // 61 without 4F
        records.add(dirRecord(AID_A, 0x01));
        Asserts.eq(AID_A, ApplicationSelection.selectFromPse(
                pse, records, new String[] { AID_A }),
                "records without entries are skipped, not terminal");

        // A non-PSE FCI yields no candidate even with valid records.
        records = new ArrayList<byte[]>();
        records.add(dirRecord(AID_A, 0x01));
        Asserts.check(ApplicationSelection.selectFromPse(ppseFci(), records,
                new String[] { AID_A, AID_B }) == null,
                "non-PSE FCI yields no candidate");

        // A terminal without cardholder confirmation skips an entry whose
        // priority indicator requires it ('87' b8) and selects the highest
        // priority entry that does not (EMV v4.4 Book 1 §12.4 step 5).
        records = new ArrayList<byte[]>();
        records.add(dirRecordWithConfirmation(AID_A, 0x01));
        records.add(dirRecord(AID_B, 0x02));
        Asserts.eq(AID_B, ApplicationSelection.selectFromPse(
                pse, records, new String[] { AID_A, AID_B }),
                "confirmation-required entry is skipped");

        // A single mutually supported application that requires cardholder
        // confirmation terminates the session instead of falling back
        // (EMV v4.4 Book 1 §12.4 step 2).
        final List<byte[]> singleConfirm = new ArrayList<byte[]>();
        singleConfirm.add(dirRecordWithConfirmation(AID_A, 0x01));
        boolean terminated = false;
        try {
            ApplicationSelection.selectFromPse(pse, singleConfirm, new String[] { AID_A });
        } catch (ApplicationSelection.TerminateSessionException e) {
            terminated = true;
        }
        Asserts.check(terminated,
                "single confirmation-required candidate terminates the session");

        // When every candidate requires confirmation there is no selectable
        // application, so the session terminates (EMV v4.4 Book 1 §12.4 step 5).
        final List<byte[]> allConfirm = new ArrayList<byte[]>();
        allConfirm.add(dirRecordWithConfirmation(AID_A, 0x01));
        allConfirm.add(dirRecordWithConfirmation(AID_B, 0x02));
        terminated = false;
        try {
            ApplicationSelection.selectFromPse(pse, allConfirm, new String[] { AID_A, AID_B });
        } catch (ApplicationSelection.TerminateSessionException e) {
            terminated = true;
        }
        Asserts.check(terminated, "all-confirmation candidate list terminates the session");

        // --- Cardholder confirmation callback (EMV v4.4 Book 1 §12.4 step 5) --
        // A confirmation-required candidate is selected when the cardholder
        // accepts it.
        records = new ArrayList<byte[]>();
        records.add(dirRecordWithConfirmation(AID_A, 0x01));
        List<String> accepted = ApplicationSelection.selectCandidatesFromPse(
                pse, records, new String[] { AID_A }, (adf, label) -> true);
        Asserts.eq(1, accepted.size(), "confirmed candidate joins the list");
        Asserts.eq(AID_A, accepted.get(0), "confirmed candidate selected");

        // When the cardholder declines the only candidate, the session terminates.
        final List<byte[]> declineRecords = new ArrayList<byte[]>();
        declineRecords.add(dirRecordWithConfirmation(AID_A, 0x01));
        terminated = false;
        try {
            ApplicationSelection.selectCandidatesFromPse(pse, declineRecords,
                    new String[] { AID_A }, (adf, label) -> false);
        } catch (ApplicationSelection.TerminateSessionException e) {
            terminated = true;
        }
        Asserts.check(terminated, "declined confirmation terminates the session");

        // The Application Label is passed to the callback.
        records = new ArrayList<byte[]>();
        records.add(dirRecordWithConfirmationAndLabel(AID_A, 0x01, "card42"));
        final String[] seenLabel = new String[1];
        ApplicationSelection.selectCandidatesFromPse(pse, records,
                new String[] { AID_A }, (adf, label) -> {
                    seenLabel[0] = label;
                    return true;
                });
        Asserts.eq("card42", seenLabel[0], "confirmation callback receives the label");

        // An unconditional lower-priority entry follows a declined confirmation
        // entry.
        records = new ArrayList<byte[]>();
        records.add(dirRecordWithConfirmation(AID_A, 0x01));
        records.add(dirRecord(AID_B, 0x02));
        List<String> withProvider = ApplicationSelection.selectCandidatesFromPse(
                pse, records, new String[] { AID_A, AID_B }, (adf, label) -> false);
        Asserts.eq(AID_B, withProvider.get(0),
                "unconditional candidate precedes a declined confirmation entry");
    }

    /** A valid PSE FCI: 6F { 84 (1PAY.SYS.DDF01), A5 { 88 01 01 } }. */
    private static byte[] pseFci() {
        ByteArrayOutputStream a5 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(a5, 0x88, new byte[] { 0x01 });
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x84, Hex.parse("315041592E5359532E4444463031"));
        TlvWriter.writeTlv(body, 0xA5, a5.toByteArray());
        ByteArrayOutputStream fci = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fci, 0x6F, body.toByteArray());
        return fci.toByteArray();
    }

    /** A PPSE-like FCI (2PAY.SYS.DDF01 with a BF0C), not a PSE. */
    private static byte[] ppseFci() {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        TlvWriter.writeTlv(body, 0x84, Hex.parse("325041592E5359532E4444463031"));
        TlvWriter.writeTlv(body, 0xA5, new byte[] { (byte) 0xBF, 0x0C, 0x00 });
        ByteArrayOutputStream fci = new ByteArrayOutputStream();
        TlvWriter.writeTlv(fci, 0x6F, body.toByteArray());
        return fci.toByteArray();
    }

    /** A directory record 70 { 61 { 4F, 87 } ... }. */
    private static byte[] dirRecord(String aid, int priority) {
        return dirRecord(aid, priority, null, 0);
    }

    /** A directory record with a second entry (aidB == null for one entry). */
    private static byte[] dirRecord(String aidA, int priorityA, String aidB, int priorityB) {
        ByteArrayOutputStream t70 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(t70, 0x61, entry(aidA, priorityA));
        if (aidB != null) {
            TlvWriter.writeTlv(t70, 0x61, entry(aidB, priorityB));
        }
        ByteArrayOutputStream record = new ByteArrayOutputStream();
        TlvWriter.writeTlv(record, 0x70, t70.toByteArray());
        return record.toByteArray();
    }

    /** An entry 61 { 4F, 87 }. */
    private static byte[] entry(String aid, int priority) {
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(entry, 0x4F, Hex.parse(aid));
        TlvWriter.writeTlv(entry, 0x87, new byte[] { (byte) priority });
        return entry.toByteArray();
    }

    /** A directory record whose entry requires cardholder confirmation (87 b8). */
    private static byte[] dirRecordWithConfirmation(String aid, int priority) {
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(entry, 0x4F, Hex.parse(aid));
        TlvWriter.writeTlv(entry, 0x87, new byte[] { (byte) (priority | 0x80) });
        ByteArrayOutputStream t70 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(t70, 0x61, entry.toByteArray());
        ByteArrayOutputStream record = new ByteArrayOutputStream();
        TlvWriter.writeTlv(record, 0x70, t70.toByteArray());
        return record.toByteArray();
    }

    /** A confirmation-required entry (87 b8) with an Application Label (50). */
    private static byte[] dirRecordWithConfirmationAndLabel(String aid, int priority,
            String label) {
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(entry, 0x4F, Hex.parse(aid));
        TlvWriter.writeTlv(entry, 0x87, new byte[] { (byte) (priority | 0x80) });
        TlvWriter.writeTlv(entry, 0x50,
                label.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        ByteArrayOutputStream t70 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(t70, 0x61, entry.toByteArray());
        ByteArrayOutputStream record = new ByteArrayOutputStream();
        TlvWriter.writeTlv(record, 0x70, t70.toByteArray());
        return record.toByteArray();
    }

    /** A directory record whose entry has no priority (87). */
    private static byte[] dirRecordNoPriority(String aid) {
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(entry, 0x4F, Hex.parse(aid));
        ByteArrayOutputStream t70 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(t70, 0x61, entry.toByteArray());
        ByteArrayOutputStream record = new ByteArrayOutputStream();
        TlvWriter.writeTlv(record, 0x70, t70.toByteArray());
        return record.toByteArray();
    }

    /** A directory record whose 61 has no ADF Name. */
    private static byte[] entryWithoutAdf() {
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlvWriter.writeTlv(entry, 0x50, Hex.parse("454D563432"));
        ByteArrayOutputStream t70 = new ByteArrayOutputStream();
        TlvWriter.writeTlv(t70, 0x61, entry.toByteArray());
        ByteArrayOutputStream record = new ByteArrayOutputStream();
        TlvWriter.writeTlv(record, 0x70, t70.toByteArray());
        return record.toByteArray();
    }
}
