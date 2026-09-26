package card42.host.emv.kernel.entry;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import card42.host.common.codec.Tags;
import card42.host.emv.kernel.core.ConfirmationProvider;
import card42.host.common.util.Hex;

/**
 * Contact application selection (EMV v4.4 Book 1 §12.3).
 *
 * <p>The contact terminal first selects the PSE ('1PAY.SYS.DDF01'); its FCI
 * carries the SFI of the directory elementary file ('88').  The directory
 * records are '70' templates, each holding one or more '61' Directory Entries
 * with the ADF Name ('4F'), an Application Label ('50') and the Application
 * Priority Indicator ('87').  The highest priority entry whose ADF Name is
 * supported is selected.  When the PSE is not supported the terminal may select
 * an ADF Name directly; that fallback is driven by the kernel, not here.
 *
 * <p>Unlike the contactless Entry Point (EMV Contactless Book B v2.12 §3.3.2)
 * the contact directory has no Kernel Identifier ('9F2A'); the selection is by
 * ADF Name and priority only.
 */
public final class ApplicationSelection {

    /** The PSE DF Name ('1PAY.SYS.DDF01', EMV v4.4 Book 1 §12.3.2). */
    public static final byte[] PSE_DF_NAME = Hex.parse("315041592E5359532E4444463031");

    /**
     * Raised when final selection must terminate the session rather than fall
     * back to the List of AIDs method (EMV v4.4 Book 1 §12.4 steps 1-2, 5):
     * there is no selectable application, or the only mutually supported
     * application requires cardholder confirmation and the terminal does not
     * provide it.
     */
    public static final class TerminateSessionException extends RuntimeException {
        TerminateSessionException(String message) {
            super(message);
        }
    }

    private ApplicationSelection() {
    }

    /**
     * True when the FCI is a valid PSE FCI: a '6F' template with the PSE DF
     * Name ('84') and a Directory SFI ('88') (EMV v4.4 Book 1 §12.3.2).
     */
    public static boolean isPseFci(byte[] fci) {
        byte[] dfName = Tags.find(fci, 0x84);
        byte[] sfi = Tags.find(fci, 0x88);
        return dfName != null && java.util.Arrays.equals(dfName, PSE_DF_NAME)
                && sfi != null && sfi.length == 1;
    }

    /**
     * The Directory SFI carried by the PSE FCI ('88'), or -1 when it is absent
     * or outside the valid range 1-10 (EMV v4.4 Book 1 §12.2.3 Table 12).  The
     * terminal must read the directory from this file, not from a hard-coded
     * SFI (EMV v4.4 Book 1 §12.3.2 step 2).
     */
    public static int directorySfi(byte[] fci) {
        byte[] sfi = Tags.find(fci, 0x88);
        if (sfi == null || sfi.length != 1) {
            return -1;
        }
        int value = sfi[0] & 0xFF;
        return (value >= 1 && value <= 10) ? value : -1;
    }

    /**
     * Selects the highest priority supported ADF Name from the PSE FCI and the
     * directory records read so far, or null when none matches.
     *
     * <p>Records without a '70' template, or entries without an ADF Name, are
     * skipped (EMV v4.4 Book 1 §12.3.2 step 2: a record without entries does
     * not end the directory).  The ADF Name matching (full or prefix) and the
     * priority value are the same rules the contactless Entry Point uses, so
     * the two share {@link EntryPoint#matchAid} / {@link EntryPoint#priority}.
     */
    public static String selectFromPse(byte[] pseFci, List<byte[]> directoryRecords,
                                       String[] supportedAids) {
        List<String> candidates = selectCandidatesFromPse(pseFci, directoryRecords, supportedAids);
        return candidates.isEmpty() ? null : candidates.get(0);
    }

    /**
     * The mutually supported ADF Names of the PSE directory in selection order
     * (highest priority first, ties keeping their directory order), excluding
     * entries that require cardholder confirmation.  Used by the kernel to
     * retry the next candidate after a failed final SELECT or a GET PROCESSING
     * OPTIONS '6985' (EMV v4.4 Book 1 §12.4, Book 4 §6.3.1).
     *
     * @throws TerminateSessionException when no candidate can be selected
     *         without cardholder confirmation (EMV v4.4 Book 1 §12.4 steps 2, 5)
     */
    public static List<String> selectCandidatesFromPse(byte[] pseFci,
            List<byte[]> directoryRecords, String[] supportedAids) {
        return selectCandidatesFromPse(pseFci, directoryRecords, supportedAids, null);
    }

    /**
     * As above, with a cardholder confirmation callback (EMV v4.4 Book 1 §12.4
     * step 5).  A null {@code confirmation} means the terminal does not provide
     * cardholder confirmation, so confirmation-required entries are skipped (or
     * terminate the session when no other candidate exists); a non-null
     * callback is consulted for each confirmation-required candidate in
     * priority order and the confirmed entries join the candidate list at their
     * priority position.
     */
    public static List<String> selectCandidatesFromPse(byte[] pseFci,
            List<byte[]> directoryRecords, String[] supportedAids,
            ConfirmationProvider confirmation) {
        List<String> aids = new ArrayList<String>();
        if (!isPseFci(pseFci)) {
            return aids;
        }
        // Build the candidate list of mutually supported ADF Names, keeping the
        // priority, the cardholder-confirmation flag and the label;
        // confirmation-required entries still join the list
        // (EMV v4.4 Book 1 §12.3.2 step 3).
        List<Integer> priorities = new ArrayList<Integer>();
        List<Boolean> confirmations = new ArrayList<Boolean>();
        List<String> labels = new ArrayList<String>();
        for (byte[] record : directoryRecords) {
            byte[] t70 = Tags.find(record, 0x70);
            if (t70 == null) {
                continue;
            }
            for (byte[] entry : Tags.findAllDirect(t70, 0x61)) {
                byte[] adf = Tags.find(entry, 0x4F);
                if (adf == null) {
                    continue;
                }
                // ADF Name is 5-16 bytes (RID 5 + PIX 0-11), M (EMV v4.4 Book 1
                // §12.2.1 Table 12); a malformed entry is skipped.
                if (adf.length < 5 || adf.length > 16) {
                    continue;
                }
                String adfHex = Hex.format(adf);
                if (EntryPoint.matchAid(adfHex, supportedAids) == null) {
                    continue;
                }
                byte[] label = Tags.find(entry, 0x50);
                aids.add(adfHex);
                priorities.add(EntryPoint.priority(entry));
                confirmations.add(EntryPoint.confirmationRequired(entry));
                labels.add(label == null ? null
                        : new String(label, StandardCharsets.US_ASCII));
            }
        }
        if (aids.isEmpty()) {
            return aids;
        }
        // EMV v4.4 Book 1 §12.4 steps 2/5: order by priority (stable, so ties
        // keep their directory order); a confirmation-required entry is
        // included only when the terminal provides confirmation and the
        // cardholder accepts it.
        List<Integer> order = new ArrayList<Integer>();
        for (int i = 0; i < aids.size(); i++) {
            order.add(i);
        }
        java.util.Collections.sort(order, new java.util.Comparator<Integer>() {
            @Override
            public int compare(Integer a, Integer b) {
                return Integer.compare(priorities.get(a), priorities.get(b));
            }
        });
        List<String> result = new ArrayList<String>();
        for (int i : order) {
            if (!confirmations.get(i)) {
                result.add(aids.get(i));
            } else if (confirmation != null
                    && confirmation.confirm(aids.get(i), labels.get(i))) {
                result.add(aids.get(i));
            }
        }
        if (result.isEmpty()) {
            // No candidate can be selected without cardholder confirmation:
            // terminate rather than fall back to the List of AIDs method
            // (EMV v4.4 Book 1 §12.4 steps 2/5).
            throw new TerminateSessionException(
                    "no candidate selectable without cardholder confirmation");
        }
        return result;
    }
}
