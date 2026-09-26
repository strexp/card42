package card42.host.emv.kernel.entry;

import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.Tags;
import card42.host.emv.kernel.core.ConfirmationProvider;
import card42.host.emv.kernel.core.Selection;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Hex;

/**
 * Contact application selection (EMV v4.4 Book 1 §12.3): SELECT the PSE and
 * pick the highest priority supported ADF from its directory records, or fall
 * back to selecting a supported ADF Name directly.
 *
 * <p>The candidate list is retained so a failed final SELECT or a GET
 * PROCESSING OPTIONS '6985' can retry the next candidate
 * (EMV v4.4 Book 1 §12.4, Book 4 §6.3.1).
 */
public final class PseSelection implements Selection {

    private static final String PSE_AID = "315041592E5359532E4444463031";

    /** Defensive bound on the directory records read before 6A83 (Book 1 §12.3.2). */
    private static final int MAX_DIRECTORY_RECORDS = 30;

    private final String[] supportedAids;
    private final ConfirmationProvider confirmation;

    private final List<String> remaining = new ArrayList<String>();
    /**
     * True when the candidates came from the PSE directory: the final SELECT
     * must then match the DF Name exactly (EMV v4.4 Book 1 §12.4).  The List of
     * AIDs fallback permits the partial-name match of §12.3.3.
     */
    private boolean exactDfName;

    public PseSelection(String[] supportedAids) {
        this(supportedAids, null);
    }

    /** As above with a cardholder confirmation callback (Book 1 §12.4 step 5). */
    public PseSelection(String[] supportedAids, ConfirmationProvider confirmation) {
        this.supportedAids = supportedAids;
        this.confirmation = confirmation;
    }

    @Override
    public String select(Terminal terminal, TransactionRequest data, TransactionResult.Mutable result)
            throws Exception {
        remaining.clear();
        ResponseAPDU pse = terminal.select(PSE_AID);
        // EMV v4.4 Book 1 §12.3.2 step 1: 6A81 (card blocked / command not
        // supported) terminates the session; 6A82/6283 or any other status
        // falls back to the List of AIDs method.
        if (pse.getSW() == 0x6A81) {
            throw new IllegalStateException("PSE SELECT -> 6A81: terminate session");
        }
        if (pse.getSW() == 0x9000) {
            try {
                // Read the directory from the SFI the PSE FCI advertises ('88'),
                // not from a hard-coded file (EMV v4.4 Book 1 §12.3.2 step 2).
                int sfi = ApplicationSelection.directorySfi(pse.getData());
                if (sfi > 0) {
                    remaining.addAll(ApplicationSelection.selectCandidatesFromPse(
                            pse.getData(), readPseDirectory(terminal, sfi), supportedAids,
                            confirmation));
                    exactDfName = !remaining.isEmpty();
                }
            } catch (IllegalStateException e) {
                // A directory read error clears the candidate list and restarts
                // with the List of AIDs method (EMV v4.4 Book 1 §12.3.2).
                remaining.clear();
            }
        }
        if (remaining.isEmpty()) {
            // PSE not supported (or no supported candidate): try the ADF Names
            // directly (EMV v4.4 Book 1 §12.3.3, List of AIDs).
            exactDfName = false;
            for (String aid : supportedAids) {
                remaining.add(aid);
            }
        }
        String selected = selectNext(terminal, data, result);
        if (selected == null) {
            throw new IllegalStateException("no supported contact application selectable");
        }
        return selected;
    }

    @Override
    public String reselect(Terminal terminal, TransactionRequest data, TransactionResult.Mutable result)
            throws Exception {
        return selectNext(terminal, data, result);
    }

    /** Tries the next candidate and returns its DF Name, or null when none remains. */
    private String selectNext(Terminal terminal, TransactionRequest data, TransactionResult.Mutable result)
            throws Exception {
        while (!remaining.isEmpty()) {
            String aid = remaining.remove(0);
            ResponseAPDU r = terminal.select(aid);
            if (r.getSW() == 0x6A81) {
                // §12.3.3 step 2: blocked / command not supported terminates.
                throw new IllegalStateException("List of AIDs SELECT " + aid
                        + " -> 6A81: terminate session");
            }
            if (r.getSW() != 0x9000) {
                continue; // 6283 (blocked) or any other status: next AID
            }
            byte[] dfName = Tags.find(r.getData(), 0x84);
            if (dfName == null) {
                continue; // mandatory DF Name missing: do not add
            }
            String dfNameHex = Hex.format(dfName);
            if (exactDfName) {
                // EMV v4.4 Book 1 §12.4: the final SELECT is valid only when the
                // AID used exactly matches the DF Name ('84') in the FCI.
                if (!aid.equals(dfNameHex)) {
                    continue;
                }
            } else if (!dfNameHex.equals(aid) && !dfNameHex.startsWith(aid)) {
                // §12.3.3 step 3: identical or a longer name starting with the AID.
                continue;
            }
            // The selected value is the DF Name returned in the FCI (§12.4).
            result.aidHex(dfNameHex);
            result.fci(r.getData());
            data.applicationIdentifier = dfName;
            return dfNameHex;
        }
        return null;
    }

    /**
     * Reads the PSE directory from the FCI-advertised SFI, record 1 until the
     * card returns 6A83 (record does not exist), which marks the end of the
     * Payment System Directory (EMV v4.4 Book 1 §12.3.2 step 2).  Any other
     * non-9000 status is an error and aborts the PSE method.  Records without
     * entries are kept; {@code selectFromPse} skips them.
     */
    private static List<byte[]> readPseDirectory(Terminal terminal, int sfi) throws Exception {
        List<byte[]> records = new ArrayList<byte[]>();
        for (int record = 1; record <= MAX_DIRECTORY_RECORDS; record++) {
            ResponseAPDU r = terminal.readRecord(record, sfi);
            if (r.getSW() == 0x6A83) {
                break; // end of the Payment System Directory
            }
            if (r.getSW() != 0x9000) {
                throw new IllegalStateException("READ RECORD PSE " + record + " -> "
                        + String.format("%04X", r.getSW()));
            }
            records.add(r.getData());
        }
        return records;
    }
}
