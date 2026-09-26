package card42.host.emv.kernel.entry;

import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.ResponseAPDU;

import card42.host.common.codec.Tags;
import card42.host.emv.kernel.core.EndApplicationException;
import card42.host.emv.kernel.core.KernelListener;
import card42.host.emv.kernel.core.Outcome;
import card42.host.emv.kernel.core.Selection;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.common.util.Bcd;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Hex;

/**
 * Contactless Entry Point: SELECT the PPSE, optionally send SEND POI INFORMATION
 * (EMV Contactless Book B v2.12 Annex C) when the card advertises it, compute the
 * Start A Pre-Processing Indicators (Book A §5.7), run the Combination Selection
 * against the reader's Combination Table (§3.3.2) and select the highest priority
 * Combination, producing a {@link KernelActivation} for the kernel (§3.4).
 *
 * <p>When a {@code SELECT (ADF Name)} is refused the Combination is removed from
 * the Candidate List and the next one is tried (§3.3.3.5); {@link #activateNext}
 * resumes the Candidate List for a Restart (Start C).
 */
public final class PpseSelection implements Selection {

    private static final String PPSE_AID = "325041592E5359532E4444463031";

    private final CombinationTable table;
    private final EntryPointConfiguration config;
    private final KernelListener listener;

    /** The Candidate List retained across a GET PROCESSING OPTIONS '6985' retry. */
    private List<EntryPoint.Candidate> candidates;
    private int nextIndex;
    /** Index of the currently activated candidate, or -1. */
    private int currentIndex = -1;
    private byte[] ppseFci;
    private PreProcessingIndicators indicators;
    private KernelActivation activation;

    /**
     * Selection with the flat supported-AID list used before H1: a default
     * Combination Table for every transaction type.
     */
    public PpseSelection(String[] supportedAids) {
        this(CombinationTable.defaults(supportedAids), new EntryPointConfiguration());
    }

    public PpseSelection(CombinationTable table, EntryPointConfiguration config) {
        this(table, config, KernelListener.NONE);
    }

    /** As above with a progress listener that receives the Entry Point Candidate List. */
    public PpseSelection(CombinationTable table, EntryPointConfiguration config,
            KernelListener listener) {
        this.table = table;
        this.config = config;
        this.listener = listener == null ? KernelListener.NONE : listener;
    }

    /**
     * Runs Start A and the Final Combination Selection (Book B §3.3.3), returning
     * the activation data for the selected kernel.
     */
    public KernelActivation activate(Terminal terminal, TransactionRequest data,
            TransactionResult.Mutable result) throws Exception {
        ResponseAPDU ppse = terminal.select(PPSE_AID);
        if (ppse.getSW() != 0x9000) {
            // Book B §3.3.2.3: a PPSE that cannot be selected adds no
            // Combinations and proceeds to Step 3 (End Application).
            throw new EndApplicationException("SELECT PPSE -> " + sw(ppse.getSW())
                    + " (build with TEST_CONTACTLESS=1 to exercise the contactless flow)");
        }
        byte[] fci = ppse.getData();
        // SEND POI INFORMATION before Entry Point selection when the card
        // advertises it (Book B §3.3.2.3) or the reader forces it.  A failed SPI
        // adds no Combinations and proceeds to End Application (§3.3.2.3b).
        if ((config.spiSupport && Spi.advertised(fci, config.terminalCategory))
                || config.forceSpi) {
            ResponseAPDU spi = Spi.send(terminal, fci, data, result, config);
            if (spi.getSW() != 0x9000 || spi.getData().length == 0) {
                throw new EndApplicationException("SEND POI INFORMATION -> "
                        + sw(spi.getSW()) + " (Book B §3.3.2.3b)");
            }
            fci = Spi.stripAdvertisement(spi.getData());
        }
        ppseFci = fci;
        candidates = EntryPoint.selectCandidates(fci, table, data.transactionType);
        nextIndex = 0;
        if (candidates.isEmpty()) {
            // Book B §3.3.2.7: an empty Candidate List is an End Application
            // Outcome (UI Request '1C', Insert/Swipe/Try another card).
            throw new EndApplicationException("Entry Point found no supported candidate");
        }
        // Per-Combination Pre-Processing Indicators (Book A §5.7, Table 5-3):
        // compute each Combination's indicators and drop the ones whose
        // configuration sets Contactless Application Not Allowed.  When every
        // Combination is not allowed the Outcome is Try Another Interface
        // (Book B §3.1.1.13).  The transaction type has no Combination when the
        // table is empty for it.
        long amount = Bcd.bcdToLong(data.amountAuthorised);
        boolean noCombination = table.forType(data.transactionType).isEmpty();
        List<EntryPoint.Candidate> allowed = new ArrayList<EntryPoint.Candidate>();
        for (EntryPoint.Candidate candidate : candidates) {
            EntryPointConfiguration cfg = configFor(candidate);
            PreProcessingIndicators ind =
                    PreProcessingIndicators.startA(cfg, amount, noCombination);
            // Autorun (Book A §8.1.1.6): when Autorun is 'Yes' the reader
            // activates Entry Point directly at Start B, independently of
            // whether a Status Check was requested.  Start B uses the fixed
            // Pre-Processing Indicators (Book B §3.1.1).
            if (cfg.autorun) {
                ind = PreProcessingIndicators.startB(cfg);
                candidate.start = Outcome.START_B;
            } else {
                candidate.start = Outcome.START_A;
            }
            candidate.indicators = ind;
            if (!ind.contactlessApplicationNotAllowed) {
                allowed.add(candidate);
            }
        }
        if (allowed.isEmpty()) {
            throw new EndApplicationException(
                    "all Combinations Contactless Application Not Allowed",
                    EndApplicationException.TRY_ANOTHER_INTERFACE);
        }
        candidates = allowed;
        List<String> adfNames = new ArrayList<String>();
        for (EntryPoint.Candidate candidate : candidates) {
            adfNames.add(candidate.adfHex);
        }
        listener.onCandidateList(adfNames);
        return selectNext(terminal, data, result);
    }

    /** Resumes the Candidate List for a Restart (Start C), or null when exhausted. */
    public KernelActivation activateNext(Terminal terminal, TransactionRequest data,
            TransactionResult.Mutable result) throws Exception {
        return selectNext(terminal, data, result);
    }

    /**
     * Re-activates the current Combination at Start B for a Try Again Final
     * Outcome (EMV Contactless Book B v2.12 §3.5.1.3 / Book A Table B.9): the
     * same ADF Name is selected again with the fixed Start B indicators.
     *
     * @return the new activation, or null when there is no current candidate
     */
    public KernelActivation restartStartB(Terminal terminal, TransactionRequest data,
            TransactionResult.Mutable result) throws Exception {
        if (currentIndex < 0 || currentIndex >= candidates.size()) {
            return null;
        }
        EntryPoint.Candidate candidate = candidates.get(currentIndex);
        candidate.indicators = PreProcessingIndicators.startB(configFor(candidate));
        candidate.start = Outcome.START_B;
        nextIndex = currentIndex;
        return selectNext(terminal, data, result);
    }

    @Override
    public String select(Terminal terminal, TransactionRequest data,
            TransactionResult.Mutable result) throws Exception {
        KernelActivation selected = activate(terminal, data, result);
        if (selected == null) {
            throw new EndApplicationException("SELECT of every Entry Point candidate failed");
        }
        return selected.adfName;
    }

    @Override
    public String reselect(Terminal terminal, TransactionRequest data,
            TransactionResult.Mutable result) throws Exception {
        KernelActivation selected = activateNext(terminal, data, result);
        return selected == null ? null : selected.adfName;
    }

    /** The activation data of the current selection, or null. */
    public KernelActivation activation() {
        return activation;
    }

    /** The Start A Pre-Processing Indicators, or null before activation. */
    public PreProcessingIndicators indicators() {
        return indicators;
    }

    /** The PPSE FCI the Candidate List was read from, or null. */
    public byte[] ppseFci() {
        return ppseFci;
    }

    /**
     * Tries the next Combination in priority order and returns its activation,
     * or null when the Candidate List is exhausted.
     */
    private KernelActivation selectNext(Terminal terminal, TransactionRequest data,
            TransactionResult.Mutable result) throws Exception {
        while (nextIndex < candidates.size()) {
            EntryPoint.Candidate candidate = candidates.get(nextIndex++);
            // Extended Selection (Book B §3.3.3.3): append the Combination's
            // '9F29' to the ADF Name when the reader supports it.
            String selectAid = candidate.adfHex;
            if (config.extendedSelectionSupported && candidate.extendedSelection != null) {
                selectAid = candidate.adfHex + Hex.format(candidate.extendedSelection);
            }
            ResponseAPDU select = terminal.select(selectAid);
            if (select.getSW() != 0x9000) {
                continue; // remove the Combination and try the next (§3.3.3.5)
            }
            // A SELECT response with a missing or mismatched DF Name ('84') is a
            // format error: drop the Combination and try the next
            // (EMV Contactless Book B v2.12 §3.3.3.5 / §3.3.1).
            byte[] dfName = Tags.find(select.getData(), 0x84);
            if (dfName == null || !Hex.format(dfName).equals(candidate.adfHex)) {
                continue;
            }
            // Book B §3.3.3.6: a Visa AID on Kernel 3 whose PDOL is absent or
            // lacks '9F66' is removed and Start C is retried.
            if (EntryPoint.visaKernel3WithoutTtq(select.getData(), candidate.adfHex,
                    candidate.kernelId)) {
                continue;
            }
            currentIndex = nextIndex - 1;
            result.aidHex(candidate.adfHex);
            result.fci(select.getData());
            // The selected value is the DF Name returned in the FCI; terminal
            // 9F06 must carry it for PDOL/CDOL construction (EMV v4.4 Book 1
            // §12.4; Book B §3.3.3.6).
            data.applicationIdentifier = dfName;
            indicators = candidate.indicators;
            activation = new KernelActivation(candidate.adfHex, selectAid, candidate.aid,
                    candidate.kernelId, ppseFci, select.getData(), select.getSW(),
                    candidate.indicators, candidate.start);
            return activation;
        }
        activation = null;
        return null;
    }

    /**
     * The Entry Point Configuration of a candidate: the Combination's own when
     * set, otherwise the Combination Table default, otherwise the configuration
     * this selection was constructed with (Book A Table 5-2).
     */
    private EntryPointConfiguration configFor(EntryPoint.Candidate candidate) {
        EntryPointConfiguration cfg = table.configFor(candidate.combination);
        return cfg != null ? cfg : config;
    }

    private static String sw(int sw) {
        return String.format("%04X", sw & 0xFFFF);
    }
}
