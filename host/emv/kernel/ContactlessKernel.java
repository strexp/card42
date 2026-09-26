package card42.host.emv.kernel;

import java.util.Random;

import card42.host.emv.kernel.analysis.CvmPerformer;
import card42.host.emv.kernel.core.EndApplicationException;
import card42.host.emv.kernel.core.Issuer;
import card42.host.emv.kernel.core.KernelException;
import card42.host.emv.kernel.core.KernelListener;
import card42.host.emv.kernel.core.Outcome;
import card42.host.emv.kernel.core.TransactionException;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.core.TransportException;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.entry.CombinationTable;
import card42.host.emv.kernel.entry.EntryPointConfiguration;
import card42.host.emv.kernel.entry.KernelActivation;
import card42.host.emv.kernel.entry.PpseSelection;
import card42.host.emv.kernel.oda.OfflineDataAuthentication;
import card42.host.emv.oda.CaKeyStore;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Reporter;

/**
 * Contactless terminal kernel (RSA profile).  It references EMV Contactless
 * Book C-8 v1.2 only conceptually (docs/specs/emv/contactless.md §1.2): the flow it
 * actually implements is the EMV v4.4 Book 3/4 RSA terminal flow, which is not
 * a subset of the C-8 flow (C-8 uses ECC GPO, encrypted records and
 * card-selected CVM).
 *
 * <p>Since H3–H5 it is the Entry Point state machine: it runs Start A
 * (Pre-Processing Indicators), the Final Combination Selection (with SPI and
 * Extended Selection) and builds a {@link KernelActivation} for the selected
 * Combination; the media-neutral {@link TransactionFlow} then runs the
 * transaction from GPO on.  A bounded Restart loop implements Start C (Select
 * Next) when the configuration allows it.  The kernel produces an
 * {@link Outcome} (Book A Table 6-2).
 *
 * <p>It deliberately implements only the RSA profile: no ECC/XDA, no Book E
 * secure channel (out of scope; docs/specs/emv/contactless.md §1.2), no data
 * exchange / data storage and no relay resistance.  The contactless AIP does
 * not advertise CVM, so no offline PIN is performed; the CVM performer is
 * {@link CvmPerformer#UNSUPPORTED} (EMV v4.4 Book 3 §10.5).
 *
 * <p>An {@link Issuer} supplies the online authorisation (ARC and Issuer
 * Authentication Data) so the kernel never needs the ICC master key; ODA is
 * verified from the certificates the card returns.
 */
public final class ContactlessKernel implements TerminalKernel {

    private static final String DEFAULT_AID = "43415244420102";

    /** Bound on the Entry Point Restart loop (Book A §8.1.1.19–24). */
    private static final int MAX_RESTARTS = 4;

    private final Reporter reporter;
    private final CaKeyStore caKeyStore;
    private final Random random;
    private final CombinationTable table;
    private final EntryPointConfiguration config;
    private KernelListener listener = KernelListener.NONE;

    /** The activation data of the last {@link #run}, or null. */
    private KernelActivation activation;

    public ContactlessKernel(Reporter reporter, CaKeyStore caKeyStore, Random random,
                             String... supportedAids) {
        this(reporter, caKeyStore, random,
                CombinationTable.defaults(supportedAids.length > 0
                        ? supportedAids : new String[] { DEFAULT_AID }),
                null);
    }

    /**
     * The kernel with an explicit Combination Table and Entry Point
     * Configuration; a null configuration is derived from the terminal data at
     * each run.
     */
    public ContactlessKernel(Reporter reporter, CaKeyStore caKeyStore, Random random,
                             CombinationTable table, EntryPointConfiguration config) {
        this.reporter = reporter;
        this.caKeyStore = caKeyStore;
        this.random = random;
        this.table = table;
        this.config = config;
    }

    /** Sets the progress listener (defaults to {@link KernelListener#NONE}). */
    public ContactlessKernel listener(KernelListener listener) {
        this.listener = listener == null ? KernelListener.NONE : listener;
        return this;
    }

    /** The activation data of the last {@link #run}, or null. */
    public KernelActivation activation() {
        return activation;
    }

    /** Runs one contactless transaction through the Entry Point state machine. */
    @Override
    public TransactionResult run(Terminal terminal, TransactionRequest request, Issuer issuer)
            throws KernelException {
        try {
            TransactionFlow flow = new TransactionFlow(reporter, random,
                    new OfflineDataAuthentication(reporter, caKeyStore), listener);
            TransactionResult.Mutable result = new TransactionResult.Mutable();
            EntryPointConfiguration effective = config != null
                    ? config : EntryPointConfiguration.from(request.config);
            PpseSelection selection = new PpseSelection(table, effective, listener);
            flow.beginTransaction(request, result);

            Outcome outcome;
            try {
                activation = selection.activate(terminal, request, result);
                listener.onStep(KernelListener.Step.APPLICATION_SELECTION, result);
            } catch (EndApplicationException e) {
                // No Combination (Book B §3.3.2.7) or all Combinations Contactless
                // Application Not Allowed (Book B §3.1.1.13).
                result.outcome(e.messageIdentifier() == EndApplicationException.TRY_ANOTHER_INTERFACE
                        ? Outcome.tryAnotherInterface()
                        : Outcome.endApplication(e.messageIdentifier()));
                listener.onOutcome(result.outcome());
                return result;
            }

            int start = activation.start;
            for (int attempt = 0; ; attempt++) {
                if (attempt > 0) {
                    // A restart activates the kernel again, so a fresh Unpredictable
                    // Number is drawn (Book A §8.1.1.8).
                    flow.newUnpredictableNumber(request);
                }
                flow.runActivated(terminal, request, issuer, selection,
                        CvmPerformer.UNSUPPORTED, result);
                outcome = Outcome.from(result);
                outcome.start = start;
                // Final Outcome association data (Book B §3.5.1.5): the ADF Name
                // actually selected (with Extended Selection) and the Kernel
                // Identifier-Terminal (tag '96', Book B Table 3-7) of the Kernel
                // Entry Point selected for the transaction.
                if (activation != null) {
                    outcome.adfName = activation.selectedAdfName;
                    outcome.kernelIdentifierTerminal = activation.kernelIdentifierTerminal();
                }
                if (outcome.finalOutcome == Outcome.DECLINE) {
                    if (effective.restartOnDecline) {
                        // Select Next: remove the current Combination and try the
                        // next (Book A §6.3 Final Outcome 'Select Next').
                        outcome = Outcome.selectNext();
                    } else if (effective.tryAgainOnDecline) {
                        // Try Again: re-run the same Combination (Book A Table 6-3/6-4).
                        outcome = Outcome.tryAgain(0);
                    }
                }
                if (!outcome.restart || attempt + 1 >= MAX_RESTARTS) {
                    break;
                }
                if (outcome.finalOutcome == Outcome.TRY_AGAIN) {
                    // Try Again returns to Start B with the same Combination
                    // (EMV Contactless Book B v2.12 §3.5.1.3 / Book A Table B.9).
                    KernelActivation restarted = selection.restartStartB(terminal, request, result);
                    if (restarted == null) {
                        outcome = Outcome.endApplication(
                                EndApplicationException.INSERT_SWIPE_OR_TRY_ANOTHER_CARD);
                        break;
                    }
                    activation = restarted;
                    start = Outcome.START_B;
                    outcome.start = Outcome.START_B;
                    continue; // same Combination, fresh Unpredictable Number
                }
                // Start C (Select Next) or Start D (restart after the online
                // response) (EMV Contactless Book A v2.12 §8.1.1.19-24).
                activation = selection.activateNext(terminal, request, result);
                if (activation == null) {
                    outcome = Outcome.endApplication(
                            EndApplicationException.INSERT_SWIPE_OR_TRY_ANOTHER_CARD);
                    break;
                }
                listener.onStep(KernelListener.Step.APPLICATION_SELECTION, result);
                start = result.wentOnline() ? Outcome.START_D : Outcome.START_C;
            }
            if (!outcome.restart) {
                // The reader may power the field off and wait for card removal
                // (Book A Table 6-2: Field Off Request / Removal Timeout).
                outcome.fieldOffRequest = effective.fieldOffRequest;
                outcome.removalTimeout = effective.removalTimeout;
            }
            result.outcome(outcome);
            listener.onOutcome(outcome);
            return result;
        } catch (KernelException e) {
            throw e;
        } catch (javax.smartcardio.CardException e) {
            throw new TransportException("contactless transaction transport failure: "
                    + e.getMessage(), e);
        } catch (Exception e) {
            throw new TransactionException("contactless transaction failed: " + e.getMessage(), e);
        }
    }
}
