package card42.host.emv.kernel;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import card42.host.emv.kernel.analysis.CvmPerformer;
import card42.host.emv.kernel.core.ConfirmationProvider;
import card42.host.emv.kernel.core.Issuer;
import card42.host.emv.kernel.core.KernelException;
import card42.host.emv.kernel.core.KernelListener;
import card42.host.emv.kernel.core.OnlinePinProvider;
import card42.host.emv.kernel.core.PinProvider;
import card42.host.emv.kernel.core.SignatureProvider;
import card42.host.emv.kernel.core.TransactionException;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.core.TransportException;
import card42.host.emv.kernel.cvm.CombinedPinSignatureCvm;
import card42.host.emv.kernel.cvm.CompositeCvmPerformer;
import card42.host.emv.kernel.cvm.OfflinePinCvm;
import card42.host.emv.kernel.cvm.OnlinePinCvm;
import card42.host.emv.kernel.cvm.SignatureCvm;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.entry.PseSelection;
import card42.host.emv.kernel.oda.OfflineDataAuthentication;
import card42.host.emv.oda.CaKeyStore;
import card42.host.emv.lib.Terminal;
import card42.host.common.util.Reporter;

/**
 * Contact terminal kernel (RSA profile) of the reference host stack
 * (EMV v4.4 Book 3/4, docs/specs/emv/contact-kernel.md).
 *
 * <p>It drives one contact transaction end to end: contact application
 * selection (PSE '1PAY.SYS.DDF01', falling back to a direct ADF selection,
 * {@link PseSelection}) followed by the media-neutral {@link TransactionFlow}
 * (GPO -&gt; READ RECORD -&gt; RSA ODA -&gt; restrictions -&gt; CVM -&gt; TRM
 * -&gt; TAA -&gt; GENERATE AC -&gt; online -&gt; second GENERATE AC).  The only
 * other difference from the {@link ContactlessKernel} is the CVM: a contact AIP
 * may advertise CVM and the kernel performs offline PIN through
 * {@link OfflinePinCvm} when the CVM List selects it (EMV v4.4 Book 3 §10.5).
 *
 * <p>It implements only the RSA profile: no ECC/XDA, no Book E secure channel,
 * no data exchange / data storage and no relay resistance.  An {@link Issuer}
 * supplies the online authorisation (ARC and Issuer Authentication Data) so the
 * kernel never needs the ICC master key; ODA is verified from the certificates
 * the card returns.
 *
 * <p>Note: EMV contact Book 1-4 has no "kernel" concept (the term is used by
 * the contactless Book B/C); "ContactKernel" is this project's name for the
 * contact terminal application, mirroring {@link ContactlessKernel}.
 */
public final class ContactKernel implements TerminalKernel {

    private static final String DEFAULT_AID = "43415244420101";

    private final Reporter reporter;
    private final CaKeyStore caKeyStore;
    private final Random random;
    private final PinProvider pinProvider;
    private final OnlinePinProvider onlinePinProvider;
    private final SignatureProvider signatureProvider;
    private final ConfirmationProvider confirmation;
    private final String[] supportedAids;
    private KernelListener listener = KernelListener.NONE;

    public ContactKernel(Reporter reporter, CaKeyStore caKeyStore, Random random,
                         PinProvider pinProvider, String... supportedAids) {
        this(reporter, caKeyStore, random, pinProvider, null, null, null, supportedAids);
    }

    /**
     * As above with the online PIN and signature host callbacks
     * (EMV v4.4 Book 3 §10.5): the offline PIN performer is composed with them so
     * the CVM List can select any of the CVMs the terminal supports.
     */
    public ContactKernel(Reporter reporter, CaKeyStore caKeyStore, Random random,
                         PinProvider pinProvider, OnlinePinProvider onlinePinProvider,
                         SignatureProvider signatureProvider, String... supportedAids) {
        this(reporter, caKeyStore, random, pinProvider, onlinePinProvider,
                signatureProvider, null, supportedAids);
    }

    /**
     * As above with a cardholder confirmation callback (EMV v4.4 Book 1 §12.4
     * step 5): a null provider means the terminal does not provide cardholder
     * confirmation and confirmation-required directory entries are skipped.
     */
    public ContactKernel(Reporter reporter, CaKeyStore caKeyStore, Random random,
                         PinProvider pinProvider, OnlinePinProvider onlinePinProvider,
                         SignatureProvider signatureProvider,
                         ConfirmationProvider confirmation, String... supportedAids) {
        this.reporter = reporter;
        this.caKeyStore = caKeyStore;
        this.random = random;
        this.pinProvider = pinProvider;
        this.onlinePinProvider = onlinePinProvider;
        this.signatureProvider = signatureProvider;
        this.confirmation = confirmation;
        this.supportedAids = supportedAids.length > 0
                ? supportedAids : new String[] { DEFAULT_AID };
    }

    /** Sets the progress listener (defaults to {@link KernelListener#NONE}). */
    public ContactKernel listener(KernelListener listener) {
        this.listener = listener == null ? KernelListener.NONE : listener;
        return this;
    }

    /** Runs one contact transaction. */
    @Override
    public TransactionResult run(Terminal terminal, TransactionRequest request, Issuer issuer)
            throws KernelException {
        try {
            TransactionFlow flow = new TransactionFlow(reporter, random,
                    new OfflineDataAuthentication(reporter, caKeyStore), listener);
            TransactionResult.Mutable result = new TransactionResult.Mutable();
            OfflinePinCvm offline = new OfflinePinCvm(pinProvider, terminal, request, result);
            SignatureCvm signature = signatureProvider == null
                    ? null : new SignatureCvm(signatureProvider, result);
            List<CvmPerformer> performers = new ArrayList<CvmPerformer>();
            if (signature != null) {
                // Combined '03'/'05' (PIN + signature) must be matched before the
                // plain offline PIN methods (EMV v4.4 Book 3 Table 43).
                performers.add(new CombinedPinSignatureCvm(offline, signature));
            }
            performers.add(offline);
            if (onlinePinProvider != null) {
                performers.add(new OnlinePinCvm(onlinePinProvider, request, result));
            }
            if (signature != null) {
                performers.add(signature);
            }
            CvmPerformer cvm = new CompositeCvmPerformer(
                    performers.toArray(new CvmPerformer[0]));
            flow.run(terminal, request, issuer, new PseSelection(supportedAids, confirmation),
                    cvm, result);
            return result;
        } catch (KernelException e) {
            throw e;
        } catch (javax.smartcardio.CardException e) {
            throw new TransportException("contact transaction transport failure: "
                    + e.getMessage(), e);
        } catch (Exception e) {
            throw new TransactionException("contact transaction failed: " + e.getMessage(), e);
        }
    }
}
