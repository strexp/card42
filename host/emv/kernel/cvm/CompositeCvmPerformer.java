package card42.host.emv.kernel.cvm;

import card42.host.emv.kernel.data.Cvm;
import card42.host.emv.kernel.analysis.CvmPerformer;

/**
 * A {@link CvmPerformer} that dispatches each CVM method to the first delegate
 * that supports it.  The contact kernel assembles its offline PIN, online PIN,
 * signature and combined performers into one instance for
 * {@code TransactionFlow} (which takes a single performer).
 */
public final class CompositeCvmPerformer implements CvmPerformer {

    private final CvmPerformer[] performers;

    public CompositeCvmPerformer(CvmPerformer... performers) {
        this.performers = performers.clone();
    }

    @Override
    public boolean supports(int method) {
        for (CvmPerformer performer : performers) {
            if (performer.supports(method)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int perform(int method, int condition) {
        for (CvmPerformer performer : performers) {
            if (performer.supports(method)) {
                return performer.perform(method, condition);
            }
        }
        return Cvm.RESULT_FAILED;
    }
}
