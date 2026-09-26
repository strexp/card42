package card42.host.emv.kernel.analysis;

/**
 * Executes the CVM method selected by {@link CvmList} (EMV v4.4 Book 3 §10.5).
 *
 * <p>The contactless kernel performs no offline PIN, so it passes no performer
 * and offline PIN methods are treated as unsupported.  The contact kernel
 * supplies an offline PIN performer (plaintext / enciphered) that captures the
 * PIN and sends VERIFY (EMV v4.4 Book 2 §7).
 *
 * <p>The performer only reports whether the CVM succeeded; {@link CvmList} maps
 * the outcome to the CVM Results and the TVR.
 */
public interface CvmPerformer {

    /**
     * The performer of a terminal that performs no offline CVM: every method is
     * unsupported, so {@link #perform} is never called on it.  Used instead of a
     * null performer so the contract is total (the contactless kernel).
     */
    CvmPerformer UNSUPPORTED = new CvmPerformer() {
        @Override
        public boolean supports(int method) {
            return false;
        }

        @Override
        public int perform(int method, int condition) {
            throw new IllegalStateException("perform called on the UNSUPPORTED CVM performer");
        }
    };

    /** True when the terminal can perform the given CVM method code. */
    boolean supports(int method);

    /**
     * Performs the given CVM method.
     *
     * @return one of {@link CvmList#RESULT_UNKNOWN}, {@link CvmList#RESULT_FAILED},
     *         {@link CvmList#RESULT_SUCCESSFUL}
     */
    int perform(int method, int condition);
}
